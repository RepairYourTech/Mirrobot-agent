"""Real pinned engine regression for B.AI's tool-call terminal convention."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ryt.backend import execute_agent
from ryt.common import load_json
from test_assurance import fixture, review
from test_opencode import Stream


@unittest.skipUnless(os.environ.get('RYT_OPENCODE_BIN'), 'explicit pinned binary required')
class BaiTerminalCompatibility(unittest.TestCase):
    def test_rejected_findings_survive_real_engine_finalization(self):
        import copy
        with tempfile.TemporaryDirectory(prefix='ryt-bai-submission-') as temp:
            root = Path(temp)
            data = fixture(root)
            session = root / 'session'
            session.mkdir()
            corrected = review()
            corrected['review']['key_issues_to_review'] = [{
                'relevant_file': 'auth.mjs', 'issue_header': 'Await authorization',
                'issue_content': '[P1] The Promise guard permits an unauthorized query.',
                'start_line': 1, 'end_line': 1,
            }]
            malformed = copy.deepcopy(corrected)
            malformed['review']['key_issues_to_review'][0]['issue_content'] = ' '
            actions = [('ryt_read_file', {'path': 'policy.mjs'}),
                       ('ryt_submit_review', malformed), ('ryt_submit_review', review()),
                       ('ryt_submit_review', corrected)]
            requests = []

            def response(request, timeout):
                payload = load_json(request.data)
                self.assertIs(payload['enable_thinking'], False)
                index = len(requests)
                requests.append(payload)
                if index < len(actions):
                    name, arguments = actions[index]
                    delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': f'integrity-{index}',
                        'type': 'function', 'function': {'name': name, 'arguments': json.dumps(arguments)}}]}
                else:
                    delta = {'role': 'assistant', 'content': 'Review submitted.'}
                chunks = [json.dumps({'model': 'qwen3.8-flash', 'choices': [choice]}) for choice in
                    [{'index': 0, 'delta': delta, 'finish_reason': None},
                     {'index': 0, 'delta': {}, 'finish_reason': 'stop'}]]
                return Stream((''.join('data: ' + chunk + '\n\n' for chunk in chunks)
                    + 'data: [DONE]\n\n').encode())

            with patch('ryt.bridge.open_provider', side_effect=response):
                result, evidence = execute_agent(Path(os.environ['RYT_OPENCODE_BIN']), data, session,
                    'SYNTHETIC-CREDENTIAL', lambda text: len(text) // 4, timeout_seconds=30,
                    profile_id='bai-qwen', max_tools=8, max_calls=10)
            self.assertEqual(result['review']['key_issues_to_review'], corrected['review']['key_issues_to_review'])
            submissions = [event for event in evidence['tool_events'] if event['tool'] == 'submit_review']
            self.assertEqual([event['status'] for event in submissions], ['failed', 'failed', 'success'])
            self.assertEqual(submissions[0]['validation']['field'], 'review.key_issues_to_review[0].issue_content')
            self.assertEqual(submissions[1]['validation']['code'], 'rejected_findings_discarded')
            tool_results = json.dumps([message for message in requests[3]['messages'] if message['role'] == 'tool'])
            self.assertIn('cannot discard rejected findings', tool_results)
            self.assertEqual(len(requests), 5)

    def test_http_200_quota_response_restarts_real_engine_with_reserve_key(self):
        from ryt.failover import execute_with_pool
        from ryt.providers import ProviderPool, routes
        with tempfile.TemporaryDirectory(prefix='ryt-bai-quota-') as temp:
            root = Path(temp)
            data = fixture(root)
            session = root / 'session'
            session.mkdir()
            active_calls = []
            actions = [('ryt_read_file', {'path': 'policy.mjs'}), ('ryt_submit_review', review())]
            def response(request, timeout):
                if request.get_header('Authorization') == 'Bearer LIMITED':
                    delta = {'role': 'assistant', 'content': json.dumps(
                        {'message': 'Too many tokens, please wait before trying again.'})}
                else:
                    self.assertEqual(request.get_header('Authorization'), 'Bearer AVAILABLE')
                    index = len(active_calls)
                    active_calls.append(load_json(request.data))
                    if index < len(actions):
                        name, arguments = actions[index]
                        delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': f'quota-{index}',
                            'type': 'function', 'function': {'name': name, 'arguments': json.dumps(arguments)}}]}
                    else:
                        delta = {'role': 'assistant', 'content': 'Review submitted.'}
                lines = [json.dumps({'model': 'qwen3.8-flash', 'choices': [choice]}) for choice in
                    [{'index': 0, 'delta': delta, 'finish_reason': None},
                     {'index': 0, 'delta': {}, 'finish_reason': 'stop'}]]
                return Stream((''.join('data: ' + line + '\n\n' for line in lines) + 'data: [DONE]\n\n').encode())
            pool = ProviderPool(routes({'PR_REVIEW_BAI_01': 'LIMITED', 'PR_REVIEW_BAI_02': 'AVAILABLE'}))
            with patch('ryt.bridge.open_provider', side_effect=response):
                result, evidence = execute_with_pool(execute_agent, Path(os.environ['RYT_OPENCODE_BIN']),
                    data, session, pool, lambda text: len(text) // 4, '', 60)
            self.assertEqual(set(result['coverage']), {'auth.mjs'})
            self.assertEqual(evidence['route'], 'bai-02')
            self.assertEqual(evidence['attempts'][0]['failure_code'], 'provider_token_rate_limit')
            self.assertEqual(evidence['pool_request_count'], 4)
            self.assertEqual(pool.next().alias, 'bai-02')
            self.assertNotIn('LIMITED', json.dumps(evidence))

    def test_stop_with_tool_calls_still_executes_and_delivers_the_tool_results(self):
        with tempfile.TemporaryDirectory(prefix='ryt-bai-protocol-') as temp:
            root = Path(temp)
            data = fixture(root)
            # Dedicated GitHub runner paths exceed Linux's 108-byte socket-address limit.
            session = root / ('runner-session-' + 'x' * 90)
            session.mkdir()
            requests = []
            actions = [('ryt_read_file', {'path': 'policy.mjs'}), ('ryt_submit_review', review())]

            def response(request, timeout):
                payload = load_json(request.data)
                self.assertEqual(request.full_url, 'https://api.b.ai/v1/chat/completions')
                self.assertEqual(payload['model'], 'qwen3.8-flash')
                self.assertIs(payload['enable_thinking'], False)
                self.assertNotIn('reasoning_effort', payload)
                requests.append(payload)
                index = len(requests) - 1
                if index < len(actions):
                    name, arguments = actions[index]
                    delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': f'call-{index}',
                        'type': 'function', 'function': {'name': name, 'arguments': json.dumps(arguments)}}]}
                else:
                    delta = {'role': 'assistant', 'content': 'Review submitted.'}
                chunks = [json.dumps({'model': payload['model'], 'choices': [choice]})
                    for choice in [{'index': 0, 'delta': delta, 'finish_reason': None},
                                   {'index': 0, 'delta': {}, 'finish_reason': 'stop'}]]
                return Stream((''.join('data: ' + chunk + '\n\n' for chunk in chunks)
                    + 'data: [DONE]\n\n').encode())

            with patch('ryt.bridge.open_provider', side_effect=response):
                result, evidence = execute_agent(Path(os.environ['RYT_OPENCODE_BIN']), data, session,
                    'SYNTHETIC-CREDENTIAL', lambda text: len(text) // 4, timeout_seconds=30,
                    profile_id='bai-qwen', max_tools=4, max_calls=10)
            self.assertEqual(len(requests), 3)
            self.assertEqual([event['tool'] for event in evidence['tool_events']], ['read_file', 'submit_review'])
            self.assertEqual(set(result['coverage']), {'auth.mjs'})
            self.assertTrue(all(request['finish_reasons'] == ['stop'] for request in evidence['provider_requests']))
            self.assertTrue(any(message['role'] == 'tool' for message in requests[-1]['messages']))
            self.assertEqual(evidence['model'], 'openai/qwen3.8-flash')
            self.assertIs(evidence['thinking_enabled'], False)
            self.assertIn('ryt_read_file', [tool['function']['name'] for tool in requests[0]['tools']])
            self.assertEqual([tool['function']['name'] for tool in requests[1]['tools']], ['ryt_submit_review'])
            self.assertEqual(requests[1]['tool_choice'],
                {'type': 'function', 'function': {'name': 'ryt_submit_review'}})
            self.assertEqual(requests[2]['tool_choice'], 'none')
            self.assertEqual(requests[2]['tools'], [])
            self.assertEqual(requests[0]['tool_choice'], 'auto')
            self.assertEqual([request['finalization_only'] for request in evidence['provider_requests']], [False, True, True])


if __name__ == '__main__':
    unittest.main()
