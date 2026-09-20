"""Provider-independent reserves; real engine transport uses synthetic responses."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ryt.bridge import ProviderBridge
from ryt.backend import execute_agent
from test_assurance import fixture, review
from test_opencode import Stream


class FinalizationContracts(unittest.TestCase):
    def test_both_profiles_reserve_context_at_the_existing_boundary(self):
        for selected, model in [('zai', 'glm-5.3-flash'), ('bai-qwen', 'qwen3.8-flash')]:
            for tokens, finalizing in [(63487, False), (63488, True), (88194, True), (90532, True)]:
                with self.subTest(profile=selected, tokens=tokens), ProviderBridge(
                        'synthetic', lambda text: tokens, profile_id=selected) as bridge:
                    payload = {'model': model, 'stream': True,
                        'messages': [{'role': 'user', 'content': 'complete immutable assigned diffs'},
                            {'role': 'assistant', 'content': 'Prior supported finding must be retained.'}],
                        'tools': [{'type': 'function', 'function': {'name': name}}
                            for name in ('ryt_read_file', 'ryt_submit_review')]}
                    messages = copy.deepcopy(payload['messages'])
                    record = bridge.validate(payload)
                    self.assertEqual(record['finalization_only'], finalizing)
                    self.assertEqual(payload['messages'][1:], messages)
                    self.assertEqual(payload['max_tokens'], 32768)
                    self.assertEqual(record['remaining_input_tokens'], 97280 - tokens)
                    if finalizing:
                        self.assertEqual([t['function']['name'] for t in payload['tools']], ['ryt_submit_review'])
                        self.assertEqual(payload['tool_choice'],
                            {'type': 'function', 'function': {'name': 'ryt_submit_review'}})
                        self.assertIn('never invent a clean result', payload['messages'][0]['content'])
                        bridge.count_tokens = lambda text: 100
                        self.assertTrue(bridge.validate(payload)['finalization_only'])
                    else:
                        self.assertEqual(len(payload['tools']), 2)

    def test_glm_reserves_calls_and_still_enforces_hard_limits(self):
        with ProviderBridge('synthetic', lambda text: 100, max_calls=9) as bridge:
            payload = {'model': 'glm-5.3-flash', 'stream': True, 'messages': [],
                'tools': [{'type': 'function', 'function': {'name': 'ryt_submit_review'}}]}
            self.assertTrue(bridge.validate(copy.deepcopy(payload))['finalization_only'])
            for _ in range(8):
                bridge.validate(copy.deepcopy(payload))
            with self.assertRaisesRegex(ValueError, 'call_limit'):
                bridge.validate(copy.deepcopy(payload))
        with ProviderBridge('synthetic', lambda text: 97281) as bridge:
            with self.assertRaisesRegex(ValueError, 'context_limit'):
                bridge.validate(copy.deepcopy(payload))


@unittest.skipUnless(os.environ.get('RYT_OPENCODE_BIN'), 'explicit pinned binary required')
class GlmFinalizationIntegration(unittest.TestCase):
    def test_glm_submits_findings_then_receives_acknowledgment_with_investigation_closed(self):
        with tempfile.TemporaryDirectory(prefix='ryt-glm-finalization-') as temp:
            root = Path(temp)
            data = fixture(root)
            session = root / 'session'
            session.mkdir()
            requests = []
            actions = [('ryt_read_file', {'path': 'policy.mjs'}), ('ryt_submit_review', review())]

            def response(request, timeout):
                payload = json.loads(request.data)
                requests.append(payload)
                self.assertEqual(payload['model'], 'glm-5.3-flash')
                self.assertEqual(payload['reasoning_effort'], 'max')
                index = len(requests) - 1
                if index < len(actions):
                    name, arguments = actions[index]
                    delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': f'call-{index}',
                        'type': 'function', 'function': {'name': name, 'arguments': json.dumps(arguments)}}]}
                    finish = 'tool_calls'
                else:
                    delta = {'role': 'assistant', 'content': 'Review submitted.'}
                    finish = 'stop'
                choices = [{'index': 0, 'delta': delta, 'finish_reason': None},
                    {'index': 0, 'delta': {}, 'finish_reason': finish}]
                return Stream((''.join('data: ' + json.dumps({'model': payload['model'],
                    'choices': [choice]}) + '\n\n' for choice in choices) + 'data: [DONE]\n\n').encode())

            with patch('ryt.bridge.open_provider', side_effect=response):
                result, evidence = execute_agent(Path(os.environ['RYT_OPENCODE_BIN']), data, session,
                    'SYNTHETIC', lambda text: len(text) // 4, timeout_seconds=30, max_calls=10)
            self.assertEqual(len(requests), 3)
            self.assertEqual(set(result['coverage']), {'auth.mjs'})
            self.assertEqual(result['review'], review()['review'])
            self.assertEqual([r['finalization_only'] for r in evidence['provider_requests']], [False, True, True])
            self.assertIn('ryt_read_file', [t['function']['name'] for t in requests[0]['tools']])
            self.assertEqual([t['function']['name'] for t in requests[1]['tools']], ['ryt_submit_review'])
            self.assertEqual(requests[1]['tool_choice'],
                {'type': 'function', 'function': {'name': 'ryt_submit_review'}})
            self.assertEqual(requests[2]['tools'], [])
            self.assertEqual(requests[2]['tool_choice'], 'none')
            self.assertTrue(any(m['role'] == 'tool' for m in requests[2]['messages']))
