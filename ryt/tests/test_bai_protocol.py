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
    def test_stop_with_tool_calls_still_executes_and_delivers_the_tool_results(self):
        with tempfile.TemporaryDirectory(prefix='ryt-bai-protocol-') as temp:
            root = Path(temp)
            data = fixture(root)
            session = root / 'session'
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
                    'SYNTHETIC-CREDENTIAL', lambda text: len(text) // 4, timeout_seconds=30, profile_id='bai-qwen', max_tools=4)
            self.assertEqual(len(requests), 3)
            self.assertEqual([event['tool'] for event in evidence['tool_events']], ['read_file', 'submit_review'])
            self.assertEqual(set(result['coverage']), {'auth.mjs'})
            self.assertTrue(all(request['finish_reasons'] == ['stop'] for request in evidence['provider_requests']))
            self.assertTrue(any(message['role'] == 'tool' for message in requests[-1]['messages']))
            self.assertEqual(evidence['model'], 'openai/qwen3.8-flash')
            self.assertIs(evidence['thinking_enabled'], False)


if __name__ == '__main__':
    unittest.main()
