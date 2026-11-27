"""Provider profile and bounded credential-failover contracts."""
import json
import unittest
import urllib.request

from ryt.bridge import ProviderBridge
from ryt.providers import profile, routes, ProviderPool, Route


class ProviderContracts(unittest.TestCase):
    def test_glm_reserves_context_for_submission_without_dropping_input(self):
        import copy
        def payload():
            return {'model': 'glm-5.3-flash', 'stream': True,
                'messages': [{'role': 'user', 'content': 'complete immutable review packet'}],
                'tools': [{'type': 'function', 'function': {'name': name}} for name in
                          ('ryt_read_file', 'ryt_search', 'ryt_submit_review')]}
        with ProviderBridge('synthetic', lambda text: 40000) as bridge:
            initial = payload()
            bridge.validate(initial)
            self.assertEqual(len(initial['tools']), 3)
            bridge.count_tokens = lambda text: 70000
            full = payload()
            messages = copy.deepcopy(full['messages'])
            bridge.validate(full)
            self.assertEqual([t['function']['name'] for t in full['tools']], ['ryt_submit_review'])
            self.assertEqual(full['tool_choice'], {'type': 'function', 'function': {'name': 'ryt_submit_review'}})
            self.assertEqual(full['messages'][1:], messages)
            self.assertIn('FINALIZATION', full['messages'][0]['content'])
            # A smaller subsequent packet must not reopen investigation after finalization.
            bridge.count_tokens = lambda text: 40000
            final = payload()
            bridge.validate(final)
            self.assertEqual([t['function']['name'] for t in final['tools']], ['ryt_submit_review'])
            self.assertEqual(final['tool_choice'], full['tool_choice'])

    def test_glm_uses_remaining_call_allocation_to_reserve_submission_turns(self):
        with ProviderBridge('synthetic', lambda text: 100, max_calls=9) as bridge:
            payload = {'model': 'glm-5.3-flash', 'stream': True, 'messages': [],
                'tools': [{'type': 'function', 'function': {'name': name}} for name in
                          ('ryt_read_file', 'ryt_submit_review')]}
            bridge.validate(payload)
            self.assertEqual([t['function']['name'] for t in payload['tools']], ['ryt_submit_review'])
            self.assertIn('8 provider requests remain', payload['messages'][0]['content'])

    def test_only_the_glm_profile_and_credential_are_admitted(self):
        for name in ['https://attacker.invalid', 'bai-qwen']:
            with self.assertRaises(ValueError):
                profile(name)
        configured = routes({'OPENAI_KEY': 'glm-secret', 'PR_REVIEW_BAI_01': 'bai-secret',
            'OPENAI_API_BASE': 'https://attacker.invalid'})
        self.assertEqual([(route.alias, route.profile) for route in configured], [('zai-01', 'zai')])
        self.assertNotIn('secret', repr(configured))
        with self.assertRaises(ValueError):
            routes({'PR_REVIEW_BAI_01': 'bai-only'})

    def test_glm_profile_forces_maximum_reasoning_and_preserves_budgets(self):
        with ProviderBridge('synthetic', lambda text: 100) as bridge:
            payload = {'model': 'glm-5.3-flash', 'messages': [], 'stream': True,
                'enable_thinking': False, 'reasoning_effort': 'none', 'max_tokens': 99999}
            record = bridge.validate(payload)
            self.assertNotIn('enable_thinking', payload)
            self.assertEqual(payload['reasoning_effort'], 'max')
            self.assertEqual(payload['max_tokens'], 32768)
            self.assertEqual((record['provider'], record['reasoning_effort']), ('zai', 'max'))
            self.assertIs(record['thinking_enabled'], True)
            self.assertEqual(record['remaining_input_tokens'], 131072 - 32768 - 1024 - 100)
            with self.assertRaises(ValueError):
                bridge.observe(record, ('data: ' + json.dumps({'model': 'qwen3.8-flash'})).encode())

    def test_glm_cannot_override_its_fixed_destination(self):
        with self.assertRaises(ValueError):
            ProviderBridge('synthetic', len, profile_id='zai', endpoint='https://attacker.invalid')
        from ryt.bridge import NoProviderRedirect
        handler = NoProviderRedirect()
        with self.assertRaises(ValueError):
            handler.redirect_request(urllib.request.Request(profile('zai').endpoint),
                None, 307, '', {}, 'https://attacker.invalid')

    def test_outages_retire_rate_limits_rotate_and_assurance_errors_do_not(self):
        pool = ProviderPool([Route('zai-01', 'zai', 'secret-a'), Route('zai-02', 'zai', 'secret-b')])
        first = pool.next()
        self.assertFalse(pool.fail(first, 'reported_model'))
        self.assertFalse(pool.fail(first, 'finish_length'))
        self.assertFalse(pool.fail(first, 'HTTP_401'))
        self.assertTrue(pool.fail(first, 'HTTP_429'))
        self.assertEqual(pool.next().alias, 'zai-01')
        self.assertTrue(pool.fail(first, 'HTTP_502'))
        second = pool.next()
        self.assertEqual(second.alias, 'zai-02')
        self.assertTrue(pool.fail(second, 'HTTP_504'))
        with self.assertRaises(ValueError):
            pool.next()
        self.assertNotIn('secret', json.dumps(pool.audit()))
        self.assertEqual([f['failure_code'] for f in pool.audit()], ['HTTP_429', 'HTTP_502', 'HTTP_504'])


if __name__ == '__main__':
    unittest.main()
