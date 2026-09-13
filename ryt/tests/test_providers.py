"""Provider profile and bounded credential-failover contracts."""
import json
import unittest
from unittest.mock import patch
import urllib.request

from ryt.bridge import ProviderBridge
from ryt.providers import profile, routes, ProviderPool


class ProviderContracts(unittest.TestCase):
    def test_qwen_reserves_context_for_submission_without_dropping_input(self):
        import copy
        def payload():
            return {'model': 'qwen3.8-flash', 'stream': True,
                'messages': [{'role': 'user', 'content': 'complete immutable review packet'}],
                'tools': [{'type': 'function', 'function': {'name': name}} for name in
                          ('ryt_read_file', 'ryt_search', 'ryt_submit_review')]}
        with ProviderBridge('synthetic', lambda text: 40000, profile_id='bai-qwen') as bridge:
            initial = payload()
            bridge.validate(initial)
            self.assertEqual(len(initial['tools']), 3)
            bridge.count_tokens = lambda text: 70000
            full = payload()
            messages = copy.deepcopy(full['messages'])
            bridge.validate(full)
            self.assertEqual([t['function']['name'] for t in full['tools']], ['ryt_submit_review'])
            self.assertEqual(full['messages'][1:], messages)
            self.assertIn('FINALIZATION', full['messages'][0]['content'])
            # A smaller subsequent packet must not reopen investigation after finalization.
            bridge.count_tokens = lambda text: 40000
            final = payload()
            bridge.validate(final)
            self.assertEqual([t['function']['name'] for t in final['tools']], ['ryt_submit_review'])

    def test_qwen_uses_remaining_call_allocation_to_reserve_submission_turns(self):
        with ProviderBridge('synthetic', lambda text: 100, profile_id='bai-qwen', max_calls=9) as bridge:
            payload = {'model': 'qwen3.8-flash', 'stream': True, 'messages': [],
                'tools': [{'type': 'function', 'function': {'name': name}} for name in
                          ('ryt_read_file', 'ryt_submit_review')]}
            bridge.validate(payload)
            self.assertEqual([t['function']['name'] for t in payload['tools']], ['ryt_submit_review'])
            self.assertIn('8 provider requests remain', payload['messages'][0]['content'])

    def test_only_trusted_profiles_and_deduplicated_credentials_are_admitted(self):
        with self.assertRaises(ValueError):
            profile('https://attacker.invalid')
        configured = routes({'OPENAI_KEY': 'glm-secret', 'PR_REVIEW_BAI_01': 'bai-secret',
            'PR_REVIEW_BAI_02': 'bai-secret', 'PR_REVIEW_BAI_03': 'reserve-secret',
            'OPENAI_API_BASE': 'https://attacker.invalid', 'PR_REVIEW_BAI_04': 'unapproved'})
        self.assertEqual([route.alias for route in configured], ['zai-01', 'bai-01', 'bai-03'])
        self.assertEqual([route.profile for route in configured], ['zai', 'bai-qwen', 'bai-qwen'])
        self.assertNotIn('secret', repr(configured))

    def test_qwen_profile_forces_thinking_off_and_preserves_budgets(self):
        with ProviderBridge('synthetic', lambda text: 100, profile_id='bai-qwen') as bridge:
            payload = {'model': 'qwen3.8-flash', 'messages': [], 'stream': True,
                'enable_thinking': True, 'reasoning_effort': 'max', 'max_tokens': 99999}
            record = bridge.validate(payload)
            self.assertIs(payload['enable_thinking'], False)
            self.assertNotIn('reasoning_effort', payload)
            self.assertEqual(payload['max_tokens'], 32768)
            self.assertEqual(record['provider'], 'bai')
            self.assertEqual(record['reasoning_effort'], 'none')
            self.assertIs(record['thinking_enabled'], False)
            self.assertEqual(record['remaining_input_tokens'], 131072 - 32768 - 1024 - 100)
            for data in [
                {'model': 'glm-5.3-flash'},
                {'model': 'qwen3.8-flash', 'choices': [{'delta': {'reasoning_content': 'unexpected'}}]},
                {'model': 'qwen3.8-flash', 'usage': {'completion_tokens_details': {'reasoning_tokens': 1}}},
            ]:
                with self.assertRaises(ValueError):
                    bridge.observe(record, ('data: ' + json.dumps(data)).encode())

    def test_qwen_and_glm_cannot_override_their_fixed_destinations(self):
        for name in ['zai', 'bai-qwen']:
            with self.assertRaises(ValueError):
                ProviderBridge('synthetic', len, profile_id=name, endpoint='https://attacker.invalid')
        from ryt.bridge import NoProviderRedirect
        handler = NoProviderRedirect()
        with self.assertRaises(ValueError):
            handler.redirect_request(urllib.request.Request(profile('bai-qwen').endpoint),
                None, 307, '', {}, 'https://attacker.invalid')

    def test_availability_failures_rotate_once_but_assurance_errors_do_not(self):
        configured = routes({'OPENAI_KEY': 'glm', 'PR_REVIEW_BAI_01': 'bai1', 'PR_REVIEW_BAI_02': 'bai2'})
        pool = ProviderPool(configured)
        first = pool.next()
        self.assertEqual(first.alias, 'zai-01')
        self.assertTrue(pool.fail(first, 'HTTP_429'))
        second = pool.next()
        self.assertEqual(second.alias, 'bai-01')
        self.assertTrue(pool.fail(second, 'HTTP_503'))
        third = pool.next()
        self.assertEqual(third.alias, 'bai-02')
        self.assertFalse(pool.fail(third, 'reported_model'))
        self.assertFalse(pool.fail(third, 'finish_length'))
        self.assertFalse(pool.fail(third, 'HTTP_401'))
        self.assertTrue(pool.fail(third, 'HTTP_429'))
        with self.assertRaises(ValueError):
            pool.next()

    def test_successful_route_stays_preferred_and_no_key_material_enters_audit(self):
        configured = routes({'OPENAI_KEY': 'secret-glm', 'PR_REVIEW_BAI_01': 'secret-bai'})
        pool = ProviderPool(configured)
        pool.fail(pool.next(), 'HTTP_429')
        self.assertEqual(pool.next().alias, 'bai-01')
        self.assertEqual(pool.next().alias, 'bai-01')
        self.assertNotIn('secret-', json.dumps(pool.audit()))
        self.assertEqual(pool.audit(), [{'route': 'zai-01', 'failure_code': 'HTTP_429'}])


if __name__ == '__main__':
    unittest.main()
