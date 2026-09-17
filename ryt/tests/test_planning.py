"""Regression for the 13-file canary overflowing a single growing conversation."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ryt.planning import INITIAL_INPUT_LIMIT, MAX_FILES, MAX_SESSIONS, plan_sessions


class SessionPlanning(unittest.TestCase):
    def plan(self, fragments, **kwargs):
        return plan_sessions([fragments], len, lambda group: 24000 + sum(len(t) for _, t in group), **kwargs)

    def test_thirteen_file_canary_gets_fresh_bounded_sessions_without_omission(self):
        files=[(f'file-{i}.py','x'*1600) for i in range(13)]
        chunks,plan=self.plan(files)
        self.assertEqual([item for chunk in chunks for item in chunk], files)
        self.assertEqual([len(c) for c in chunks],[4,4,4,1])
        self.assertEqual(len(plan['sessions']),4)
        self.assertTrue(all(s['estimated_initial_tokens']<=49152 for s in plan['sessions']))
        self.assertEqual(plan['input_files'],13)

    def test_splits_before_packet_or_diff_budget_is_exceeded(self):
        chunks,plan=plan_sessions([[('a','x'*5000),('b','x'*5000)]], len,
                                 lambda group: 40000 + sum(len(t) for _,t in group))
        self.assertEqual([len(c) for c in chunks],[1,1])
        self.assertEqual(plan['sessions'][0]['diff_tokens'],5000)

    def test_single_large_file_keeps_whole_diff_when_it_fits_initial_budget(self):
        chunks,_=self.plan([('large','x'*15000),('small','x')])
        self.assertEqual([p for c in chunks for p,_ in c],['large','small'])
        self.assertEqual(len(chunks[0][0][1]),15000)
        self.assertEqual(len(chunks),2)

    def test_reviewed_initial_allocations_preserve_independent_headroom_floor(self):
        from ryt.bridge import CONTEXT_TOKENS, OUTPUT_TOKENS
        self.assertIn(INITIAL_INPUT_LIMIT, (49152, 65536))
        self.assertEqual(CONTEXT_TOKENS, 131072)
        self.assertEqual(OUTPUT_TOKENS, 32768)
        self.assertGreaterEqual(CONTEXT_TOKENS - OUTPUT_TOKENS - 1024 - INITIAL_INPUT_LIMIT, 31744)
        files = [('large', 'x' * (INITIAL_INPUT_LIMIT - 24000))]
        chunks, manifest = self.plan(files)
        self.assertEqual(chunks, [files])
        self.assertEqual(manifest['initial_input_limit'], INITIAL_INPUT_LIMIT)
        self.assertEqual(manifest['sessions'][0]['estimated_initial_tokens'], INITIAL_INPUT_LIMIT)
        with self.assertRaisesRegex(ValueError, 'initial context'):
            self.plan([('large', 'x' * (INITIAL_INPUT_LIMIT - 24000 + 1))])
        with self.assertRaisesRegex(ValueError, 'initial context'):
            plan_sessions([[('large', 'complete diff')]], len, lambda _: 65537)

    def test_initial_allocation_accepts_64k_without_changing_complete_input(self):
        files = [('large', 'x' * 41536)]
        chunks, manifest = self.plan(files)
        self.assertEqual(chunks, [files])
        self.assertEqual(manifest['initial_input_limit'], 65536)
        self.assertEqual(manifest['sessions'][0]['estimated_initial_tokens'], 65536)
        with self.assertRaisesRegex(ValueError, 'initial context'):
            self.plan([('large', 'x' * 41537)])

    def test_initial_allocation_splits_before_64k_even_when_diff_target_fits(self):
        files = [('a', 'x' * 3000), ('b', 'y' * 3000)]
        chunks, _ = plan_sessions([files], len,
            lambda group: 60000 + sum(len(text) for _, text in group))
        self.assertEqual(chunks, [[files[0]], [files[1]]])

    def test_unfit_file_and_unfit_scope_fail_instead_of_truncating_or_expanding_calls(self):
        with self.assertRaisesRegex(ValueError,'initial context'):
            self.plan([('huge','x'*50000)])
        # The trusted assurance test follows the pinned planner constants so
        # the base-revision controller can validate a separately reviewed cap change.
        self.assertEqual(MAX_SESSIONS,8)
        at_limit=[(f'f{i}','x') for i in range(MAX_SESSIONS * MAX_FILES)]
        chunks,plan=self.plan(at_limit)
        self.assertEqual(len(chunks),MAX_SESSIONS)
        self.assertEqual(plan['max_sessions'],MAX_SESSIONS)
        self.assertEqual([item for chunk in chunks for item in chunk],at_limit)
        with self.assertRaisesRegex(ValueError,'eight-session'):
            self.plan([(f'f{i}','x') for i in range(MAX_SESSIONS * MAX_FILES + 1)])


    def test_empty_duplicate_and_noninteger_counters_are_rejected(self):
        for items in [[],[('x','')],[('x','one'),('x','two')]]:
            with self.assertRaises(ValueError):self.plan(items)
        for count in [lambda _:True,lambda _:-1,lambda _:1.5]:
            with self.assertRaises(ValueError):plan_sessions([[('a','diff')]],count,lambda _:20000)

    def test_evidence_is_deterministic_and_records_each_exact_chunk_hash(self):
        from ryt.common import sha256
        files=[('a','old and new\n'),('b','another\n')]
        first=self.plan(files);second=self.plan(files)
        self.assertEqual(first,second)
        self.assertEqual(first[1]['sessions'][0]['input_sha'],sha256('\n'.join(t for _,t in files)))


class InitialRequestBudget(unittest.TestCase):
    def test_initial_request_leaves_reserved_exploration_space(self):
        import tempfile
        from ryt.bridge import ProviderBridge
        from ryt.common import load_json
        for tokens,accepted in [(INITIAL_INPUT_LIMIT,True),(INITIAL_INPUT_LIMIT + 1,False),(65537,False)]:
            with tempfile.TemporaryDirectory() as temp,ProviderBridge('SYNTHETIC',lambda _:tokens) as bridge:
                packet=bridge.input_packet({'diffs':{'x':'diff'}},Path(temp)/'receipt.json')
                payload={'model':'glm-5.3-flash','messages':[{'role':'user','content':packet}],'stream':True}
                if accepted:
                    record=bridge.validate(payload)
                    self.assertEqual(record['remaining_input_tokens'],131072 - 32768 - 1024 - tokens)
                    self.assertGreaterEqual(record['remaining_input_tokens'],31744)
                    self.assertEqual(payload['reasoning_effort'],'max')
                    self.assertEqual(payload['max_tokens'],32768)
                else:
                    with self.assertRaises(ValueError):bridge.validate(payload)
                    self.assertEqual(bridge.records,[])

    def test_budget_notice_never_discards_original_context(self):
        from ryt.bridge import ProviderBridge
        import copy
        original=[{'role':'system','content':'Original policy'}, {'role':'user','content':'All original data'}]
        with ProviderBridge('SYNTHETIC',lambda _:60000) as bridge:
            payload={'model':'glm-5.3-flash','messages':copy.deepcopy(original),'stream':True}
            bridge.validate(payload)
            self.assertEqual(payload['messages'][1:],original)
            self.assertIn('RYT SESSION CONTEXT',payload['messages'][0]['content'])
