"""Regression for the 13-file canary overflowing a single growing conversation."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ryt.planning import MAX_FILES, MAX_SESSIONS, plan_sessions


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

    def test_unfit_file_and_unfit_scope_fail_instead_of_truncating_or_expanding_calls(self):
        with self.assertRaisesRegex(ValueError,'initial context'):
            self.plan([('huge','x'*30000)])
        # The trusted assurance test follows the pinned planner constant instead
        # of hard-coding today's session count, so a separately reviewed limit
        # change can still be tested by base-revision control code.
        at_limit=[(f'f{i}','x') for i in range(MAX_SESSIONS * MAX_FILES)]
        chunks,plan=self.plan(at_limit)
        self.assertEqual(len(chunks),MAX_SESSIONS)
        self.assertEqual(plan['max_sessions'],MAX_SESSIONS)
        self.assertEqual([item for chunk in chunks for item in chunk],at_limit)
        with self.assertRaisesRegex(ValueError,'session safety limit'):
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
        for tokens,accepted in [(49152,True),(49153,False)]:
            with tempfile.TemporaryDirectory() as temp,ProviderBridge('SYNTHETIC',lambda _:tokens) as bridge:
                packet=bridge.input_packet({'diffs':{'x':'diff'}},Path(temp)/'receipt.json')
                payload={'model':'glm-5.3-flash','messages':[{'role':'user','content':packet}],'stream':True}
                if accepted:
                    record=bridge.validate(payload)
                    self.assertEqual(record['remaining_input_tokens'],48128)
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
