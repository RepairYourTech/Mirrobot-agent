import copy
import json
from pathlib import Path
import tempfile
import unittest

from test_assurance import fixture, review
from ryt.tool_server import RepositoryTools


class SubmissionIntegrity(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = RepositoryTools(fixture(self.root), self.root / 'out')
        self.tools.call('read_diff', {'path': 'auth.mjs'})
        self.tools.call('read_diff', {'path': 'auth.mjs', 'offset': 240})

    def candidate(self):
        payload = review()
        payload['review']['key_issues_to_review'] = [{
            'relevant_file': 'auth.mjs', 'issue_header': 'Await the authorization decision',
            'issue_content': '[P1] An unawaited Promise makes the authorization guard ineffective.',
            'start_line': 1, 'end_line': 1,
        }]
        return payload

    def test_rejected_findings_cannot_be_silently_replaced_with_empty_report(self):
        payload = self.candidate()
        del payload['review']['key_issues_to_review'][0]['issue_content']
        with self.assertRaises(ValueError):
            self.tools.call('submit_review', payload)
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, 'cannot discard rejected findings'):
                self.tools.call('submit_review', review())
        self.assertFalse(self.tools.submitted)
        self.assertFalse((self.root / 'out/result.json').exists())

    def test_corrected_findings_remain_submittable_after_rejected_empty_report(self):
        corrected = self.candidate()
        malformed = copy.deepcopy(corrected)
        malformed['review']['key_issues_to_review'][0]['issue_content'] = ' '
        with self.assertRaises(ValueError):
            self.tools.call('submit_review', malformed)
        with self.assertRaises(ValueError):
            self.tools.call('submit_review', review())
        accepted = self.tools.call('submit_review', corrected)
        self.assertEqual(accepted['findings'], 1)
        saved = json.loads((self.root / 'out/result.json').read_text())
        self.assertEqual(saved['review'], corrected['review'])

    def test_initial_clean_review_remains_allowed(self):
        self.assertEqual(self.tools.call('submit_review', review())['findings'], 0)

    def test_rejected_clean_schema_correction_does_not_imply_lost_findings(self):
        malformed = review()
        del malformed['review']['risk_level']
        with self.assertRaises(ValueError):
            self.tools.call('submit_review', malformed)
        self.assertEqual(self.tools.call('submit_review', review())['findings'], 0)

    def test_failure_before_finding_validation_still_prevents_silent_loss(self):
        malformed = self.candidate()
        malformed['files'] = []
        with self.assertRaises(ValueError):
            self.tools.call('submit_review', malformed)
        with self.assertRaisesRegex(ValueError, 'cannot discard rejected findings'):
            self.tools.call('submit_review', review())

    def test_invalid_top_level_arguments_still_prevent_silent_loss(self):
        malformed = self.candidate()
        malformed['unexpected'] = 'untrusted value'
        with self.assertRaises(ValueError):
            self.tools.call('submit_review', malformed)
        with self.assertRaisesRegex(ValueError, 'cannot discard rejected findings'):
            self.tools.call('submit_review', review())

    def test_validation_evidence_identifies_field_without_copying_supplied_values(self):
        for field in ('issue_header', 'issue_content'):
            with self.subTest(field=field):
                malformed = self.candidate()
                malformed['review']['key_issues_to_review'][0][field] = {'untrusted': 'DO-NOT-LOG'}
                with self.assertRaisesRegex(ValueError, 'key_issues_to_review\\[0\\].' + field):
                    self.tools.call('submit_review', malformed)
                events = json.loads((self.root / 'out/tools.json').read_text())
                self.assertEqual(events[-1]['validation'], {
                    'code': 'finding_text_required',
                    'field': 'review.key_issues_to_review[0].' + field,
                })
                self.assertNotIn('DO-NOT-LOG', json.dumps(events))
