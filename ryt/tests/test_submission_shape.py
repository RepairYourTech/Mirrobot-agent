"""Malformed model data must be correctable, not an internal fatal failure."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ryt.backend import execute_agent
from ryt.common import load_json
from ryt.tool_server import RepositoryTools, SubmissionValidationError
from test_assurance import fixture, review
from test_opencode import Stream


def candidate():
    payload = review()
    payload['review']['key_issues_to_review'] = [{
        'relevant_file': 'auth.mjs', 'issue_header': 'Await authorization',
        'issue_content': '[P1] The Promise guard permits an unauthorized query.',
        'start_line': 1, 'end_line': 1,
    }]
    return payload


def tools_for(root):
    tools = RepositoryTools(fixture(root), root / 'evidence')
    tools.call('read_diff', {'path': 'auth.mjs'})
    tools.call('read_diff', {'path': 'auth.mjs', 'offset': 240})
    return tools


class SubmissionShape(unittest.TestCase):
    def test_nested_shapes_have_value_free_diagnostics_and_allow_full_correction(self):
        cases = [('files', None, 'files', 'file_dispositions_required'),
                 ('missing_files', None, 'files', 'file_dispositions_mismatch'),
                 ('duplicate_files', None, 'files', 'file_dispositions_mismatch'),
                 ('review', None, 'review', 'review_object_required'),
                 ('findings', None, 'review.key_issues_to_review', 'findings_array_required')]
        cases += [('file_record', v, 'files[0]', 'file_disposition_object_required')
                  for v in (None, 'DO-NOT-LOG', 1, [])]
        cases += [('file_path', v, 'files[0].path', 'assigned_file_required')
                  for v in (None, {}, [], True, 'DO-NOT-LOG')]
        cases += [('analysis', v, 'files[0].analysis', 'file_analysis_required')
                  for v in (None, {}, ' x ')]
        cases += [('finding_record', v, 'review.key_issues_to_review[0]', 'finding_object_required')
                  for v in (None, 'DO-NOT-LOG', 1, [])]
        cases += [('anchor', v, 'review.key_issues_to_review[0].relevant_file', 'finding_anchor_invalid')
                  for v in (None, {}, [], True, 'DO-NOT-LOG')]
        cases += [(key, {}, 'review.' + key, 'review_section_required')
                  for key in ('security_concerns', 'risk_level', 'merge_recommendation')]
        for target, value, field, code in cases:
            with self.subTest(target=target, value=value), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                tools = tools_for(root)
                corrected = candidate()
                malformed = copy.deepcopy(corrected)
                if target in ('files', 'review'): malformed[target] = value
                elif target == 'missing_files': malformed['files'] = []
                elif target == 'duplicate_files': malformed['files'] *= 2
                elif target == 'file_record': malformed['files'] = [value]
                elif target == 'file_path': malformed['files'][0]['path'] = value
                elif target == 'analysis': malformed['files'][0]['analysis'] = value
                elif target == 'findings': malformed['review']['key_issues_to_review'] = value
                elif target == 'finding_record': malformed['review']['key_issues_to_review'] = [value]
                elif target == 'anchor': malformed['review']['key_issues_to_review'][0]['relevant_file'] = value
                else: malformed['review'][target] = value
                with self.assertRaises(SubmissionValidationError):
                    tools.call('submit_review', malformed)
                self.assertFalse(tools.fatal)
                self.assertFalse((root / 'evidence/result.json').exists())
                self.assertEqual(tools.events[-1]['validation'], {'code': code, 'field': field})
                self.assertNotIn('DO-NOT-LOG', json.dumps(tools.events))
                if tools.finding_count_attempted:
                    with self.assertRaisesRegex(ValueError, 'cannot discard rejected findings'):
                        tools.call('submit_review', review())
                self.assertEqual(tools.call('submit_review', corrected)['findings'], 1)
                self.assertEqual(load_json((root / 'evidence/result.json').read_text())['review'], corrected['review'])

    def test_internal_failure_still_poisons_the_session(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            tools = tools_for(root)
            with patch.object(tools, 'execute', side_effect=RuntimeError('synthetic internal failure')):
                with self.assertRaises(RuntimeError):
                    tools.call('review_context', {})
            self.assertTrue(tools.fatal)
            with self.assertRaisesRegex(ValueError, 'fatal inspection'):
                tools.call('submit_review', candidate())
            self.assertFalse((root / 'evidence/result.json').exists())


@unittest.skipUnless(os.environ.get('RYT_OPENCODE_BIN'), 'explicit pinned binary required')
class SubmissionShapeEngine(unittest.TestCase):
    def test_malformed_then_empty_then_corrected_report_preserves_findings(self):
        for target in ('files', 'findings'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                data = fixture(root)
                session = root / 'session'
                session.mkdir()
                corrected = candidate()
                malformed = copy.deepcopy(corrected)
                if target == 'files': malformed['files'] = [None]
                else: malformed['review']['key_issues_to_review'] = [None]
                actions = [malformed, review(), corrected]
                requests = []
                def response(request, timeout):
                    payload = load_json(request.data)
                    self.assertIs(payload['enable_thinking'], False)
                    index = len(requests)
                    requests.append(payload)
                    if index < len(actions):
                        delta = {'role': 'assistant', 'tool_calls': [{'index': 0,
                            'id': f'shape-{index}', 'type': 'function', 'function': {
                                'name': 'ryt_submit_review', 'arguments': json.dumps(actions[index])}}]}
                    else:
                        delta = {'role': 'assistant', 'content': 'Review submitted.'}
                    choices = [{'index': 0, 'delta': delta, 'finish_reason': None},
                               {'index': 0, 'delta': {}, 'finish_reason': 'stop'}]
                    chunks = ['data: ' + json.dumps({'model': 'qwen3.8-flash', 'choices': [choice]})
                              + '\n\n' for choice in choices]
                    return Stream((''.join(chunks) + 'data: [DONE]\n\n').encode())
                with patch('ryt.bridge.open_provider', side_effect=response):
                    result, evidence = execute_agent(Path(os.environ['RYT_OPENCODE_BIN']), data,
                        session, 'SYNTHETIC-CREDENTIAL', lambda text: len(text) // 4,
                        timeout_seconds=30, profile_id='bai-qwen', max_calls=10, max_tools=8)
                self.assertEqual(result['review'], corrected['review'])
                submissions = [e for e in evidence['tool_events'] if e['tool'] == 'submit_review']
                self.assertEqual([e['status'] for e in submissions], ['failed', 'failed', 'success'])
                expected = 'file_disposition_object_required' if target == 'files' else 'finding_object_required'
                self.assertEqual(submissions[0]['validation']['code'], expected)
                self.assertEqual(submissions[1]['validation']['code'], 'rejected_findings_discarded')
                self.assertEqual(len(requests), 4)
                self.assertEqual(set(result['coverage']), {'auth.mjs'})
                self.assertNotIn('SYNTHETIC-CREDENTIAL', json.dumps(evidence))
