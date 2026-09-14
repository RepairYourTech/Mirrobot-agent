"""Completion remains fail-closed after a model corrects a rejected tool call."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from ryt.backend import validate_session_output
from ryt.common import write_json
from ryt.diagnostics import SessionFailure


class CompletionEvidence(unittest.TestCase):
    def test_complete_result_and_every_failure_boundary_have_specific_outcomes(self):
        events = [{'type': 'step_finish', 'part': {'reason': 'stop'}}]
        requests = [{'finish_reasons': ['stop'], 'tool_results_sha256': ['receipt'],
                     'prefilled_files': {'file.py': {'sha256': 'diff-digest', 'lines': 2}}}]
        result = {'coverage': {'file.py': {'sha256': 'diff-digest', 'lines': 2, 'delivered_lines': 2}}}
        tools = [{'tool': 'read_diff', 'status': 'success', 'output_sha256': 'receipt'}]
        for fault, code in [
            ('none', None), ('engine_error', 'engine_error_event'),
            ('missing_stop', 'engine_missing_stop'), ('missing_requests', 'provider_missing_completion'),
            ('unfinished_request', 'provider_missing_completion'), ('missing_result', 'missing_submission'),
            ('missing_receipt', 'tool_delivery_mismatch'), ('missing_prefill', 'initial_coverage_missing'),
            ('different_coverage', 'reported_coverage_mismatch'),
        ]:
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                output = root / 'evidence'
                output.mkdir()
                current_events = copy.deepcopy(events)
                current_requests = copy.deepcopy(requests)
                current_result = copy.deepcopy(result)
                if fault == 'engine_error': current_events.insert(0, {'type': 'error'})
                if fault == 'missing_stop': current_events = []
                if fault == 'missing_requests': current_requests = []
                if fault == 'unfinished_request': current_requests[0]['finish_reasons'] = []
                if fault == 'missing_receipt': current_requests[0]['tool_results_sha256'] = []
                if fault == 'missing_prefill': current_requests[0]['prefilled_files'] = {}
                if fault == 'different_coverage': current_result['coverage']['file.py']['sha256'] = 'wrong'
                (root / 'events.jsonl').write_text('\n'.join(json.dumps(event) for event in current_events))
                if fault != 'missing_result': write_json(output / 'result.json', current_result)
                write_json(output / 'tools.json', tools)
                if code is None:
                    self.assertEqual(validate_session_output(root, current_requests), (result, tools, 0))
                else:
                    with self.assertRaises(SessionFailure) as raised:
                        validate_session_output(root, current_requests)
                    self.assertEqual(raised.exception.code, code)


if __name__ == '__main__':
    unittest.main()
