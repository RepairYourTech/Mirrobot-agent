import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ryt.context_packet import initial_packet
from ryt.common import write_json, sha256
from ryt.tool_server import RepositoryTools, TOOLS


class ContextBoundaries(unittest.TestCase):
    def context(self):
        return {'head': 'a'*40, 'required_files': ['a.ts'], 'snapshot_files': ['a.ts','b.ts'],
                'sections': {'prior_findings': [
                    {'path': 'a.ts', 'body': 'Previous a finding\n' * 200, 'resolved': False},
                    {'path': 'b.ts', 'body': 'Previous b finding\n' * 200, 'resolved': True}],
                'pr': 'description', 'repository_guidance': 'guidance', 'requirements': ['acceptance']}}

    def test_complete_diffs_remain_unchanged_and_no_history_is_removed(self):
        context=self.context();before=copy.deepcopy(context)
        diffs={'a.ts': 'all exact hunks\n'};p=initial_packet(context,diffs)
        self.assertEqual(p['diffs'],diffs);self.assertEqual(context,before)
        self.assertNotIn('snapshot_files',p['context'])
        records=p['context']['sections']['prior_findings']['records']
        self.assertEqual(len(records),2)
        for record,source in zip(records,context['sections']['prior_findings']):
            self.assertNotIn('body',record);self.assertEqual(record['body_sha256'],sha256(source['body']))
        self.assertLess(len(json.dumps(p)),len(json.dumps(context)))

    def test_prior_bodies_remain_available_with_exact_path_and_pagination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data=root/'data';data.mkdir();(data/'head').mkdir()
            write_json(data/'context.json',self.context());write_json(data/'diffs.json',{'a.ts':'diff'})
            tools=RepositoryTools(data,root/'out')
            response=tools.call('read_context',{'section':'prior_findings','path':'a.ts'})
            text=response['text']
            while response['next_offset'] is not None:
                response=tools.call('read_context',{'section':'prior_findings','path':'a.ts','offset':response['next_offset']});text+=response['text']
            found=json.loads(text)
            self.assertEqual(found,[self.context()['sections']['prior_findings'][0]])
            with self.assertRaises(ValueError):tools.call('read_context',{'section':'pr','path':'a.ts'})
            with self.assertRaises(ValueError):tools.call('read_context',{'section':'prior_findings','path':'../escape'})

    def test_file_pagination_does_not_skip_paths_between_pages(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data=root/'data';data.mkdir();(data/'head').mkdir()
            context=self.context();context['snapshot_files']=[f'file-{n:03}.ts' for n in range(67)]
            write_json(data/'context.json',context);write_json(data/'diffs.json',{'a.ts':'diff'})
            tools=RepositoryTools(data,root/'out');found=[];offset=0
            while offset is not None:
                response=tools.call('list_files',{'offset':offset});found+=response['files'];offset=response['next_offset']
            self.assertEqual(found,context['snapshot_files']);self.assertEqual(len(set(found)),67)

    def test_submission_schema_explains_the_actual_required_output(self):
        spec=next(tool for tool in TOOLS if tool['name']=='submit_review')['inputSchema']
        review=spec['properties']['review']
        self.assertEqual(set(review['required']),{'key_issues_to_review','security_concerns','risk_level','merge_recommendation'})
        self.assertEqual(review['properties']['key_issues_to_review']['items']['properties']['start_line']['minimum'],1)
        self.assertEqual(spec['properties']['files']['items']['properties']['analysis']['minLength'],10)


    def test_long_prior_body_can_be_read_without_a_single_escaped_json_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data=root/'data';data.mkdir();(data/'head').mkdir()
            context=self.context();body=('line with quotes " and source\n'*250)
            context['sections']['prior_findings'][0]['body']=body
            write_json(data/'context.json',context);write_json(data/'diffs.json',{'a.ts':'diff'})
            tools=RepositoryTools(data,root/'out');offset=0;read=''
            while offset is not None:
                result=tools.call('read_context',{'section':'prior_findings','ordinal':0,'offset':offset})
                read+=result['text'];offset=result['next_offset']
            self.assertEqual(read,body);self.assertEqual(result['sha256'],sha256(body))
