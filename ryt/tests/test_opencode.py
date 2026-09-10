"""Actual pinned OpenCode + MCP + sandbox integration; provider responses are synthetic."""
import io
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


class Stream(io.BytesIO):
    headers = {'Content-Type': 'text/event-stream'}


@unittest.skipUnless(os.environ.get('RYT_OPENCODE_BIN'), 'explicit pinned binary required')
class OpenCodeIntegration(unittest.TestCase):
    def test_real_engine_and_tools_under_mocked_provider(self):
        with tempfile.TemporaryDirectory(prefix='ryt-opencode-integration-') as temp:
            root=Path(temp);data=fixture(root); session=root/'session';session.mkdir()
            calls=[]
            actions=[('ryt_review_context',{}),('ryt_read_diff',{'path':'auth.mjs'}),
                     ('ryt_read_diff',{'path':'auth.mjs','offset':240}),
                     ('ryt_read_file',{'path':'policy.mjs'}),
                     ('ryt_run_probe',{'language':'python','code':'from pathlib import Path\nassert "admin" in Path("/repo/policy.mjs").read_text()\nprint("PROBE_OK")'}),
                     ('ryt_submit_review',review())]
            def response(request, timeout):
                payload=load_json(request.data);calls.append(payload)
                self.assertEqual(payload['model'],'glm-5.3-flash')
                self.assertEqual(payload['reasoning_effort'],'max')
                self.assertEqual(request.full_url,'https://api.z.ai/api/coding/paas/v4/chat/completions')
                names=[tool['function']['name'] for tool in payload.get('tools',[])]
                self.assertIn('ryt_read_file',names)
                self.assertTrue(all(name.startswith('ryt_') or name=='invalid' for name in names),names)
                index=len(calls)-1
                if index<len(actions):
                    name,args=actions[index]
                    delta={'role':'assistant','tool_calls':[{'index':0,'id':'call'+str(index),
                        'type':'function','function':{'name':name,'arguments':json.dumps(args)}}]}
                    finish='tool_calls'
                else:
                    delta={'role':'assistant','content':'Review submitted with all required input accounted for.'};finish='stop'
                stream=[]
                for choice in [{'index':0,'delta':delta,'finish_reason':None},
                               {'index':0,'delta':{},'finish_reason':finish}]:
                    stream.append('data: '+json.dumps({'id':'chatcmpl-mock','object':'chat.completion.chunk',
                        'created':1700000000,'model':'glm-5.3-flash','choices':[choice]})+'\n\n')
                stream.append('data: '+json.dumps({'choices':[],'usage':{'prompt_tokens':100,'completion_tokens':50,'total_tokens':150}})+'\n\n')
                stream.append('data: [DONE]\n\n')
                return Stream(''.join(stream).encode())
            try:
                with patch('ryt.bridge.urllib.request.urlopen',side_effect=response):
                    result,telemetry=execute_agent(Path(os.environ['RYT_OPENCODE_BIN']),data,session,'NOT-A-REAL-KEY',lambda s:len(s)//4)
            except Exception:
                print('MOCK TEST ENGINE STDERR:',(session/'stderr.log').read_text()[-10000:])
                print('MOCK TEST ENGINE EVENTS:',(session/'events.jsonl').read_text()[-10000:])
                raise
            self.assertEqual(len(result['files']),1)
            self.assertEqual(len(telemetry['provider_requests']),7)
            self.assertEqual(result['coverage']['auth.mjs']['delivered_lines'],301)
            self.assertIn('read_file',[t['tool'] for t in telemetry['tool_events']])
            outputs=[json.dumps(p) for p in calls]
            self.assertTrue(any('PROBE_OK' in text for text in outputs),'nested networkless sandbox did not run')

if __name__=='__main__':unittest.main()
