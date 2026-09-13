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
                with patch('ryt.bridge.open_provider',side_effect=response):
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

@unittest.skipUnless(os.environ.get('RYT_OPENCODE_BIN'), 'explicit pinned binary required')
class FreshSessionIntegration(unittest.TestCase):
    def test_thirteen_files_execute_as_four_fresh_contexts_and_publish_all_dispositions(self):
        import asyncio,re,time
        from types import SimpleNamespace
        from ryt.backend import ReviewBackend
        with tempfile.TemporaryDirectory(prefix='ryt-multi-session-') as temp:
            root=Path(temp);data=fixture(root)
            backend=ReviewBackend.__new__(ReviewBackend)
            backend.root=root;backend.data=data;backend.binary=Path(os.environ['RYT_OPENCODE_BIN'])
            fragments=[(f'file-{i}.py','+source line\n'*20) for i in range(13)]
            backend.chunks=[fragments];backend.deadline=time.monotonic()+300
            backend.evidence={'head':'a'*40,'base':'b'*40,'mirrobot_sessions':[]}
            backend.inventory={'files':{'auth.mjs':{},'policy.mjs':{}},'unavailable':[]}
            backend.histories=[];backend.history_limited=False
            backend.reviewer=SimpleNamespace(git_provider=SimpleNamespace(pr=SimpleNamespace(title='Fixture',body='')),
                  vars={},token_handler=SimpleNamespace(count_tokens=lambda text:len(text)//4))
            planned=backend.plan_sessions();self.assertEqual([len(c) for c in planned],[4,4,4,1])
            active={};seen=[]
            def response(request,timeout):
                payload=load_json(request.data)
                text='\n'.join(m['content'] for m in payload['messages'] if m['role']=='user' and isinstance(m.get('content'),str))
                match=re.search(r'RYT_REVIEW_PACKET_BEGIN_([a-f0-9]+)\n(.*?)\nRYT_REVIEW_PACKET_END_\1',text,re.S)
                self.assertIsNotNone(match)
                nonce=match[1];packet=load_json(match[2]);paths=list(packet['diffs'])
                turn=active.get(nonce,0);active[nonce]=turn+1
                if turn==0:
                    self.assertFalse(any(m['role']=='tool' for m in payload['messages']))
                    seen.append(paths)
                    name='ryt_read_file';args={'path':'policy.mjs'}
                elif turn==1:
                    name='ryt_submit_review';args={'files':[{'path':p,'analysis':'Checked this full diff and its shared policy contract.'} for p in paths],
                        'review':review()['review']}
                else:name=None
                delta={'role':'assistant','content':'Completed this session.'} if name is None else {
                    'role':'assistant','tool_calls':[{'index':0,'id':nonce+str(turn),'type':'function',
                    'function':{'name':name,'arguments':json.dumps(args)}}]}
                finish='stop' if name is None else 'tool_calls'
                lines=[]
                for choice in [{'index':0,'delta':delta,'finish_reason':None}, {'index':0,'delta':{},'finish_reason':finish}]:
                    lines.append('data: '+json.dumps({'id':'test','object':'chat.completion.chunk','created':1,
                         'model':'glm-5.3-flash','choices':[choice]})+'\n\n')
                lines.append('data: '+json.dumps({'choices':[],'usage':{'prompt_tokens':100,'completion_tokens':50,'total_tokens':150}})+'\n\n')
                return Stream((''.join(lines)+'data: [DONE]\n\n').encode())
            with patch.dict(os.environ, {'OPENAI_KEY': 'SYNTHETIC-CREDENTIAL'}), patch('ryt.bridge.open_provider',side_effect=response):
                for i,group in enumerate(planned):asyncio.run(backend.predict(i,group))
            self.assertEqual(len(active),4)
            self.assertEqual([sorted(group) for group in seen], [sorted(p for p,_ in c) for c in planned])
            self.assertEqual(sorted(p for group in seen for p in group), sorted(p for p,_ in fragments))
            self.assertEqual(len(backend.evidence['mirrobot_sessions']),4)
            self.assertEqual([s['chunk_index'] for s in backend.evidence['mirrobot_sessions']],[1,2,3,4])
            for session,chunk in zip(backend.evidence['mirrobot_sessions'],planned):
                self.assertEqual(set(session['delivery']),{p for p,_ in chunk})
                self.assertLessEqual(session['provider_requests'][0]['estimated_input_tokens'],49152)
                self.assertTrue(all(r['reasoning_effort']=='max' for r in session['provider_requests']))
