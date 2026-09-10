"""Authenticated, fixed-upstream provider bridge. Provider key never enters OpenCode."""
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import secrets
import threading
import urllib.error
import urllib.request
from ryt.common import load_json, sha256, write_json

ENDPOINT = 'https://api.z.ai/api/coding/paas/v4/chat/completions'


class ProviderBridge:
    def __init__(self, api_key, count_tokens, *, endpoint=ENDPOINT):
        if endpoint != ENDPOINT:
            raise ValueError('provider endpoint is immutable')
        self.key = api_key
        self.token = secrets.token_hex(32)
        self.count_tokens = count_tokens
        self.records = []
        self.prefill = None
        self.prefill_nonce = secrets.token_hex(16)
        self.receipt_path = None
        self.failed = threading.Event()
        self.lock = threading.Lock()
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                if (self.path != '/v1/chat/completions' or
                        not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + bridge.token)):
                    self.send_error(403, 'endpoint or credential rejected')
                    return
                try:
                    length = int(self.headers.get('Content-Length', '0'))
                    if not 0 < length <= 4 * 1024 * 1024:
                        raise ValueError('request size invalid')
                    payload = load_json(self.rfile.read(length))
                    record = bridge.validate(payload)
                    request = urllib.request.Request(ENDPOINT, data=json.dumps(payload).encode(),
                        headers={'Authorization': 'Bearer ' + bridge.key, 'Content-Type': 'application/json'})
                    with urllib.request.urlopen(request, timeout=600) as response:
                        self.send_response(200)
                        self.send_header('Content-Type', response.headers.get('Content-Type', 'text/event-stream'))
                        self.send_header('Cache-Control', 'no-cache')
                        self.end_headers()
                        size = 0
                        for line in response:
                            size += len(line)
                            if size > 16 * 1024 * 1024:
                                raise ValueError('provider response exceeds budget')
                            bridge.observe(record, line)
                            self.wfile.write(line)
                            self.wfile.flush()
                        if not record['finish_reasons']:
                            raise ValueError('provider stream has no completed choice')
                except Exception as error:
                    bridge.failed.set()
                    bridge.error = ('HTTP_' + str(error.code)) if isinstance(error, urllib.error.HTTPError) else type(error).__name__
                    try:
                        self.send_error(502, 'provider request failed; no retry or fallback')
                    except OSError:
                        pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @staticmethod
    def receipts(messages):
        receipts = set()
        for message in messages:
            if message.get('role') != 'tool':
                continue
            content = message.get('content', '')
            if isinstance(content, str):
                content = [content]
            if not isinstance(content, list):
                continue
            for part in content:
                text = part.get('text', '') if isinstance(part, dict) else part
                if not isinstance(text, str):
                    continue
                try:
                    data = load_json(text)
                except (ValueError, TypeError):
                    continue
                if isinstance(data, dict) and {'path', 'text', 'sha256', 'offset', 'end'} <= data.keys():
                    receipts.add(sha256(json.dumps(data, sort_keys=True)))
        return sorted(receipts)

    def input_packet(self, packet, receipt_path):
        self.prefill = packet
        self.receipt_path = receipt_path
        return ('RYT_REVIEW_PACKET_BEGIN_' + self.prefill_nonce + '\n' +
                json.dumps(packet, ensure_ascii=False) + '\nRYT_REVIEW_PACKET_END_' + self.prefill_nonce)

    def prefill_receipts(self, messages):
        if self.prefill is None:
            return {}
        begin = 'RYT_REVIEW_PACKET_BEGIN_' + self.prefill_nonce + '\n'
        end = '\nRYT_REVIEW_PACKET_END_' + self.prefill_nonce
        for message in messages:
            if message.get('role') != 'user':
                continue
            content = message.get('content', '')
            parts = [content] if isinstance(content, str) else content
            if not isinstance(parts, list):
                continue
            for part in parts:
                text = part.get('text', '') if isinstance(part, dict) else part
                if not isinstance(text, str) or begin not in text:
                    continue
                raw = text.split(begin, 1)[1]
                if end not in raw:
                    raise ValueError('initial input packet truncated')
                actual = load_json(raw.split(end, 1)[0])
                if actual != self.prefill:
                    raise ValueError('initial input packet modified')
                return {path: {'sha256': sha256(diff), 'lines': len(diff.splitlines())}
                        for path, diff in actual['diffs'].items()}
        raise ValueError('complete initial input packet missing from provider request')

    def validate(self, payload):
        if payload.get('model') != 'glm-5.3-flash' or not isinstance(payload.get('messages'), list):
            raise ValueError('wrong model or messages')
        if payload.get('stream') is not True:
            raise ValueError('streaming required for completion evidence')
        if not isinstance(payload.get('max_tokens', 16384), int) or isinstance(payload.get('max_tokens'), bool):
            raise ValueError('invalid output limit')
        payload['reasoning_effort'] = 'max'
        payload['max_tokens'] = min(payload.pop('max_completion_tokens', payload.get('max_tokens', 16384)), 16384)
        payload['stream_options'] = {'include_usage': True}
        # Bound context without secretly clipping/compacting the model's inputs.
        tokens = self.count_tokens(json.dumps(payload))
        if tokens > 131072 - 16384 - 1024:
            raise ValueError('context budget exhausted; input will not be clipped')
        prefilled = self.prefill_receipts(payload['messages'])
        with self.lock:
            if prefilled and self.receipt_path is not None:
                write_json(self.receipt_path, prefilled)
            if len(self.records) >= 64:
                raise ValueError('model-call bound reached')
            record = {'model': payload['model'], 'reasoning_effort': payload['reasoning_effort'],
                      'request_sha256': sha256(json.dumps(payload, sort_keys=True)),
                      'estimated_input_tokens': tokens, 'finish_reasons': [], 'usage': {}, 'reported_models': [],
                      'tool_results_sha256': self.receipts(payload['messages']), 'prefilled_files': prefilled}
            self.records.append(record)
        return record

    def observe(self, record, line):
        if not line.startswith(b'data:'):
            return
        text = line[5:].strip()
        if text == b'[DONE]':
            return
        data = load_json(text)
        if data.get('error'):
            raise ValueError('provider stream error')
        model = data.get('model')
        if model and model.lower() != 'glm-5.3-flash':
            raise ValueError('provider reported a different model')
        if model and model not in record['reported_models']:
            record['reported_models'].append(model)
        if data.get('usage'):
            record['usage'] = data['usage']
        for choice in data.get('choices', []):
            reason = choice.get('finish_reason')
            if reason:
                record['finish_reasons'].append(reason)
                if reason not in ('stop', 'tool_calls'):
                    raise ValueError('unfinished provider response')

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.key = ''

    @property
    def url(self):
        return 'http://127.0.0.1:' + str(self.server.server_port) + '/v1'
