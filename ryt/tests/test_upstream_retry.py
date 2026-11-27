"""A transient upstream refusal is retried on the same route before the engine sees anything.

Issue RepairYourTech/RepairYourTech#2710: one z.ai HTTP 429 terminated the OpenCode session and
retired the GLM route for the rest of the review, so every later chunk went to a fallback that
could not answer. These tests pin the bounded same-route retry and the per-chunk rotation.
"""
import email.utils
import http.client
import io
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch

from ryt.bridge import ProviderBridge
from ryt.common import write_json
from ryt.failover import execute_with_pool
from ryt.providers import ProviderPool, routes
from ryt import upstream


class Stream(io.BytesIO):
    headers = {'Content-Type': 'text/event-stream'}


def refusal(status, body=b'', headers=None):
    return urllib.error.HTTPError('https://upstream.invalid', status, 'refused',
                                  dict(headers or {}), io.BytesIO(body))


def scripted(responses):
    """open_provider stand-in: raise a scripted refusal, or return a scripted stream."""
    def open_provider(request, timeout):
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item
    return open_provider


def completion(model='glm-5.3-flash'):
    return Stream(('data: ' + json.dumps({'model': model, 'choices': [{'index': 0,
        'delta': {'role': 'assistant', 'content': 'ok'}, 'finish_reason': 'stop'}]}) +
        '\n\ndata: [DONE]\n\n').encode())


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=10)
        self.unix_path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(str(self.unix_path))


def post(bridge):
    connection = UnixHTTPConnection(bridge.socket_path)
    body = json.dumps({'model': 'glm-5.3-flash', 'stream': True,
                       'messages': [{'role': 'user', 'content': 'review'}]})
    connection.request('POST', '/v1/chat/completions', body=body, headers={
        'Authorization': 'Bearer ' + bridge.token, 'Content-Type': 'application/json'})
    response = connection.getresponse()
    try:
        return response.status, response.read()
    finally:
        connection.close()


class SameRouteRetry(unittest.TestCase):
    def test_glm_429_is_retried_inside_the_bridge_and_the_session_survives(self):
        zai_overload = json.dumps({'error': {'code': '1305', 'message': 'PRIVATE provider prose'}}).encode()
        responses = [refusal(429, zai_overload, {'Retry-After': '7'}), refusal(503), completion()]
        waits = []
        with ProviderBridge('synthetic', lambda text: 100) as bridge, \
                patch('ryt.bridge.open_provider', side_effect=scripted(responses)), \
                patch.object(bridge, 'wait', side_effect=lambda seconds: waits.append(seconds) or False):
            status, body = post(bridge)
            self.assertEqual(status, 200)
            self.assertIn(b'"finish_reason": "stop"', body)
            self.assertFalse(bridge.failed.is_set())
            self.assertEqual(len(bridge.records), 1)
            record = bridge.records[0]
        self.assertEqual(record['finish_reasons'], ['stop'])
        self.assertEqual(waits[0], 7.0)
        self.assertEqual(len(waits), 2)
        self.assertLessEqual(waits[1], upstream.MAX_DELAY)
        self.assertEqual([(r['status'], r.get('code')) for r in record['upstream_retries']],
                         [(429, '1305'), (503, None)])
        self.assertNotIn('PRIVATE', json.dumps(record))

    def test_exhausted_retries_fail_with_the_public_status_and_provider_code_only(self):
        body = json.dumps({'error': {'code': 'invalid_parameter', 'param': 'messages[0].role',
                                     'type': 'invalid_request_error', 'message': 'PRIVATE'}}).encode()
        attempts = []
        def refuse(request, timeout):
            attempts.append(request)
            raise refusal(429, b'{"error":{"code":"1302"}}')
        with ProviderBridge('synthetic', lambda text: 100) as bridge, \
                patch('ryt.bridge.open_provider', side_effect=refuse), \
                patch.object(bridge, 'wait', return_value=False):
            status, _ = post(bridge)
            self.assertEqual(status, 502)
            self.assertEqual(bridge.error, 'HTTP_429')
            self.assertEqual(len(attempts), upstream.MAX_ATTEMPTS)
            self.assertEqual(len(bridge.records), 1)
            self.assertEqual(bridge.records[0]['upstream_errors'], [{'status': 429, 'code': '1302'}])
        with ProviderBridge('synthetic', lambda text: 100) as bridge, \
                patch('ryt.bridge.open_provider', side_effect=scripted([refusal(400, body)])), \
                patch.object(bridge, 'wait', return_value=False):
            connection_body = json.dumps({'model': 'glm-5.3-flash', 'stream': True, 'messages': []})
            connection = UnixHTTPConnection(bridge.socket_path)
            connection.request('POST', '/v1/chat/completions', body=connection_body,
                               headers={'Authorization': 'Bearer ' + bridge.token})
            self.assertEqual(connection.getresponse().status, 502)
            connection.close()
            # A 400 is not transient: one attempt, and its typed fields become diagnosable.
            self.assertEqual(bridge.error, 'HTTP_400')
            self.assertEqual(bridge.records[0]['upstream_errors'], [{'status': 400, 'code': 'invalid_parameter',
                'param': 'messages[0].role', 'type': 'invalid_request_error'}])
            self.assertNotIn('PRIVATE', json.dumps(bridge.records))

    def test_closing_the_bridge_stops_a_pending_backoff(self):
        with ProviderBridge('synthetic', lambda text: 100) as bridge:
            started = time.monotonic()
            bridge.closing.set()
            self.assertTrue(bridge.wait(30))
            self.assertLess(time.monotonic() - started, 1)

    def test_retry_after_is_honoured_bounded_and_untrusted_fields_are_dropped(self):
        later = email.utils.formatdate(time.time() + 9, usegmt=True)
        self.assertAlmostEqual(upstream.retry_after({'Retry-After': later}), 9, delta=2)
        self.assertEqual(upstream.retry_after({'Retry-After': '100000'}), upstream.MAX_RETRY_AFTER)
        for value in ['', 'soon', '-4', 'nan']:
            self.assertIsNone(upstream.retry_after({'Retry-After': value}))
        self.assertEqual(upstream.provider_error(refusal(429, b'{"error":{"code":1305,"param":"a b<c"}}')),
                         {'code': '1305'})
        self.assertEqual(upstream.provider_error(refusal(500, b'not json')), {})
        self.assertEqual(upstream.provider_error(refusal(500, b'{"code":"x"}' + b' ' * 9000)), {})


class StalledBody(io.RawIOBase):
    """An error body whose read blocks until released, like a provider that stalls after the status."""
    def __init__(self):
        import threading
        self.released = threading.Event()

    def readable(self):
        return True

    def readinto(self, buffer):
        self.released.wait(30)
        return 0


class ErrorBodyBounds(unittest.TestCase):
    def test_a_stalled_error_body_cannot_hold_the_retry_or_the_failure_signal(self):
        body = StalledBody()
        error = urllib.error.HTTPError('https://upstream.invalid', 429, 'refused', {}, body)
        try:
            with patch.object(upstream, 'ERROR_BODY_SECONDS', 0.2):
                started = time.monotonic()
                self.assertEqual(upstream.provider_error(error), {})
                self.assertLess(time.monotonic() - started, 2)
        finally:
            body.released.set()

    def test_a_parser_recursion_failure_keeps_the_http_status(self):
        # Within the 8 KiB bound CPython's scanner does not recurse that deep today; the guard
        # keeps a parser limit from turning HTTP_429 into transport_RecursionError (no failover).
        record = {}
        with patch.object(upstream.json, 'loads', side_effect=RecursionError), \
                self.assertRaises(urllib.error.HTTPError) as raised:
            upstream.open_with_retry(lambda: (_ for _ in ()).throw(refusal(400, b'{"error":{"code":"x"}}')),
                                     record, lambda seconds: False)
        self.assertEqual(raised.exception.code, 400)
        self.assertEqual(record['upstream_errors'], [{'status': 400}])


class PerChunkRotation(unittest.TestCase):
    def test_rate_limit_skips_only_the_current_chunk_but_an_outage_retires_glm(self):
        pool = ProviderPool(routes({'OPENAI_KEY': 'glm'}))
        first = pool.next()
        self.assertEqual(first.alias, 'zai-01')
        self.assertTrue(pool.fail(first, 'HTTP_429'))
        with self.assertRaises(ValueError):
            pool.next(exclude={'zai-01'})
        # The next chunk starts on GLM again: a rate limit is not an outage.
        self.assertEqual(pool.next().alias, 'zai-01')
        self.assertTrue(pool.fail(first, 'HTTP_503'))
        with self.assertRaises(ValueError):
            pool.next()
        self.assertEqual(pool.audit(), [{'route': 'zai-01', 'failure_code': 'HTTP_429'},
            {'route': 'zai-01', 'failure_code': 'HTTP_503'}])

    def test_one_chunk_never_repeats_a_route_the_bridge_already_retried(self):
        pool = ProviderPool(routes({'OPENAI_KEY': 'glm'}))
        sessions = []
        def execute(binary, data, session, key, *args, **options):
            sessions.append(key)
            write_json(session / 'progress.json', {'failure_code': 'HTTP_429',
                'provider_requests': [{'upstream_errors': [{'status': 429}]}], 'tool_events': []})
            raise ValueError('rate limited')
        for _ in range(2):
            with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError) as raised:
                execute_with_pool(execute, None, None, Path(temp), pool, len, '', 600)
            self.assertIn('unavailable', str(raised.exception))
        # One GLM session per chunk, and the second chunk was still offered GLM.
        self.assertEqual(sessions, ['glm', 'glm'])


if __name__ == '__main__':
    unittest.main()
