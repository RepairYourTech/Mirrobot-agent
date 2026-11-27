"""Bounded same-route retry for transient upstream refusals.

A refusal arrives before any byte reaches the engine, so the identical request can be resent
without the engine observing a partial stream. Only typed, charset-checked provider fields are
kept; provider prose never enters evidence.
"""
import email.utils
import json
import math
import random
import re
import time
import urllib.error

TRANSIENT_STATUS = frozenset({429, 500, 502, 503, 504})
MAX_ATTEMPTS = 6           # the first request plus five retries
BASE_DELAY = 4.0           # seconds; doubles per retry: 4, 8, 16, 32, 60
MAX_DELAY = 60.0           # ceiling for a computed backoff
MAX_RETRY_AFTER = 120.0    # ceiling for a provider-supplied Retry-After
MAX_TOTAL_WAIT = 240.0     # one request never waits longer than this across all retries
ERROR_BODY_LIMIT = 8192
FIELD = re.compile(r'[A-Za-z0-9_.:\[\]-]{1,64}')
FIELDS = ('code', 'param', 'type')


def retry_after(headers):
    value = (headers or {}).get('Retry-After')
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if re.fullmatch(r'[0-9]{1,9}', value):
        seconds = float(value)
    else:
        try:
            parsed = email.utils.parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
        if parsed is None or parsed.tzinfo is None:
            return None
        seconds = parsed.timestamp() - time.time()
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return min(seconds, MAX_RETRY_AFTER)


def provider_error(error):
    """Typed fields of an OpenAI-compatible error body, never its message."""
    try:
        raw = error.read(ERROR_BODY_LIMIT + 1)
    except Exception:
        return {}
    if not raw or len(raw) > ERROR_BODY_LIMIT:
        return {}
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}
    body = data.get('error') if isinstance(data.get('error'), dict) else data
    result = {}
    for name in FIELDS:
        value = body.get(name)
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        value = str(value)
        if FIELD.fullmatch(value):
            result[name] = value
    return result


def backoff(attempt, jitter=random.random):
    """Full-jitter exponential delay for the retry after `attempt` (1-based)."""
    ceiling = min(MAX_DELAY, BASE_DELAY * 2 ** (attempt - 1))
    return ceiling * (0.5 + jitter() / 2)


def open_with_retry(open_once, record, wait, jitter=random.random):
    """Open the upstream stream, resending the same request after a transient refusal.

    `wait(seconds)` returns True when the bridge is closing, which abandons the retry.
    """
    waited = 0.0
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return open_once()
        except urllib.error.HTTPError as error:
            entry = {'status': error.code, **provider_error(error)}
            error.close()
            delay = retry_after(error.headers)
            if delay is None:
                delay = backoff(attempt, jitter)
            if (error.code not in TRANSIENT_STATUS or attempt == MAX_ATTEMPTS or
                    waited + delay > MAX_TOTAL_WAIT):
                record.setdefault('upstream_errors', []).append(entry)
                raise
            entry['wait_seconds'] = round(delay, 3)
            record.setdefault('upstream_retries', []).append(entry)
            if wait(delay):
                raise
            waited += delay
    raise AssertionError('unreachable')
