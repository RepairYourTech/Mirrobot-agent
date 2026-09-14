"""Restart unavailable inference sessions without resetting their execution budget."""
import time

from ryt.common import load_json, read_text, write_json
from ryt.diagnostics import public_failure_code


def execute_with_pool(execute, binary, data, root, pool, count_tokens, policy, timeout_seconds):
    started = time.monotonic()
    deadline = started + timeout_seconds
    attempts = []
    used_calls = 0
    used_tools = 0
    for index in range(len(pool.routes)):
        remaining = int(deadline - time.monotonic())
        if remaining < 30 or used_calls >= 64 or used_tools >= 384:
            raise ValueError('inference failover budget exhausted')
        route = pool.next()
        session = root / f'attempt-{index + 1}'
        session.mkdir(mode=0o700)
        attempt_started = time.monotonic()
        try:
            result, telemetry = execute(binary, data, session, route.key, count_tokens, policy, remaining,
                profile_id=route.profile, max_calls=64 - used_calls, max_tools=384 - used_tools)
        except Exception:
            progress_path = session / 'progress.json'
            progress = load_json(read_text(progress_path)) if progress_path.exists() else {}
            code = public_failure_code(progress.get('failure_code'))
            requests = progress.get('provider_requests', [])
            used_calls += len(requests)
            tools = progress.get('tool_events', [])
            used_tools += len(tools)
            retryable = pool.fail(route, code)
            # Preserve the cause independently of whether the route can retry.
            # Arbitrary progress values and exception messages stay private.
            attempts.append({'route': route.alias, 'profile': route.profile, 'status': 'failed',
                'failure_code': code, 'retryable': retryable,
                'request_count': len(requests), 'tool_count': len(tools),
                'elapsed_seconds': round(time.monotonic() - attempt_started, 3)})
            write_json(root / 'progress.json', {'failure_code': attempts[-1]['failure_code'],
                'attempts': attempts, 'provider_requests': requests, 'tool_events': tools})
            if not retryable:
                raise
            continue
        used_calls += len(telemetry['provider_requests'])
        used_tools += len(telemetry['tool_events'])
        attempts.append({'route': route.alias, 'profile': route.profile, 'status': 'complete',
            'request_count': len(telemetry['provider_requests']),
            'tool_count': len(telemetry['tool_events']),
            'elapsed_seconds': round(time.monotonic() - attempt_started, 3)})
        telemetry.update(route=route.alias, profile=route.profile, attempts=attempts,
            pool_budget_seconds=timeout_seconds, pool_elapsed_seconds=round(time.monotonic() - started, 3),
            pool_request_count=used_calls, pool_tool_count=used_tools)
        return result, telemetry
    raise ValueError('all configured inference routes unavailable')
