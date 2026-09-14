"""Public-safe failure codes. Never turn arbitrary exception text into telemetry."""
import builtins
import re
import urllib.error

CODES = frozenset({
    'request_size', 'output_limit', 'context_limit', 'call_limit',
    'response_size', 'missing_terminal', 'stream_json', 'stream_error',
    'reported_model', 'finish_length', 'finish_filter', 'finish_other', 'provider_redirect', 'unexpected_thinking',
    'provider_token_rate_limit',
    'route_retired',
})

SESSION_CODES = frozenset({
    'session_timeout', 'engine_output_limit', 'engine_process_failed',
    'engine_tool_not_allowed', 'engine_error_event', 'engine_missing_stop',
    'provider_missing_completion', 'missing_submission', 'tool_delivery_mismatch',
    'initial_coverage_missing', 'reported_coverage_mismatch',
})


class SessionFailure(ValueError):
    def __init__(self, code):
        if code not in SESSION_CODES:
            raise ValueError('unknown session diagnostic code')
        self.code = code
        super().__init__(code)


class BridgeFailure(ValueError):
    def __init__(self, code):
        if code not in CODES:
            raise ValueError('unknown diagnostic code')
        self.code = code
        super().__init__(code)


def public_failure_code(code):
    if not isinstance(code, str):
        return 'non_retryable_session_failure'
    if code in CODES | SESSION_CODES | {'TimeoutError', 'ConnectionError', 'transport_URLError'}:
        return code
    if re.fullmatch(r'HTTP_[1-5][0-9]{2}', code):
        return code
    if code.startswith('transport_'):
        exception_type = getattr(builtins, code[len('transport_'):], None)
        if isinstance(exception_type, type) and issubclass(exception_type, Exception):
            return code
    return 'non_retryable_session_failure'


def safe_failure(error):
    if isinstance(error, (BridgeFailure, SessionFailure)):
        return error.code
    if isinstance(error, urllib.error.HTTPError):
        return 'HTTP_' + str(error.code)
    if isinstance(error, (TimeoutError, ConnectionError)):
        return type(error).__name__
    return 'transport_' + type(error).__name__
