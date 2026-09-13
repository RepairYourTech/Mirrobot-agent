"""Public-safe failure codes. Never turn arbitrary exception text into telemetry."""
import urllib.error

CODES = frozenset({
    'request_size', 'output_limit', 'context_limit', 'call_limit',
    'response_size', 'missing_terminal', 'stream_json', 'stream_error',
    'reported_model', 'finish_length', 'finish_filter', 'finish_other', 'provider_redirect', 'unexpected_thinking',
})


class BridgeFailure(ValueError):
    def __init__(self, code):
        if code not in CODES:
            raise ValueError('unknown diagnostic code')
        self.code = code
        super().__init__(code)


def safe_failure(error):
    if isinstance(error, BridgeFailure):
        return error.code
    if isinstance(error, urllib.error.HTTPError):
        return 'HTTP_' + str(error.code)
    if isinstance(error, (TimeoutError, ConnectionError)):
        return type(error).__name__
    return 'transport_' + type(error).__name__
