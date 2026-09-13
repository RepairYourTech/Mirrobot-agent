"""Trusted inference profiles and a bounded per-review credential pool."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Profile:
    provider: str
    model: str
    endpoint: str
    reasoning_effort: str
    thinking_enabled: bool


PROFILES = {
    'zai': Profile('zai', 'glm-5.3-flash', 'https://api.z.ai/api/coding/paas/v4/chat/completions', 'max', True),
    'bai-qwen': Profile('bai', 'qwen3.8-flash', 'https://api.b.ai/v1/chat/completions', 'none', False),
}
RETRYABLE = frozenset({'HTTP_429', 'HTTP_500', 'HTTP_502', 'HTTP_503', 'HTTP_504',
                       'TimeoutError', 'ConnectionError', 'transport_URLError', 'provider_token_rate_limit'})


def profile(name):
    if name not in PROFILES:
        raise ValueError('unapproved inference profile')
    return PROFILES[name]


@dataclass(frozen=True)
class Route:
    alias: str
    profile: str
    key: str = field(repr=False)


def routes(environment):
    names = [('OPENAI_KEY', 'zai-01', 'zai')] + [
        (f'PR_REVIEW_BAI_{index:02d}', f'bai-{index:02d}', 'bai-qwen') for index in range(1, 4)]
    result = []
    seen = set()
    for variable, alias, selected in names:
        key = environment.get(variable, '')
        if not isinstance(key, str) or key.strip() != key:
            raise ValueError('invalid inference credential configuration')
        if key and key not in seen:
            result.append(Route(alias, selected, key))
            seen.add(key)
    if not result:
        raise ValueError('no inference credentials configured')
    return result


class ProviderPool:
    """A failing route is retired for this review, never retried for every chunk."""
    def __init__(self, configured):
        self.routes = tuple(configured)
        self.failures = []
        self.disabled = set()

    def next(self):
        for route in self.routes:
            if route.alias not in self.disabled:
                return route
        raise ValueError('all configured inference routes unavailable')

    def fail(self, route, code):
        if route not in self.routes or code not in RETRYABLE:
            return False
        if route.alias not in self.disabled:
            self.disabled.add(route.alias)
            self.failures.append({'route': route.alias, 'failure_code': code})
        return True

    def audit(self):
        return [dict(failure) for failure in self.failures]
