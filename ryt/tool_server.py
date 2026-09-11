"""Minimal stdio MCP: snapshot data and sandboxed probes, never GitHub or host access."""
import json
from pathlib import Path
import sys
from ryt.common import confined, load_json, read_text, sha256, write_json
from ryt.probe import run_probe

PAGE_LINES = 240
PAGE_BYTES = 8000
OUTPUT_BYTES = 32768


def integer(value, minimum=0, maximum=10000000):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('integer outside allowed range')
    return value


def schema(properties, required=()):
    return {'type': 'object', 'properties': properties, 'required': list(required), 'additionalProperties': False}

S = {'type': 'string'}
I = {'type': 'integer', 'minimum': 0}
TOOLS = [
 {'name': 'review_context', 'description': 'Get mandatory changed-file list, prior bot findings and untrusted PR context.',
  'inputSchema': schema({})},
 {'name': 'read_context', 'description': 'Read paginated PR description, linked requirements, trusted repo guidance or prior findings as data. Follow next_offset for the complete section.',
  'inputSchema': schema({'section': S, 'offset': I, 'path': S, 'ordinal': I}, ['section'])},
 {'name': 'read_diff', 'description': 'Revisit a page of an assigned file diff when useful. The full diff was already delivered in the verified initial packet; redundant rereading is not required.',
  'inputSchema': schema({'path': S, 'offset': I}, ['path'])},
 {'name': 'list_files', 'description': 'Browse the immutable head repository snapshot; follow pagination.',
  'inputSchema': schema({'prefix': S, 'offset': I})},
 {'name': 'read_file', 'description': 'Read source outside the diff or surrounding callers/tests. Paths are relative to the read-only snapshot; head or base.',
  'inputSchema': schema({'path': S, 'offset': I, 'revision': {'type': 'string', 'enum': ['head', 'base']}}, ['path'])},
 {'name': 'search', 'description': 'Literal source search across head snapshot. Returns paginated line matches; no regex execution.',
  'inputSchema': schema({'query': S, 'prefix': S, 'offset': I}, ['query'])},
 {'name': 'run_probe', 'description': 'Run a bounded Python/JavaScript scratch probe with read-only /repo, NO NETWORK or credentials. No dependencies installed. Exit1 may demonstrate a bug; do not call a failed probe a passed test.',
  'inputSchema': schema({'language': {'type': 'string', 'enum': ['python', 'javascript']}, 'code': S}, ['language', 'code'])},
 {'name': 'submit_review', 'description': 'Submit the completed review once all assigned files are analyzed. Complete initial diff delivery counts; do not reread every diff just for accounting. Use exactly the declared fields. GitHub publication occurs outside the agent.',
  'inputSchema': schema({'files': {'type': 'array', 'minItems': 1,
       'items': schema({'path': S, 'analysis': {'type': 'string', 'minLength': 10}}, ['path', 'analysis'])},
    'review': schema({
       'key_issues_to_review': {'type': 'array', 'items': schema({
          'relevant_file': S, 'issue_header': {'type': 'string', 'minLength': 1},
          'issue_content': {'type': 'string', 'minLength': 1},
          'start_line': {'type': 'integer', 'minimum': 1}, 'end_line': {'type': 'integer', 'minimum': 1}},
          ['relevant_file', 'issue_header', 'issue_content', 'start_line', 'end_line'])},
       'security_concerns': {'type': 'string', 'minLength': 1},
       'risk_level': {'type': 'string', 'minLength': 1},
       'merge_recommendation': {'type': 'string', 'minLength': 1},
       'relevant_tests': S, 'estimated_effort_to_review_[1-5]': {'type': 'integer', 'minimum': 1, 'maximum': 5}},
       ['key_issues_to_review', 'security_concerns', 'risk_level', 'merge_recommendation'])},
    ['files', 'review'])},
]


class RepositoryTools:
    def __init__(self, data, output):
        self.data = Path(data)
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.context = load_json(read_text(self.data / 'context.json', 4 * 1024 * 1024))
        self.diffs = load_json(read_text(self.data / 'diffs.json', 16 * 1024 * 1024))
        self.coverage = {name: set() for name in self.diffs}
        self.events = []
        self.fatal = False
        self.submitted = False

    def page(self, text, offset):
        lines = text.splitlines(keepends=True)
        integer(offset, maximum=len(lines))
        selected, size = [], 0
        for line in lines[offset:offset + PAGE_LINES]:
            size += len(json.dumps(line, ensure_ascii=False).encode())
            if size > PAGE_BYTES:
                if not selected:
                    raise ValueError('single line exceeds inspection budget')
                break
            selected.append(line)
        end = offset + len(selected)
        return {'text': ''.join(selected), 'offset': offset, 'end': end, 'total_lines': len(lines),
                'next_offset': end if end < len(lines) else None, 'sha256': sha256(text)}

    def available(self, prefix=''):
        if prefix:
            confined(self.data / 'head', prefix.rstrip('/'))
        return [p for p in sorted(self.context['snapshot_files']) if p.startswith(prefix)]

    def execute(self, name, args):
        if len(self.events) >= 384:
            raise ValueError('tool-call limit exceeded')
        if self.submitted:
            raise ValueError('review already finalized')
        if name == 'review_context':
            keys = ('head', 'base', 'required_files', 'review_type', 'history_limited', 'snapshot_unavailable')
            result = {key: self.context[key] for key in keys if key in self.context}
            result['context_sections'] = list(self.context.get('sections', {}))
            return result
        if name == 'read_context':
            section = args['section']
            if section not in self.context.get('sections', {}):
                raise ValueError('unknown context section')
            value = self.context['sections'][section]
            if 'ordinal' in args:
                if section != 'prior_findings' or not isinstance(value, list) or 'path' in args:
                    raise ValueError('ordinal selects one prior finding without a path filter')
                ordinal = integer(args['ordinal'], maximum=len(value)-1)
                finding = value[ordinal]
                return {**{k: v for k, v in finding.items() if k != 'body'}, 'section': section,
                        'ordinal': ordinal, **self.page(finding['body'], args.get('offset', 0))}
            if 'path' in args:
                if section != 'prior_findings' or not isinstance(value, list):
                    raise ValueError('path filter applies only to prior findings')
                confined(self.data / 'head', args['path'])
                value = [finding for finding in value if finding.get('path') == args['path']]
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, indent=2)
            return {'section': section, **self.page(text, args.get('offset', 0))}
        if name == 'read_diff':
            path = args['path']; offset = args.get('offset', 0)
            if path not in self.diffs:
                raise ValueError('file is not in this required diff chunk')
            page = self.page(self.diffs[path], offset)
            return {'path': path, **page}
        if name == 'list_files':
            paths = self.available(args.get('prefix', ''))
            offset = integer(args.get('offset', 0), maximum=len(paths))
            return {'files': paths[offset:offset+20], 'total': len(paths),
                    'next_offset': offset + 20 if offset + 20 < len(paths) else None}
        if name == 'read_file':
            revision = args.get('revision', 'head')
            if revision not in ('head', 'base'):
                raise ValueError('unknown snapshot revision')
            path = confined(self.data / revision, args['path'])
            return {'path': args['path'], 'revision': revision, **self.page(read_text(path), args.get('offset', 0))}
        if name == 'search':
            query = args['query']
            if not isinstance(query, str) or not query or len(query) > 512:
                raise ValueError('invalid literal search')
            matches = []
            for path in self.available(args.get('prefix', '')):
                try:
                    text = read_text(confined(self.data / 'head', path))
                except (ValueError, UnicodeDecodeError):
                    continue
                for line, content in enumerate(text.splitlines(), 1):
                    if query in content:
                        matches.append({'path': path, 'line': line, 'excerpt': content[:300]})
                        if len(matches) >= 5000:
                            break
                if len(matches) >= 5000:
                    break
            offset = integer(args.get('offset', 0), maximum=len(matches))
            return {'matches': matches[offset:offset+20], 'matches_collected': len(matches),
                    'truncated': len(matches) >= 5000,
                    'next_offset': offset+20 if offset+20 < len(matches) else None}
        if name == 'run_probe':
            result = run_probe(args['language'], args['code'], self.data / 'head')
            if result['exit_code'] == 'timeout':
                self.fatal = True
            return result
        if name == 'submit_review':
            return self.submit(args)
        raise ValueError('unregistered tool')

    def submit(self, args):
        if self.fatal:
            raise ValueError('a fatal inspection/probe failure prevents completion')
        prefill_path = self.output / 'prefill.json'
        if prefill_path.exists():
            receipts = load_json(read_text(prefill_path))
            for path, text in self.diffs.items():
                receipt = receipts.get(path)
                if receipt is not None:
                    if receipt != {'sha256': sha256(text), 'lines': len(text.splitlines())}:
                        raise ValueError('trusted input receipt mismatch')
                    self.coverage[path].update(range(receipt['lines']))
        missing = {p: len(t.splitlines())-len(self.coverage[p]) for p, t in self.diffs.items()
                   if len(t.splitlines()) != len(self.coverage[p])}
        if missing:
            raise ValueError('undelivered diff pages: ' + json.dumps(missing))
        files = args['files']
        if (not isinstance(files, list) or sorted(x.get('path', '') for x in files) != sorted(self.diffs) or
                any(not isinstance(x.get('analysis'), str) or len(x['analysis'].strip()) < 10 for x in files)):
            raise ValueError('each required file needs exactly one substantive disposition')
        review = args['review']
        findings = review.get('key_issues_to_review') if isinstance(review, dict) else None
        if not isinstance(findings, list):
            raise ValueError('missing structured findings array')
        for issue in findings:
            if issue.get('relevant_file') not in self.diffs:
                raise ValueError('finding must anchor to a changed file in this chunk')
            for key in ('issue_header', 'issue_content'):
                if not isinstance(issue.get(key), str) or not issue[key].strip():
                    raise ValueError('finding header/explanation required')
            start = integer(issue.get('start_line'), 1)
            integer(issue.get('end_line'), start)
        for key in ('security_concerns', 'risk_level', 'merge_recommendation'):
            if not isinstance(review.get(key), str) or not review[key].strip():
                raise ValueError('missing required review section')
        record = {'schema': 1, 'review': review, 'files': files,
                  'coverage': {p: {'sha256': sha256(t), 'lines': len(t.splitlines()),
                                    'delivered_lines': len(self.coverage[p])} for p, t in self.diffs.items()}}
        write_json(self.output / 'result.json', record)
        self.submitted = True
        return {'accepted': True, 'files': len(files), 'findings': len(findings),
                'notice': 'Finish the session; trusted publisher still must verify current head/base and GitHub readback.'}

    def call(self, name, args):
        spec = next((tool['inputSchema'] for tool in TOOLS if tool['name'] == name), None)
        if (spec is None or not isinstance(args, dict) or set(args)-set(spec['properties']) or
                set(spec['required'])-set(args)):
            raise ValueError('invalid tool arguments')
        event = {'tool': name, 'arguments_sha256': sha256(json.dumps(args, sort_keys=True)),
                 'path': args.get('path'), 'status': 'failed'}
        self.events.append(event)
        try:
            result = self.execute(name, args)
            if len(json.dumps(result, ensure_ascii=False).encode()) > OUTPUT_BYTES:
                raise ValueError('tool output exceeds transport budget; narrow the request')
            if name == 'read_diff':
                self.coverage[args['path']].update(range(result['offset'], result['end']))
            event.update(status='success', output_sha256=sha256(json.dumps(result, sort_keys=True)),
                         offset=result.get('offset'), end=result.get('end'))
            return result
        except (ValueError, FileNotFoundError, UnicodeDecodeError):
            raise
        except Exception:
            self.fatal = True
            raise
        finally:
            write_json(self.output / 'tools.json', self.events)



def main():
    tools = RepositoryTools(sys.argv[1], sys.argv[2])
    for line in sys.stdin:
        if len(line) > 1024 * 1024:
            raise ValueError('MCP input budget exceeded')
        request = load_json(line)
        identifier = request.get('id')
        if identifier is None:
            continue
        try:
            method = request['method']
            if method == 'initialize':
                result = {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'ryt-mirrobot-inspection', 'version': '1.0'}}
            elif method == 'tools/list':
                result = {'tools': TOOLS}
            elif method == 'ping':
                result = {}
            elif method == 'tools/call':
                params = request['params']
                try:
                    value = tools.call(params['name'], params.get('arguments', {}))
                    result = {'content': [{'type': 'text', 'text': json.dumps(value, ensure_ascii=False)}]}
                except (KeyError, ValueError, OSError) as error:
                    result = {'isError': True, 'content': [{'type': 'text', 'text': str(error)[:800]}]}
            else:
                raise ValueError('unsupported MCP method')
            response = {'jsonrpc': '2.0', 'id': identifier, 'result': result}
        except Exception:
            response = {'jsonrpc': '2.0', 'id': identifier, 'error': {'code': -32602, 'message': 'invalid request'}}
        print(json.dumps(response), flush=True)


if __name__ == '__main__':
    main()
