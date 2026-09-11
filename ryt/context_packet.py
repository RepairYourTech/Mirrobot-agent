"""Keep complete diffs in context and full prior bodies navigable, not duplicated.

This is initial input selection, not compaction of an existing conversation.
No previous review body is removed from the immutable tool-side context.
"""
from ryt.common import sha256


def initial_packet(context, diffs):
    visible = {key: value for key, value in context.items() if key != 'snapshot_files'}
    sections = dict(visible.get('sections', {}))
    history = sections.get('prior_findings', [])
    if not isinstance(history, list):
        raise ValueError('prior finding history must be a list')
    index = []
    for ordinal, finding in enumerate(history):
        if not isinstance(finding, dict) or not isinstance(finding.get('body'), str):
            raise ValueError('invalid prior finding record')
        index.append({**{key: value for key, value in finding.items() if key != 'body'},
                      'ordinal': ordinal, 'body_sha256': sha256(finding['body']),
                      'body_bytes': len(finding['body'].encode())})
    sections['prior_findings'] = {
        'delivery': 'index-only; complete bodies remain in read_context',
        'read_tool': 'ryt_read_context', 'section': 'prior_findings',
        'filter': 'optional path selects an exact file; ordinal reads one indexed body as paginated text',
        'records': index,
    }
    visible['sections'] = sections
    return {'context': visible, 'diffs': dict(diffs)}
