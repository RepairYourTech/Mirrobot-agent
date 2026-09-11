"""Complete-file planning with exploration headroom, before any inference call."""
from ryt.common import sha256

MAX_SESSIONS = 6
MAX_FILES = 4
DIFF_TARGET_TOKENS = 8192
INITIAL_INPUT_LIMIT = 49152


def token_count(value):
    if type(value) is not int or value < 0:
        raise ValueError('invalid token counter result')
    return value


def plan_sessions(chunks, count_tokens, estimate_initial):
    fragments=[item for group in chunks for item in group]
    if not fragments or any(not isinstance(p,str) or not p or not isinstance(t,str) or not t.strip()
                            for p,t in fragments):
        raise ValueError('empty or malformed review fragment')
    if len({p for p,_ in fragments}) != len(fragments):
        raise ValueError('duplicate review path')
    planned=[];current=[]
    for item in fragments:
        if token_count(estimate_initial([item])) > INITIAL_INPUT_LIMIT:
            raise ValueError('single file exceeds initial context allocation; split PR required')
        candidate=current+[item]
        diff_tokens=token_count(count_tokens('\n'.join(t for _,t in candidate)))
        too_large=(len(candidate)>MAX_FILES or diff_tokens>DIFF_TARGET_TOKENS or
                   token_count(estimate_initial(candidate))>INITIAL_INPUT_LIMIT)
        if current and too_large:
            planned.append(current);current=[]
        current.append(item)
    if current:planned.append(current)
    if len(planned)>MAX_SESSIONS:
        raise ValueError('review exceeds six-session safety limit; split PR required')
    # Preserve every old/new hunk byte, order and path; no model-driven exclusions.
    if [item for group in planned for item in group] != fragments:
        raise ValueError('planned review input changed')
    sessions=[{'index':i+1,'files':[p for p,_ in group],
               'input_sha':sha256('\n'.join(t for _,t in group)),
               'diff_tokens':token_count(count_tokens('\n'.join(t for _,t in group))),
               'estimated_initial_tokens':token_count(estimate_initial(group))}
              for i,group in enumerate(planned)]
    return planned, {'schema':1,'input_files':len(fragments),'max_sessions':MAX_SESSIONS,
                     'max_files_per_session':MAX_FILES,'diff_target_tokens':DIFF_TARGET_TOKENS,
                     'initial_input_limit':INITIAL_INPUT_LIMIT,'sessions':sessions}
