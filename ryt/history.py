"""Authenticated GitHub Actions history; GraphQL and REST spell bot logins differently."""
ACTIONS_BOT_DATABASE_ID = 41898282


def review_history(threads):
    limited = bool(threads['pageInfo']['hasPreviousPage'])
    histories = []
    for thread in threads['nodes']:
        limited |= bool(thread['comments']['pageInfo']['hasPreviousPage'])
        for comment in thread['comments']['nodes']:
            author = comment.get('author') or {}
            # Identity is a server-provided Bot database ID, not a name in PR text.
            if (author.get('__typename') != 'Bot' or author.get('databaseId') != ACTIONS_BOT_DATABASE_ID
                    or comment['isMinimized']):
                continue
            body = comment['body']
            histories.append({'path': thread['path'], 'line': thread['line'],
                'resolved': thread['isResolved'], 'outdated': thread['isOutdated'],
                'commit': (comment.get('originalCommit') or {}).get('oid'), 'body': body[:8000]})
            limited |= len(body) > 8000
    limited |= len(histories) > 100
    return histories[-100:], limited
