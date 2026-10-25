"""Choose one consistent attribute assignment for the existing privileged bypass.

TKN20 represents attributes as a map, so AC17's union of positive tokens is not
valid for it. This helper does not authorize callers or modify stored attributes.
"""
import ast
import re


_TOKEN = re.compile(r'[A-Za-z0-9_.-]+:[A-Za-z0-9_.@/-]+|and\b|or\b|not\b|[()]', re.IGNORECASE)


def bypass_attributes(user_attributes, policies):
    tokens = {}
    expressions = []
    for policy in policies:
        if not policy:
            continue
        if len(policy) > 4096:
            raise ValueError('TKN20 bypass policy is too complex.')
        expression = []
        offset = 0
        for match in _TOKEN.finditer(policy):
            if policy[offset:match.start()].strip():
                raise ValueError('Unsupported TKN20 bypass policy syntax.')
            token = match.group().lower()
            if ':' in token:
                name = f'a{len(tokens)}'
                tokens[name] = tuple(token.split(':', 1))
                expression.append(name)
            else:
                expression.append(token)
            offset = match.end()
        if policy[offset:].strip():
            raise ValueError('Unsupported TKN20 bypass policy syntax.')
        expressions.append('(' + ' '.join(expression) + ')')
    if not expressions:
        raise ValueError('Missing TKN20 bypass policy.')
    tree = ast.parse(' or '.join(expressions), mode='eval')
    steps = 0

    def satisfy(node, chosen, excluded, negated=False):
        nonlocal steps
        steps += 1
        if steps > 4096:
            raise ValueError('TKN20 bypass policy is too complex.')
        if isinstance(node, ast.Name) and node.id in tokens:
            key, value = tokens[node.id]
            if negated:
                if chosen.get(key) != value:
                    yield chosen, {**excluded, key: excluded.get(key, set()) | {value}}
            elif value not in excluded.get(key, set()) and (key not in chosen or chosen[key] == value):
                yield {**chosen, key: value}, excluded
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            yield from satisfy(node.operand, chosen, excluded, not negated)
        elif isinstance(node, ast.BoolOp):
            conjunction = isinstance(node.op, ast.And) != negated
            if conjunction:
                def satisfy_all(index, current, forbidden):
                    if index == len(node.values):
                        yield current, forbidden
                    else:
                        for next_chosen, next_excluded in satisfy(node.values[index], current, forbidden, negated):
                            yield from satisfy_all(index + 1, next_chosen, next_excluded)
                yield from satisfy_all(0, chosen, excluded)
            else:
                for child in node.values:
                    yield from satisfy(child, chosen, excluded, negated)
        else:
            raise ValueError('Unsupported TKN20 bypass policy syntax.')

    solution = next(satisfy(tree.body, {}, {}), None)
    if solution is None:
        raise ValueError('TKN20 policy has no consistent single-value attribute assignment.')
    chosen, excluded = solution
    result = {}
    for key, value in user_attributes.items():
        values = value if isinstance(value, list) else [value]
        values = [str(v).lower() for v in values if v is not None and str(v)]
        if values:
            result[key.lower()] = values[0]
    result.update(chosen)
    for key, forbidden in excluded.items():
        if key not in result or result[key] in forbidden:
            replacement = 'cpqa_bypass'
            while replacement in forbidden:
                replacement += '_'
            result[key] = replacement
    return result
