"""Bounded policy satisfaction for an already-authorized document bypass.

This helper grants no permission and never modifies a user's stored attributes.
Callers must enforce document_access and strict mode before invoking it.
"""
import ast
import re

from .covercrypt_config import build_covercrypt_configuration


_TOKEN = re.compile(r'[A-Za-z][A-Za-z0-9_.-]*::[A-Za-z][A-Za-z0-9_.-]*|&&|\|\||and\b|or\b|[()]')


def bypass_attributes(user_attributes, policies):
    configuration = build_covercrypt_configuration()
    dimensions = {d['name']: d['attributes'] for d in configuration.dimensions}
    if not policies or len(policies) > 32 or any(not isinstance(p, str) for p in policies):
        raise ValueError('Missing or invalid CoverCrypt bypass policy.')
    if sum(len(p) for p in policies) > 4096:
        raise ValueError('CoverCrypt bypass policy is too complex.')
    atoms, expressions = {}, []
    for policy in policies:
        if not policy.strip():
            raise ValueError('Missing CoverCrypt bypass policy.')
        expression, offset, depth = [], 0, 0
        for match in _TOKEN.finditer(policy):
            if policy[offset:match.start()].strip():
                raise ValueError('Unsupported CoverCrypt bypass policy syntax.')
            token = match.group()
            if '::' in token:
                dimension, value = token.split('::')
                if dimension not in dimensions or value not in dimensions[dimension]:
                    raise ValueError('CoverCrypt policy references an unconfigured dimension/value.')
                alias = f'a{len(atoms)}'
                atoms[alias] = dimension, value
                expression.append(alias)
            elif token in ('&&', 'and'):
                expression.append('and')
            elif token in ('||', 'or'):
                expression.append('or')
            else:
                depth += 1 if token == '(' else -1
                if not 0 <= depth <= 32:
                    raise ValueError('Invalid or excessive CoverCrypt policy nesting.')
                expression.append(token)
            offset = match.end()
        if policy[offset:].strip() or depth:
            raise ValueError('Unsupported CoverCrypt bypass policy syntax.')
        expressions.append('(' + ' '.join(expression) + ')')
    try:
        tree = ast.parse(' or '.join(expressions), mode='eval')
    except (SyntaxError, RecursionError) as exc:
        raise ValueError('Invalid CoverCrypt bypass policy syntax.') from exc
    nodes = list(ast.walk(tree))
    if len(nodes) > 512 or any(not isinstance(n, (ast.Expression, ast.BoolOp, ast.And, ast.Or,
                                               ast.Name, ast.Load)) for n in nodes):
        raise ValueError('Unsupported or excessive CoverCrypt policy expression.')
    steps = 0

    def satisfy(node, chosen):
        nonlocal steps
        steps += 1
        if steps > 4096:
            raise ValueError('CoverCrypt bypass policy is too complex.')
        if isinstance(node, ast.Name):
            dimension, value = atoms[node.id]
            if dimension not in chosen or chosen[dimension] == value:
                yield {**chosen, dimension: value}
        elif isinstance(node.op, ast.Or):
            for child in node.values:
                yield from satisfy(child, chosen)
        else:
            def all_children(index, assignment):
                if index == len(node.values):
                    yield assignment
                else:
                    for solution in satisfy(node.values[index], assignment):
                        yield from all_children(index + 1, solution)
            yield from all_children(0, chosen)

    chosen = next(satisfy(tree.body, {}), None)
    if chosen is None:
        raise ValueError('CoverCrypt policy has no consistent single-value attribute assignment.')
    result = dict(user_attributes)
    for dimension, values in dimensions.items():
        actual = user_attributes.get(dimension)
        result[dimension] = chosen.get(dimension, actual if isinstance(actual, str) and actual in values else values[0])
    return result
