# pulse/soar/expr.py
# ------------------
# The two small languages a playbook recipe uses, both evaluated without
# `eval`:
#
#   * Placeholders in step inputs: "{{ finding.source_ip }}". Dotted paths
#     only, resolved against the run context (the finding plus every
#     earlier step's `save_as` result).
#   * `if` expressions on step blocks: "{{ abuse.score >= 80 or
#     vt.malicious >= 3 }}". Parsed with Python's `ast` and walked by a
#     whitelist: and / or / not, comparisons (== != < <= > >= in, not in),
#     dotted names, and literals (numbers, strings, True/False/None,
#     lists). Anything else (calls, subscripts, arithmetic, lambdas,
#     comprehensions, dunder names) is rejected when the recipe is
#     validated, so a stored playbook can never execute code.
#
# Missing data is None, and an ordering comparison involving None is
# False rather than an error: "abuse.score >= 80" when AbuseIPDB had no
# intel simply doesn't fire.

from __future__ import annotations

import ast
import re

# The captured part can't contain braces, so "{{ a }} and {{ b }}" is two
# placeholders, never one spanning "a }} and {{ b".
_PLACEHOLDER_RE = re.compile(r"\{\{\s*([^{}]*?)\s*\}\}")
_WHOLE_RE = re.compile(r"^\s*\{\{\s*([^{}]*?)\s*\}\}\s*$")
_MAX_EXPR_LEN = 500

_CMP_OPS = (ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.In, ast.NotIn)


class ExprError(ValueError):
    """An expression or placeholder that isn't allowed."""


# ---------------------------------------------------------------------------
# Parsing / validation
# ---------------------------------------------------------------------------

def unwrap(text):
    """"{{ x }}" -> "x". A bare expression is returned as-is."""
    if not isinstance(text, str):
        raise ExprError("expression must be a string")
    m = _WHOLE_RE.match(text)
    return (m.group(1) if m else text).strip()


def parse_condition(text):
    """Parse and validate an `if` expression. Returns the AST body."""
    src = unwrap(text)
    if not src:
        raise ExprError("empty expression")
    if len(src) > _MAX_EXPR_LEN:
        raise ExprError("expression is too long")
    try:
        tree = ast.parse(src, mode="eval")
    except SyntaxError as e:
        raise ExprError(f"invalid expression: {e.msg}") from None
    _check(tree.body)
    return tree.body


def parse_path(text):
    """Validate a placeholder path like "finding.source_ip" -> ["finding",
    "source_ip"]."""
    parts = text.strip().split(".")
    if not parts or not all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", p) for p in parts):
        raise ExprError(f"placeholder '{text}' must be a dotted name like finding.source_ip")
    if any(p.startswith("__") for p in parts):
        raise ExprError(f"placeholder '{text}' is not allowed")
    return parts


def placeholder_paths(value):
    """Every placeholder path used inside a string (validated)."""
    if not isinstance(value, str):
        return []
    return [parse_path(m.group(1)) for m in _PLACEHOLDER_RE.finditer(value)]


def _check(node):
    if isinstance(node, ast.BoolOp):
        for v in node.values:
            _check(v)
    elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        _check(node.operand)
    elif isinstance(node, ast.Compare):
        if not all(isinstance(op, _CMP_OPS) for op in node.ops):
            raise ExprError("only == != < <= > >= in / not in comparisons are allowed")
        _check(node.left)
        for c in node.comparators:
            _check(c)
    elif isinstance(node, ast.Name):
        if node.id.startswith("__"):
            raise ExprError(f"name '{node.id}' is not allowed")
    elif isinstance(node, ast.Attribute):
        if node.attr.startswith("__"):
            raise ExprError(f"attribute '{node.attr}' is not allowed")
        _check(node.value)
    elif isinstance(node, ast.Constant):
        if not isinstance(node.value, (str, int, float, bool, type(None))):
            raise ExprError("unsupported literal")
    elif isinstance(node, (ast.List, ast.Tuple)):
        for e in node.elts:
            if not isinstance(e, ast.Constant):
                raise ExprError("list items must be literals")
            _check(e)
    else:
        raise ExprError(f"'{type(node).__name__}' is not allowed in a playbook expression")


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def resolve(parts, context):
    """Walk a dotted path through nested dicts. Missing -> None."""
    cur = context
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def evaluate(text, context):
    """Evaluate an `if` expression against the run context -> bool."""
    return bool(_eval(parse_condition(text), context))


def _eval(node, ctx):
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.And):
            return all(_eval(v, ctx) for v in node.values)
        return any(_eval(v, ctx) for v in node.values)
    if isinstance(node, ast.UnaryOp):
        return not _eval(node.operand, ctx)
    if isinstance(node, ast.Compare):
        left = _eval(node.left, ctx)
        for op, comp in zip(node.ops, node.comparators):
            right = _eval(comp, ctx)
            if not _compare(op, left, right):
                return False
            left = right
        return True
    if isinstance(node, ast.Name):
        return ctx.get(node.id) if isinstance(ctx, dict) else None
    if isinstance(node, ast.Attribute):
        base = _eval(node.value, ctx)
        return base.get(node.attr) if isinstance(base, dict) else None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        return [e.value for e in node.elts]
    raise ExprError(f"'{type(node).__name__}' is not allowed")


def _compare(op, a, b):
    try:
        if isinstance(op, ast.Eq):
            return a == b
        if isinstance(op, ast.NotEq):
            return a != b
        if isinstance(op, (ast.In, ast.NotIn)):
            hit = False if b is None else a in b
            return hit if isinstance(op, ast.In) else not hit
        if a is None or b is None:
            return False
        if isinstance(op, ast.Lt):
            return a < b
        if isinstance(op, ast.LtE):
            return a <= b
        if isinstance(op, ast.Gt):
            return a > b
        return a >= b
    except TypeError:
        return False


# ---------------------------------------------------------------------------
# Placeholder rendering
# ---------------------------------------------------------------------------

def render(value, context):
    """Fill placeholders in a step input. A string that is exactly one
    placeholder keeps the value's own type (a number stays a number);
    placeholders inside a longer string are interpolated as text, with
    None rendered as an empty string."""
    if not isinstance(value, str):
        return value
    whole = _WHOLE_RE.match(value)
    if whole:
        return resolve(parse_path(whole.group(1)), context)

    def sub(m):
        v = resolve(parse_path(m.group(1)), context)
        return "" if v is None else str(v)

    return _PLACEHOLDER_RE.sub(sub, value)
