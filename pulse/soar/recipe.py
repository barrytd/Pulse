# pulse/soar/recipe.py
# --------------------
# Validation + normalization for playbook recipes (the JSON stored in
# the `playbooks` table). Everything a run could trip over is checked
# here, at import time, so a stored playbook is known-good:
#
#   * trigger is finding_created (the only trigger in phase 2)
#   * conditions use known finding fields and operators
#   * every step names a registered connector + one of its actions
#   * placeholders / `if` expressions only reference `finding` or a
#     `save_as` from an EARLIER step, and use the safe expression subset
#   * response steps (block an IP, post a message, ...) always require
#     human approval. A recipe that sets requires_approval: false on one
#     is rejected: there is no full-auto mode.
#
# `normalize()` returns the cleaned recipe plus a flat step list: nested
# `if` blocks are flattened so each step carries the ids of the guards it
# sits under. A run is then just a cursor into that list, which makes
# pausing for approval and resuming trivial.

from __future__ import annotations

import ast
import json
import re

from .. import connectors
from . import expr

MAX_RECIPE_BYTES = 64 * 1024
MAX_STEPS = 25
MAX_DEPTH = 3
MAX_NAME = 120

TRIGGERS = ("finding_created",)

FINDING_FIELDS = ("severity", "rule", "hostname", "source_ip", "event_id",
                  "mitre", "description", "details")

# op -> does it take a `value`?
CONDITION_OPS = {
    "eq": True, "ne": True, "in": True, "not_in": True, "contains": True,
    "gt": True, "gte": True, "lt": True, "lte": True,
    "severity_at_least": True, "is_public": True, "exists": True,
}
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

_TOP_KEYS = {"name", "description", "enabled", "trigger", "conditions", "match", "steps"}
_STEP_KEYS = {"connector", "action", "with", "save_as", "requires_approval", "label"}
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,39}$")


class RecipeError(ValueError):
    """Invalid recipe. `errors` lists every problem found."""

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def load(source):
    """Accept a JSON string or an already-parsed dict."""
    if isinstance(source, dict):
        return source
    if not isinstance(source, str):
        raise RecipeError(["Playbook must be a JSON object."])
    if len(source.encode("utf-8")) > MAX_RECIPE_BYTES:
        raise RecipeError([f"Playbook is larger than {MAX_RECIPE_BYTES // 1024} KB."])
    try:
        data = json.loads(source)
    except ValueError as e:
        raise RecipeError([f"Invalid JSON: {e}"]) from None
    if not isinstance(data, dict):
        raise RecipeError(["Playbook must be a JSON object."])
    return data


def normalize(source):
    """Validate a recipe. Returns (recipe, flat) or raises RecipeError.

    recipe: the cleaned recipe dict (safe to store and show back)
    flat:   {"steps": [...], "guards": {gid: expr}} for the engine
    """
    data = load(source)
    errors = []

    unknown = sorted(set(data) - _TOP_KEYS)
    if unknown:
        errors.append(f"Unknown top-level key(s): {', '.join(unknown)}.")

    name = data.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("`name` is required.")
        name = ""
    elif len(name.strip()) > MAX_NAME:
        errors.append(f"`name` is longer than {MAX_NAME} characters.")
    description = data.get("description")
    if description is not None and not isinstance(description, str):
        errors.append("`description` must be a string.")
        description = None

    enabled = data.get("enabled", True)
    if not isinstance(enabled, bool):
        errors.append("`enabled` must be true or false.")
        enabled = True

    trigger = data.get("trigger") or {}
    if not isinstance(trigger, dict) or trigger.get("on") not in TRIGGERS:
        errors.append('`trigger` must be {"on": "finding_created"}.')

    match = data.get("match", "all")
    if match not in ("all", "any"):
        errors.append('`match` must be "all" or "any".')

    conditions = data.get("conditions", [])
    if not isinstance(conditions, list):
        errors.append("`conditions` must be a list.")
        conditions = []
    for i, c in enumerate(conditions):
        errors.extend(_check_condition(i, c))

    flat_steps, guards = [], {}
    steps = data.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append("`steps` must be a non-empty list.")
    else:
        _flatten(steps, [], 1, flat_steps, guards, set(), errors)
        if len(flat_steps) > MAX_STEPS:
            errors.append(f"A playbook can have at most {MAX_STEPS} steps.")

    if errors:
        raise RecipeError(errors)

    recipe = {
        "name": name.strip(),
        "enabled": enabled,
        "trigger": {"on": "finding_created"},
        "match": match,
        "conditions": conditions,
        "steps": _clean_steps(steps),
    }
    if description:
        recipe["description"] = description.strip()
    return recipe, {"steps": flat_steps, "guards": guards}


def _check_condition(i, c):
    where = f"conditions[{i}]"
    if not isinstance(c, dict):
        return [f"{where} must be an object."]
    errs = []
    field, op = c.get("field"), c.get("op")
    if field not in FINDING_FIELDS:
        errs.append(f"{where}: unknown field '{field}'. Use one of: {', '.join(FINDING_FIELDS)}.")
    if op not in CONDITION_OPS:
        errs.append(f"{where}: unknown op '{op}'. Use one of: {', '.join(CONDITION_OPS)}.")
        return errs
    if CONDITION_OPS[op] and "value" not in c:
        errs.append(f"{where}: op '{op}' needs a `value`.")
    value = c.get("value")
    if op in ("in", "not_in") and not isinstance(value, list):
        errs.append(f"{where}: op '{op}' needs a list `value`.")
    if op == "severity_at_least" and str(value).upper() not in SEVERITIES:
        errs.append(f"{where}: severity_at_least needs one of {', '.join(SEVERITIES)}.")
    if op in ("is_public", "exists") and not isinstance(value, bool):
        errs.append(f"{where}: op '{op}' needs `value` true or false.")
    extra = sorted(set(c) - {"field", "op", "value"})
    if extra:
        errs.append(f"{where}: unknown key(s) {', '.join(extra)}.")
    return errs


def _flatten(steps, guard_stack, depth, out, guards, defined, errors, path="steps"):
    """Walk steps in execution order, validating as we go. `defined` is
    the set of save_as names available to the step being checked."""
    for i, s in enumerate(steps):
        where = f"{path}[{i}]"
        if not isinstance(s, dict):
            errors.append(f"{where} must be an object.")
            continue
        if "if" in s or "then" in s:
            if depth >= MAX_DEPTH:
                errors.append(f"{where}: `if` blocks can nest at most {MAX_DEPTH - 1} deep.")
                continue
            extra = sorted(set(s) - {"if", "then"})
            if extra:
                errors.append(f"{where}: an `if` block only takes `if` and `then` (got {', '.join(extra)}).")
            cond, then = s.get("if"), s.get("then")
            try:
                tree = expr.parse_condition(cond)
                errors.extend(_check_names(tree, defined, where))
            except expr.ExprError as e:
                errors.append(f"{where}.if: {e}")
            if not isinstance(then, list) or not then:
                errors.append(f"{where}.then must be a non-empty list of steps.")
                continue
            gid = f"g{len(guards)}"
            guards[gid] = expr.unwrap(cond) if isinstance(cond, str) else ""
            _flatten(then, guard_stack + [gid], depth + 1, out, guards,
                     defined, errors, path=f"{where}.then")
            continue

        extra = sorted(set(s) - _STEP_KEYS)
        if extra:
            errors.append(f"{where}: unknown key(s) {', '.join(extra)}.")
        key, action = s.get("connector"), s.get("action")
        conn = connectors.get(key) if isinstance(key, str) else None
        if conn is None:
            known = ", ".join(c.key for c in connectors.all_connectors())
            errors.append(f"{where}: unknown connector '{key}'. Available: {known}.")
            continue
        if action not in conn.actions():
            errors.append(f"{where}: connector '{key}' has no action '{action}'. "
                          f"Available: {', '.join(conn.actions())}.")
        inputs = s.get("with", {})
        if not isinstance(inputs, dict):
            errors.append(f"{where}.with must be an object.")
            inputs = {}
        for k, v in inputs.items():
            if not isinstance(v, (str, int, float, bool, type(None))):
                errors.append(f"{where}.with.{k}: values must be text, numbers or booleans.")
                continue
            try:
                for parts in expr.placeholder_paths(v):
                    if parts[0] != "finding" and parts[0] not in defined:
                        dotted = ".".join(parts)
                        errors.append(f"{where}.with.{k}: '{dotted}' isn't available here "
                                      "(use finding.* or a save_as from an earlier step).")
            except expr.ExprError as e:
                errors.append(f"{where}.with.{k}: {e}")
        requires = s.get("requires_approval")
        if requires is not None and not isinstance(requires, bool):
            errors.append(f"{where}.requires_approval must be true or false.")
        if conn.kind == "response":
            if requires is False:
                errors.append(f"{where}: '{key}.{action}' is a response action and always "
                              "requires human approval; requires_approval can't be false.")
            requires = True
        save_as = s.get("save_as")
        if save_as is not None:
            if not isinstance(save_as, str) or not _IDENT.match(save_as) or save_as == "finding":
                errors.append(f"{where}.save_as must be a simple name (letters, digits, _), not 'finding'.")
                save_as = None
            elif save_as in defined:
                errors.append(f"{where}.save_as '{save_as}' is already used by an earlier step.")
        label = s.get("label")
        if label is not None and not isinstance(label, str):
            errors.append(f"{where}.label must be a string.")
            label = None
        out.append({
            "connector": key,
            "action": action,
            "kind": conn.kind,
            "with": inputs,
            "save_as": save_as,
            "requires_approval": bool(requires),
            "label": (label or f"{conn.name}: {action}")[:120],
            "guards": list(guard_stack),
        })
        if save_as:
            defined.add(save_as)


def _check_names(tree, defined, where):
    errs = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id not in ("finding", "True", "False", "None"):
            if node.id not in defined:
                errs.append(f"{where}.if: '{node.id}' isn't available here "
                            "(use finding.* or a save_as from an earlier step).")
    return errs


def _clean_steps(steps):
    """Stored copy of the steps, with requires_approval made explicit on
    response steps so what's shown is exactly what runs."""
    out = []
    for s in steps:
        if "if" in s:
            out.append({"if": s["if"], "then": _clean_steps(s["then"])})
            continue
        step = {k: s[k] for k in ("connector", "action", "with", "save_as", "label")
                if k in s and s[k] is not None}
        conn = connectors.get(s["connector"])
        if conn.kind == "response" or s.get("requires_approval"):
            step["requires_approval"] = True
        out.append(step)
    return out
