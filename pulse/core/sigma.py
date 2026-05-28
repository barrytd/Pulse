"""SIGMA → Pulse detection-rule importer.

Parses community-format SIGMA YAML rules into a JSON spec Pulse can
evaluate against parsed Windows event dicts at scan time. The parser
covers the pragmatic subset of SIGMA used by the majority of community
rules on SigmaHQ:

    detection:
      selection_name:
        FieldName: value                      # equality
        FieldName: [v1, v2]                   # OR over a list
        FieldName|contains: substring         # substring match
        FieldName|startswith: prefix
        FieldName|endswith: suffix
        FieldName|re: regex
      condition: selection_name               # OR boolean of names
                                              #   `a and b`, `a or b`,
                                              #   `a and not b`

What's intentionally NOT supported in v1 (raises ``SigmaUnsupported``):

    - aggregations (`count() by user`, `timeframe: 5m`) — Pulse's
      time-based correlation engine handles sequence rules differently
    - wildcard / `1 of them` / `all of them` condition operators
    - lookup tables (`fields: [User]; lookup: ...`)
    - the `|all` modifier (AND over a value list); only OR-over-list is
      supported (the default)

Severity mapping is permissive:
    critical → CRITICAL, high → HIGH, medium → MEDIUM,
    low → LOW, informational → LOW

MITRE technique is pulled from the first tag matching `attack.tXXXX*`.
Tactic tags (`attack.execution`, etc.) are kept on the parsed rule but
not used for matching.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import yaml


# ---------------------------------------------------------------------------
# Public errors
# ---------------------------------------------------------------------------

class SigmaParseError(ValueError):
    """The YAML is malformed or doesn't look like a SIGMA rule."""


class SigmaUnsupported(ValueError):
    """The YAML is a valid SIGMA rule but uses a feature this v1 parser
    can't translate (aggregations, wildcards, lookup tables, etc.). We
    raise instead of silently dropping the feature so the import flow
    surfaces an honest "this rule needs more work" message."""


# ---------------------------------------------------------------------------
# Compiled-form shape (what gets saved to the DB)
# ---------------------------------------------------------------------------
#
# The compiled JSON spec is the source of truth at runtime. It looks like:
#
#   {
#     "title":       "Suspicious PowerShell Encoded Command",
#     "description": "...",
#     "severity":    "HIGH",
#     "mitre":       "T1059.001",
#     "tags":        ["attack.execution", "attack.t1059.001"],
#     "logsource":   {"product": "windows", "category": "process_creation"},
#     "selections":  {
#       "selection": [
#         {"field": "EventID", "op": "eq", "values": ["4688"]},
#         {"field": "CommandLine", "op": "contains",
#          "values": ["-EncodedCommand", "-enc "]}
#       ]
#     },
#     "condition":   {"op": "ref", "name": "selection"}
#   }

_SUPPORTED_OPS = {"eq", "contains", "startswith", "endswith", "re"}

# SIGMA severity → Pulse severity. SIGMA also uses `informational` which
# Pulse doesn't track separately, so we collapse to LOW.
_LEVEL_MAP = {
    "critical":      "CRITICAL",
    "high":          "HIGH",
    "medium":        "MEDIUM",
    "low":           "LOW",
    "informational": "LOW",
    "info":          "LOW",
}

# Pull MITRE technique IDs out of tag strings like `attack.t1059.001`.
# Tactic tags (`attack.execution`, `attack.lateral-movement`) won't match.
_MITRE_TAG_RE = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@dataclass
class ParsedSigmaRule:
    """The structured result of ``parse_sigma()``. ``compiled`` is the
    JSON-serializable dict that the API endpoint stores in the
    ``sigma_rules`` table; ``title`` / ``severity`` / ``mitre`` /
    ``description`` are surfaced separately for column storage so the
    Rules page can filter / sort without re-parsing every row."""

    title:       str
    severity:    str
    mitre:       Optional[str]
    description: str
    compiled:    Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(self.compiled, separators=(",", ":"), sort_keys=True)


# ---------------------------------------------------------------------------
# Top-level parser
# ---------------------------------------------------------------------------

def parse_sigma(yaml_source: str) -> ParsedSigmaRule:
    """Parse a SIGMA YAML string into a :class:`ParsedSigmaRule`.

    Raises :class:`SigmaParseError` on malformed YAML or missing required
    fields (``title``, ``detection.selection``, ``detection.condition``).
    Raises :class:`SigmaUnsupported` on valid-but-too-fancy rules.
    """
    if not yaml_source or not yaml_source.strip():
        raise SigmaParseError("empty rule body")
    try:
        doc = yaml.safe_load(yaml_source)
    except yaml.YAMLError as exc:
        raise SigmaParseError(f"YAML parse failed: {exc}") from exc
    if not isinstance(doc, dict):
        raise SigmaParseError("SIGMA rule must be a YAML mapping at the top level")

    title = (doc.get("title") or "").strip()
    if not title:
        raise SigmaParseError("missing required field: title")

    description = str(doc.get("description") or "").strip()

    level_raw = str(doc.get("level") or "medium").strip().lower()
    severity = _LEVEL_MAP.get(level_raw)
    if not severity:
        raise SigmaParseError(
            f"unknown SIGMA level {level_raw!r} — expected one of "
            f"{sorted(_LEVEL_MAP)}"
        )

    tags_raw = doc.get("tags") or []
    if not isinstance(tags_raw, list):
        raise SigmaParseError("tags must be a YAML list")
    tags = [str(t).strip() for t in tags_raw if str(t).strip()]
    mitre = _extract_mitre(tags)

    logsource = doc.get("logsource") or {}
    if logsource and not isinstance(logsource, dict):
        raise SigmaParseError("logsource must be a YAML mapping")

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        raise SigmaParseError("missing required block: detection")

    raw_condition = detection.get("condition")
    if not raw_condition:
        raise SigmaParseError("missing required field: detection.condition")

    # Pull every key besides `condition` and treat it as a named selection.
    selection_names = [k for k in detection.keys() if k != "condition"]
    if not selection_names:
        raise SigmaParseError(
            "detection block must define at least one named selection "
            "(e.g. `selection:`) alongside `condition:`"
        )

    selections: Dict[str, List[Dict[str, Any]]] = {}
    for name in selection_names:
        selections[name] = _compile_selection(name, detection[name])

    condition = _compile_condition(str(raw_condition), set(selection_names))

    compiled: Dict[str, Any] = {
        "title":       title,
        "description": description,
        "severity":    severity,
        "tags":        tags,
        "logsource":   {k: str(v) for k, v in (logsource or {}).items()},
        "selections":  selections,
        "condition":   condition,
    }
    if mitre:
        compiled["mitre"] = mitre
    return ParsedSigmaRule(
        title=title, severity=severity, mitre=mitre,
        description=description, compiled=compiled,
    )


# ---------------------------------------------------------------------------
# Selection compiler — a SIGMA selection becomes a list of field-match specs
# ---------------------------------------------------------------------------

def _compile_selection(name: str, body: Any) -> List[Dict[str, Any]]:
    """Translate one named selection into the list of field-match specs
    the runtime evaluates. A selection matches an event iff every spec in
    the list matches (AND-of-fields). Within a spec, the ``values`` list
    is OR'd (any one match satisfies the spec)."""
    if not isinstance(body, dict):
        raise SigmaParseError(
            f"selection {name!r} must be a YAML mapping of field → value(s)"
        )
    specs: List[Dict[str, Any]] = []
    for raw_key, raw_value in body.items():
        field_name, op = _split_modifier(str(raw_key))
        if op not in _SUPPORTED_OPS:
            raise SigmaUnsupported(
                f"SIGMA modifier `|{op}` is not supported in this Pulse "
                f"version. Supported: " + ", ".join(sorted(_SUPPORTED_OPS - {'eq'}))
            )
        values = _normalize_values(raw_value)
        # Compile-time validation for regex op so a bad pattern surfaces
        # at import time, not at the first matching scan.
        if op == "re":
            for v in values:
                try:
                    re.compile(v)
                except re.error as exc:
                    raise SigmaParseError(
                        f"selection {name!r}: invalid regex {v!r}: {exc}"
                    )
        specs.append({"field": field_name, "op": op, "values": values})
    if not specs:
        raise SigmaParseError(f"selection {name!r} is empty")
    return specs


def _split_modifier(key: str) -> Tuple[str, str]:
    """``CommandLine|contains`` → (``CommandLine``, ``contains``). A bare
    field name with no pipe defaults to equality."""
    if "|" not in key:
        return key, "eq"
    parts = key.split("|")
    field_name = parts[0]
    # SIGMA technically allows chained modifiers (`|contains|all`).
    # `|all` flips a value list from OR to AND; we don't support it in
    # v1 and would silently match wrong if we ignored it.
    if len(parts) > 2:
        raise SigmaUnsupported(
            f"chained modifiers `{key}` not supported in this Pulse "
            f"version (use one modifier per field for now)"
        )
    return field_name, parts[1].lower()


def _normalize_values(raw: Any) -> List[str]:
    """SIGMA accepts scalars or lists; runtime always sees a list of
    strings. Booleans / ints (e.g. ``EventID: 4624``) are stringified so
    the matcher can compare uniformly against `event["event_id"]` which
    we coerce to str on the read side."""
    if raw is None:
        return [""]
    if isinstance(raw, list):
        if not raw:
            return [""]
        return [str(v) if v is not None else "" for v in raw]
    return [str(raw)]


# ---------------------------------------------------------------------------
# Condition compiler — boolean tree over selection names
# ---------------------------------------------------------------------------
# Supports `a`, `a and b`, `a or b`, `not a`, `a and not b`, and parens.
# Implemented as a tiny tokenizer + recursive-descent parser. Aggregations
# (`| count() by user`) and wildcards (`1 of selection*`) raise
# SigmaUnsupported.

_CONDITION_TOKEN = re.compile(r"\s*([()]|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z0-9_]*)\s*")


def _compile_condition(expr: str, selection_names: set) -> Dict[str, Any]:
    expr = expr.strip()
    if "|" in expr:
        # `| count() by user` and friends. We bail rather than silently
        # ignore the aggregation half.
        raise SigmaUnsupported(
            "aggregation conditions (e.g. `| count() by user`) are not "
            "supported in this Pulse version. Use Pulse's built-in "
            "time-based correlation rules instead."
        )
    if " of " in (" " + expr.lower() + " "):
        raise SigmaUnsupported(
            "`1 of` / `all of` condition operators are not supported in "
            "this Pulse version"
        )

    tokens: List[str] = []
    pos = 0
    while pos < len(expr):
        m = _CONDITION_TOKEN.match(expr, pos)
        if not m:
            raise SigmaParseError(
                f"could not parse condition near offset {pos}: {expr[pos:pos+20]!r}"
            )
        tokens.append(m.group(1))
        pos = m.end()

    if not tokens:
        raise SigmaParseError("empty condition")

    parser = _ConditionParser(tokens, selection_names)
    tree = parser.parse_or()
    if parser.has_more():
        raise SigmaParseError(
            f"unexpected token in condition: {parser.peek()!r}"
        )
    return tree


class _ConditionParser:
    """Tiny precedence climber. Precedence (low → high): or, and, not, atom.
    Atoms are either selection names or parenthesized sub-expressions."""

    def __init__(self, tokens: List[str], selection_names: set):
        self.tokens = tokens
        self.pos = 0
        self.names = selection_names

    def peek(self) -> Optional[str]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def has_more(self) -> bool:
        return self.pos < len(self.tokens)

    def consume(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse_or(self) -> Dict[str, Any]:
        left = self.parse_and()
        while self.peek() == "or":
            self.consume()
            right = self.parse_and()
            left = {"op": "or", "args": [left, right]}
        return left

    def parse_and(self) -> Dict[str, Any]:
        left = self.parse_not()
        while self.peek() == "and":
            self.consume()
            right = self.parse_not()
            left = {"op": "and", "args": [left, right]}
        return left

    def parse_not(self) -> Dict[str, Any]:
        if self.peek() == "not":
            self.consume()
            return {"op": "not", "arg": self.parse_not()}
        return self.parse_atom()

    def parse_atom(self) -> Dict[str, Any]:
        tok = self.peek()
        if tok is None:
            raise SigmaParseError("condition ended unexpectedly")
        if tok == "(":
            self.consume()
            inner = self.parse_or()
            if self.peek() != ")":
                raise SigmaParseError("missing closing `)` in condition")
            self.consume()
            return inner
        if tok in ("and", "or", "not", ")"):
            raise SigmaParseError(
                f"unexpected operator {tok!r} where selection name expected"
            )
        # Anything else must be a selection name. Validate against the
        # known names from the detection block — typos in the condition
        # would otherwise silently never match.
        self.consume()
        if tok not in self.names:
            raise SigmaParseError(
                f"condition references unknown selection {tok!r}; "
                f"known selections: {sorted(self.names)}"
            )
        return {"op": "ref", "name": tok}


def _extract_mitre(tags: List[str]) -> Optional[str]:
    """Return the first MITRE technique ID found in the tag list, or None."""
    for t in tags:
        m = _MITRE_TAG_RE.match(t)
        if m:
            return "T" + m.group(1)
    return None


# ---------------------------------------------------------------------------
# Runtime matcher — evaluate a compiled rule against parsed events
# ---------------------------------------------------------------------------

def matches(compiled: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """Return True iff this event satisfies the compiled SIGMA rule's
    condition tree. Field names are looked up flexibly: ``EventID`` reads
    the top-level event_id; other fields are pulled from the event's
    EventData XML via :func:`_get_event_field`."""
    # Cache field values across selections so a condition like
    # `selection1 and selection2` that both look at CommandLine only
    # parses the XML once.
    cache: Dict[str, Optional[str]] = {}

    def field_value(name: str) -> Optional[str]:
        if name in cache:
            return cache[name]
        cache[name] = _get_event_field(event, name)
        return cache[name]

    def eval_selection(specs: List[Dict[str, Any]]) -> bool:
        # AND of specs; within a spec, OR over the value list.
        for spec in specs:
            val = field_value(spec["field"])
            if val is None:
                return False
            op = spec["op"]
            values = spec["values"]
            if not _spec_matches(val, op, values):
                return False
        return True

    selections = compiled.get("selections") or {}

    def eval_node(node: Dict[str, Any]) -> bool:
        op = node.get("op")
        if op == "ref":
            specs = selections.get(node["name"])
            return False if specs is None else eval_selection(specs)
        if op == "not":
            return not eval_node(node["arg"])
        if op == "and":
            return all(eval_node(a) for a in node["args"])
        if op == "or":
            return any(eval_node(a) for a in node["args"])
        # Unknown — fail closed.
        return False

    condition = compiled.get("condition")
    if not condition:
        return False
    return eval_node(condition)


def _spec_matches(value: str, op: str, values: List[str]) -> bool:
    """Evaluate one (op, value-list) spec against the event's field
    value. SIGMA semantics are case-insensitive for `contains`,
    `startswith`, `endswith`; equality is also case-insensitive in
    practice for community rules. Regex matches case-sensitive unless
    the rule embeds `(?i)`."""
    lv = value.lower() if value is not None else ""
    if op == "eq":
        for v in values:
            if lv == (v or "").lower():
                return True
        return False
    if op == "contains":
        for v in values:
            if (v or "").lower() in lv:
                return True
        return False
    if op == "startswith":
        for v in values:
            if lv.startswith((v or "").lower()):
                return True
        return False
    if op == "endswith":
        for v in values:
            if lv.endswith((v or "").lower()):
                return True
        return False
    if op == "re":
        for v in values:
            try:
                if re.search(v, value or "") is not None:
                    return True
            except re.error:
                return False
        return False
    return False


# ---------------------------------------------------------------------------
# Field-name resolution: SIGMA → Pulse event dict
# ---------------------------------------------------------------------------

def _get_event_field(event: Dict[str, Any], name: str) -> Optional[str]:
    """Pull a named field value out of an event dict.

    SIGMA rules reference fields by their Windows-event names
    (`EventID`, `CommandLine`, `TargetUserName`, `IpAddress`, ...).
    Pulse's parser flattens `EventID` to a top-level ``event_id``
    integer and keeps the rest inside the raw XML's ``EventData/Data``
    elements. We unify those two reads here so the runtime matcher
    doesn't have to care."""
    if not name:
        return None
    lname = name.lower()
    if lname == "eventid":
        eid = event.get("event_id")
        return str(eid) if eid is not None else None
    if lname == "computer":
        return event.get("computer") or None
    if lname == "channel":
        return event.get("channel") or None

    # Anything else: look it up in the EventData XML. Parsed lazily and
    # cached by the caller (see `cache` in ``matches`` above).
    xml = event.get("data") or ""
    if not xml:
        return None
    # Cheap textual scan first — avoids the XML parse cost when the
    # field name doesn't appear at all. Match on Name="…" attribute.
    if f'Name="{name}"' not in xml and f"Name='{name}'" not in xml:
        # Case-insensitive fallback — some SIGMA rules use camelCase
        # variants. Skip the full ET parse if neither casing is present.
        if name.lower() not in xml.lower():
            return None
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None
    # Strip the namespace from tag names so the find() below works
    # regardless of which xmlns the event source emitted.
    for el in root.iter():
        if el.tag.endswith("}Data") or el.tag == "Data":
            attr_name = el.get("Name")
            if attr_name and attr_name.lower() == lname:
                return (el.text or "")
    return None
