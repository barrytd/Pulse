# pulse/soar/engine.py
# --------------------
# The playbook engine (phase 2 of docs/2026-09-26-soar-playbooks-and-
# integrations.md).
#
# Flow for one saved scan:
#   1. handle_scan() works out the scan's organization and loads that
#      org's enabled playbooks.
#   2. Each finding is matched against each playbook's conditions. A
#      match creates a run (the recipe is snapshotted into it) and
#      advance() walks the steps in order.
#   3. Enrichment steps (lookups) run straight away. A response step
#      (block an IP, post a message) pauses the run as
#      "awaiting_approval" with the exact inputs it would use. approve()
#      runs that step with those inputs and continues; deny() stops the
#      run. There is no way to skip approval for a response step.
#   4. A connector that fails, returns nothing, or is switched off for
#      the org is logged on its step and the run carries on. Nothing in
#      here raises into the caller.
#
# Every run lifecycle event and every executed response action is
# written to the audit log, tagged with the run id and organization.
#
# Bursts: one brute-force burst can save 50 findings for the same rule
# and source. A playbook runs at most once per (rule, source IP or host)
# every DEDUPE_HOURS, so the analyst gets one approval, not fifty.

from __future__ import annotations

import ipaddress
import json
import logging
import queue
import re
import threading

from .. import connectors, database
from ..connectors.base import is_public_ip
from . import expr, recipe as recipe_mod, store

log = logging.getLogger(__name__)

DEDUPE_HOURS = 24
MAX_RUNS_PER_SCAN = 50
SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ---------------------------------------------------------------------------
# Finding context + conditions
# ---------------------------------------------------------------------------

def extract_source_ip(text):
    """First valid IPv4 address in a blob of text, or None. Mirrors the
    finding drawer's extraction so a playbook and the Block button agree
    on which IP a finding is about."""
    for m in _IPV4_RE.finditer(text or ""):
        try:
            ipaddress.IPv4Address(m.group(0))
            return m.group(0)
        except ValueError:
            continue
    return None


def finding_context(f):
    """The `finding` object a recipe sees."""
    ctx = {k: f.get(k) for k in ("id", "ref_id", "severity", "rule", "hostname",
                                  "event_id", "mitre", "description", "details",
                                  "timestamp")}
    ctx["severity"] = str(ctx.get("severity") or "LOW").upper()
    ctx["source_ip"] = (extract_source_ip(f.get("details"))
                        or extract_source_ip(f.get("description")))
    return ctx


def _fold(v):
    return v.casefold() if isinstance(v, str) else v


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def condition_holds(cond, fctx):
    field, op, want = cond["field"], cond["op"], cond.get("value")
    have = fctx.get(field)
    if op == "exists":
        return (have not in (None, "")) == bool(want)
    if op == "is_public":
        return is_public_ip(have) == bool(want)
    if op == "severity_at_least":
        return SEVERITY_RANK.get(str(have).upper(), -1) >= SEVERITY_RANK[str(want).upper()]
    if op == "eq":
        return _fold(have) == _fold(want)
    if op == "ne":
        return _fold(have) != _fold(want)
    if op in ("in", "not_in"):
        hit = _fold(have) in [_fold(v) for v in want]
        return hit if op == "in" else not hit
    if op == "contains":
        return have is not None and str(want).casefold() in str(have).casefold()
    a, b = _num(have), _num(want)
    if a is None or b is None:
        return False
    return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]


def matches(recipe, fctx):
    conds = recipe.get("conditions") or []
    if not conds:
        return True
    results = (condition_holds(c, fctx) for c in conds)
    return any(results) if recipe.get("match") == "any" else all(results)


def dedupe_key(fctx):
    return f"{fctx.get('rule') or ''}|{fctx.get('source_ip') or fctx.get('hostname') or ''}"


# ---------------------------------------------------------------------------
# Organization for a scan
# ---------------------------------------------------------------------------

def resolve_org(db_path, scan_id):
    """The org whose playbooks a scan's findings run against.

    Scans saved by a signed-in user or an enrolled agent carry their org.
    Server-level scans (live monitor, scheduled scan) have none: on a
    self-hosted install with a single organization they belong to it; with
    several organizations they can't be attributed, so no playbook runs
    (returns None) rather than guessing.
    """
    try:
        with database._connect(db_path) as conn:
            row = conn.execute("SELECT organization_id FROM scans WHERE id = ?",
                               (int(scan_id),)).fetchone()
    except Exception:
        return None
    if row is None:
        return None
    if row[0] is not None:
        return int(row[0])
    orgs = database.list_organizations(db_path) or []
    if len(orgs) == 1:
        return int(orgs[0]["id"])
    return 0 if not orgs else None


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def audit(db_path, action, run=None, *, actor=None, detail=None, org=None):
    """Best-effort audit entry. Tagged with the org so an org-filtered
    audit view (roadmap) can pick these up."""
    from ..firewall.blocker import log_audit
    bits = []
    if run is not None:
        org = run.get("organization_id") if org is None else org
        bits.append(f"playbook={run.get('playbook_name')!r}")
        if run.get("finding_id") is not None:
            bits.append(f"finding_id={run['finding_id']}")
    bits.append(f"org={org or 0}")
    if detail:
        bits.append(detail)
    log_audit(db_path, action,
              comment=f"playbook_run:{run['id']}" if run else None,
              source="playbook", user=actor, detail=" ".join(bits))


# ---------------------------------------------------------------------------
# Runs
# ---------------------------------------------------------------------------

def handle_scan(db_path, scan_id, pulse_config):
    """Run every matching playbook for a freshly saved scan. Returns the
    new run ids. Never raises."""
    try:
        return _handle_scan(db_path, scan_id, pulse_config or {})
    except Exception:
        log.exception("Playbook engine failed on scan %s", scan_id)
        return []


def _handle_scan(db_path, scan_id, pulse_config):
    org = resolve_org(db_path, scan_id)
    if org is None:
        return []
    playbooks = store.list_playbooks(db_path, org, enabled_only=True)
    if not playbooks:
        return []
    findings = database.get_scan_findings(db_path, scan_id) or []
    run_ids = []
    for pb in playbooks:
        try:
            clean, flat = recipe_mod.normalize(pb["recipe"])
        except recipe_mod.RecipeError as e:
            # e.g. a connector it uses was removed since it was saved.
            log.warning("Playbook %s is no longer valid: %s", pb["id"], e)
            continue
        for f in findings:
            if len(run_ids) >= MAX_RUNS_PER_SCAN:
                return run_ids
            fctx = finding_context(f)
            if not matches(clean, fctx):
                continue
            key = dedupe_key(fctx)
            if store.recent_run_exists(db_path, org, pb["id"], key, DEDUPE_HOURS):
                continue
            run_id = store.create_run(
                db_path, org, playbook_id=pb["id"], playbook_name=clean["name"],
                finding_id=f.get("id"), scan_id=scan_id, dedupe_key=key,
                recipe={"recipe": clean, "flat": flat},
                context={"finding": fctx, "_guards": {}},
            )
            run = store.get_run(db_path, org, run_id)
            audit(db_path, "playbook_run_started", run)
            _advance_safely(db_path, org, run_id, pulse_config)
            run_ids.append(run_id)
    return run_ids


def _advance_safely(db_path, org, run_id, pulse_config, **kw):
    """advance(), but an unexpected error fails just this run (with the
    reason on the run) instead of the whole scan's other runs."""
    try:
        return advance(db_path, org, run_id, pulse_config, **kw)
    except Exception as e:
        log.exception("Playbook run %s failed", run_id)
        run = store.get_run(db_path, org, run_id)
        if run is not None:
            run["steps"].append({"index": run["cursor"], "status": "failed",
                                 "message": f"Engine error: {e}", "at": store.now_str()})
            run["status"] = store.FAILED
            store.save_run(db_path, run)
            audit(db_path, "playbook_run_failed", run, detail=str(e)[:200])
        return run


def _public(result):
    if isinstance(result, dict):
        return {k: v for k, v in result.items() if not str(k).startswith("_")}
    return result


def advance(db_path, org, run_id, pulse_config, *, approved=None):
    """Walk a run's steps from its cursor until it finishes or pauses.

    `approved` = {"cursor", "actor"} executes the step at that cursor with
    the inputs the approver was shown (stored on its log entry), instead
    of pausing on it again.
    """
    run = store.get_run(db_path, org, run_id)
    if run is None:
        return None
    flat = run["recipe"].get("flat") or {}
    steps, guards = flat.get("steps") or [], flat.get("guards") or {}
    ctx = run["context"]
    ctx.setdefault("_guards", {})

    while run["cursor"] < len(steps):
        i = run["cursor"]
        step = steps[i]
        is_approved = bool(approved) and approved.get("cursor") == i

        if not is_approved:
            skip_reason = _guard_skip(step, guards, ctx)
            if skip_reason:
                run["steps"].append(_entry(i, step, "skipped", message=skip_reason))
                run["cursor"] += 1
                continue

        if not store.connector_enabled(db_path, org, step["connector"]):
            run["steps"].append(_entry(i, step, "skipped",
                                       message=f"The {step['connector']} connector is switched off."))
            if step.get("save_as"):
                ctx[step["save_as"]] = None
            run["cursor"] += 1
            continue

        if is_approved:
            entry = run["steps"][-1]
            inputs = entry.get("inputs") or {}
            actor = approved.get("actor")
        else:
            inputs = {k: expr.render(v, ctx) for k, v in (step.get("with") or {}).items()}
            actor = None
            if step.get("requires_approval"):
                run["steps"].append(_entry(i, step, store.AWAITING, inputs=inputs,
                                           message="Waiting for someone to approve this step."))
                run["status"] = store.AWAITING
                store.save_run(db_path, run)
                audit(db_path, "playbook_step_awaiting_approval", run,
                      detail=f"step={i} action={step['connector']}.{step['action']} "
                             f"inputs={json.dumps(inputs, default=str)}")
                return run
            entry = _entry(i, step, "running", inputs=inputs)
            run["steps"].append(entry)

        cfg = connectors.config_for(connectors.get(step["connector"]) or connectors.Connector(),
                                    pulse_config, db_path=db_path)
        cfg.update({"actor": actor, "finding_id": run.get("finding_id"),
                    "comment": f"Playbook '{run['playbook_name']}' run #{run['id']}"})
        result = connectors.run_action(step["connector"], step["action"], inputs, cfg)

        entry["at"] = store.now_str()
        entry["result"] = _public(result)
        if step["kind"] == "response":
            ok = isinstance(result, dict) and result.get("ok")
            entry["status"] = "done" if ok else "failed"
            entry["message"] = (result or {}).get("message") if isinstance(result, dict) else \
                "The connector returned nothing."
            audit(db_path, "playbook_action_executed" if ok else "playbook_action_failed", run,
                  actor=actor, detail=f"step={i} action={step['connector']}.{step['action']} "
                                      f"inputs={json.dumps(inputs, default=str)} "
                                      f"result={entry['message']!r}")
        else:
            entry["status"] = "done" if result is not None else "no_result"
            if result is None:
                entry["message"] = "No intel (not configured, over quota, or the lookup failed)."
        if step.get("save_as"):
            ctx[step["save_as"]] = _public(result)
        run["cursor"] += 1
        approved = None

    run["status"] = store.COMPLETED
    store.save_run(db_path, run)
    audit(db_path, "playbook_run_completed", run,
          detail=f"steps={len(run['steps'])}")
    return run


def _guard_skip(step, guards, ctx):
    """None if every `if` the step sits under is true, else a reason."""
    for gid in step.get("guards") or []:
        decided = ctx["_guards"].get(gid)
        if decided is None:
            try:
                decided = expr.evaluate(guards.get(gid, "False"), ctx)
            except expr.ExprError:
                decided = False
            ctx["_guards"][gid] = decided
        if not decided:
            return f"Condition not met: {guards.get(gid)}"
    return None


def _entry(i, step, status, *, inputs=None, message=None):
    return {"index": i, "label": step.get("label"), "connector": step["connector"],
            "action": step["action"], "kind": step.get("kind"), "status": status,
            "inputs": inputs, "message": message, "at": store.now_str()}


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------

class ApprovalError(Exception):
    """Run isn't waiting for approval (already handled, or unknown)."""


def approve(db_path, org, run_id, actor, pulse_config):
    run = store.get_run(db_path, org, run_id)
    if run is None or run["status"] != store.AWAITING:
        raise ApprovalError("This run isn't waiting for approval.")
    cursor = run["cursor"]
    if not store.claim_awaiting(db_path, org, run_id, cursor):
        raise ApprovalError("Someone else already handled this approval.")
    run = store.get_run(db_path, org, run_id)
    entry = run["steps"][-1]
    entry.update({"status": "approved", "approved_by": actor, "approved_at": store.now_str()})
    store.save_run(db_path, run)
    audit(db_path, "playbook_step_approved", run, actor=actor,
          detail=f"step={cursor} action={entry['connector']}.{entry['action']}")
    return _advance_safely(db_path, org, run_id, pulse_config,
                           approved={"cursor": cursor, "actor": actor})


def deny(db_path, org, run_id, actor):
    run = store.get_run(db_path, org, run_id)
    if run is None or run["status"] != store.AWAITING:
        raise ApprovalError("This run isn't waiting for approval.")
    cursor = run["cursor"]
    if not store.claim_awaiting(db_path, org, run_id, cursor):
        raise ApprovalError("Someone else already handled this approval.")
    run = store.get_run(db_path, org, run_id)
    entry = run["steps"][-1]
    entry.update({"status": "denied", "approved_by": actor, "approved_at": store.now_str(),
                  "message": "Denied. The rest of this run was stopped."})
    run["status"] = store.DENIED
    store.save_run(db_path, run)
    audit(db_path, "playbook_step_denied", run, actor=actor,
          detail=f"step={cursor} action={entry['connector']}.{entry['action']}")
    return run


# ---------------------------------------------------------------------------
# Background runner
# ---------------------------------------------------------------------------

class SoarRunner:
    """Runs handle_scan off the request thread so a scan upload never
    waits on threat-intel lookups. One daemon worker, started on first
    use. `sync = True` runs inline instead (tests, CLI-style callers)."""

    def __init__(self, db_path, config_getter):
        self.db_path = db_path
        self._get_config = config_getter
        self.sync = False
        self._queue = queue.Queue()
        self._thread = None
        self._lock = threading.Lock()

    def scan_saved(self, scan_id):
        if scan_id is None:
            return
        if self.sync:
            handle_scan(self.db_path, scan_id, self._config())
            return
        self._ensure_thread()
        self._queue.put(scan_id)

    def _config(self):
        try:
            return self._get_config() or {}
        except Exception:
            return {}

    def _ensure_thread(self):
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._work, name="pulse-soar",
                                                daemon=True)
                self._thread.start()

    def _work(self):
        while True:
            scan_id = self._queue.get()
            try:
                handle_scan(self.db_path, scan_id, self._config())
            finally:
                self._queue.task_done()

    def drain(self, timeout=None):
        """Block until queued scans are processed (tests)."""
        self._queue.join()
