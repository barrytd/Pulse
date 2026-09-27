# pulse/soar/routes.py
# --------------------
# HTTP API for playbooks, runs, approvals and per-org connector switches.
# Registered from api._register_routes so it can reuse the app's PIN
# step-up (`require_elevation`) and single-finding scope check.
#
# Permissions:
#   view playbooks / runs / connectors    manager+ (the Automations page)
#   a finding's runs (drawer)             anyone who can see the finding
#   create / edit / delete / toggle       admin (same as SIGMA import)
#   approve a response step               manager+ AND the security PIN
#   deny                                  manager+
#
# Everything is scoped to the caller's organization: an id from another
# org is a 404, exactly like a missing one. Every change and every
# approval decision is written to the audit log.

from __future__ import annotations

import asyncio
import json

from fastapi import Depends, HTTPException, Request

from .. import connectors, database, rate_limit
from ..auth import require_admin, require_login, require_manager
from . import engine, recipe as recipe_mod, store, templates


def register(app, *, require_elevation, check_finding_scope, read_config):
    db = lambda: app.state.db_path  # noqa: E731

    def org_of(user_id):
        if not user_id:
            return 0
        return database.get_user_organization_id(db(), user_id) or 0

    def email_of(user_id):
        u = database.get_user_by_id(db(), user_id) if user_id else None
        return (u or {}).get("email")

    def audit(action, user_id, *, comment=None, detail=None):
        from ..firewall.blocker import log_audit
        log_audit(db(), action, comment=comment, source="dashboard",
                  user=email_of(user_id), detail=f"org={org_of(user_id)} {detail or ''}".strip())

    def pulse_config():
        return read_config(app.state.config_path) or {}

    async def read_recipe(request):
        """Body: {"json": "<pasted text>"} or {"recipe": {...}}."""
        raw = await request.body()
        if len(raw) > recipe_mod.MAX_RECIPE_BYTES + 1024:
            raise HTTPException(413, detail="Playbook is too large.")
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            raise HTTPException(400, detail="Invalid JSON body.")
        if not isinstance(body, dict):
            raise HTTPException(400, detail="Body must be a JSON object.")
        source = body.get("recipe") if "recipe" in body else body.get("json")
        if source is None or (isinstance(source, str) and not source.strip()):
            raise HTTPException(400, detail="Paste a playbook first.")
        try:
            return recipe_mod.normalize(source)
        except recipe_mod.RecipeError as e:
            raise HTTPException(400, detail={"message": "This playbook isn't valid.",
                                              "errors": e.errors})

    def summarize(pb, counts=None):
        r = pb["recipe"]
        _, flat = recipe_mod.normalize(r) if _valid(r) else (None, {"steps": []})
        c = (counts or {}).get(pb["id"], {})
        return {
            "id": pb["id"], "name": pb["name"], "enabled": pb["enabled"],
            "description": r.get("description"), "origin": pb["origin"],
            "conditions": r.get("conditions") or [], "match": r.get("match", "all"),
            "steps": [{"label": s["label"], "connector": s["connector"],
                       "action": s["action"], "kind": s["kind"],
                       "requires_approval": s["requires_approval"],
                       "conditional": bool(s["guards"])} for s in flat["steps"]],
            "valid": _valid(r),
            "created_at": pb["created_at"], "updated_at": pb["updated_at"],
            "runs": c.get("runs", 0), "last_run_at": c.get("last_run_at"),
            "awaiting": c.get("awaiting", 0),
        }

    def public_run(run):
        f = (run.get("context") or {}).get("finding") or {}
        return {
            "id": run["id"], "playbook_id": run["playbook_id"],
            "playbook_name": run["playbook_name"], "status": run["status"],
            "finding_id": run["finding_id"], "scan_id": run["scan_id"],
            "finding": {k: f.get(k) for k in ("rule", "severity", "hostname",
                                               "source_ip", "ref_id")},
            "steps": run["steps"], "total_steps": len(((run.get("recipe") or {})
                                                        .get("flat") or {}).get("steps") or []),
            "created_at": run["created_at"], "finished_at": run["finished_at"],
        }

    # --- Playbooks ---------------------------------------------------------

    @app.get("/api/playbooks")
    def list_playbooks(user_id: int = Depends(require_manager)):
        org = org_of(user_id)
        counts = store.run_counts_by_playbook(db(), org)
        return {"playbooks": [summarize(pb, counts) for pb in store.list_playbooks(db(), org)]}

    @app.get("/api/playbooks/templates")
    def list_templates(user_id: int = Depends(require_manager)):
        return {"templates": [{"key": t["key"], "name": t["recipe"]["name"],
                               "summary": t["summary"], "recipe": t["recipe"]}
                              for t in templates.TEMPLATES]}

    @app.get("/api/playbooks/builder")
    def builder_schema(user_id: int = Depends(require_manager)):
        """Vocabulary for the click-together builder (condition kinds,
        connectors + their inputs, placeholders). Registered before
        /api/playbooks/{id} so "builder" isn't read as an id."""
        from . import builder
        return builder.schema()

    @app.post("/api/playbooks/validate")
    async def validate_playbook(request: Request, user_id: int = Depends(require_admin)):
        rate_limit.hit(request, "playbook_validate", window_sec=60, max_hits=60)
        clean, flat = await read_recipe(request)
        return {"ok": True, "name": clean["name"],
                "steps": len(flat["steps"]),
                "approval_steps": sum(1 for s in flat["steps"] if s["requires_approval"])}

    @app.post("/api/playbooks")
    async def create_playbook(request: Request, user_id: int = Depends(require_admin)):
        rate_limit.hit(request, "playbook_create", window_sec=3600, max_hits=200)
        raw = await request.body()
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            raise HTTPException(400, detail="Invalid JSON body.")
        origin = "import"
        if isinstance(body, dict) and body.get("template"):
            t = templates.get(body["template"])
            if not t:
                raise HTTPException(404, detail="No such template.")
            clean, _ = recipe_mod.normalize(t["recipe"])
            origin = f"template:{t['key']}"
        else:
            clean, _ = await read_recipe(request)
        org = org_of(user_id)
        pid = store.create_playbook(db(), org, clean, created_by=user_id, origin=origin)
        audit("playbook_create", user_id, comment=f"playbook:{pid}",
              detail=f"name={clean['name']!r} origin={origin} enabled={clean['enabled']}")
        return summarize(store.get_playbook(db(), org, pid))

    @app.get("/api/playbooks/{playbook_id}")
    def get_playbook(playbook_id: int, user_id: int = Depends(require_manager)):
        pb = store.get_playbook(db(), org_of(user_id), playbook_id)
        if not pb:
            raise HTTPException(404, detail="Playbook not found.")
        return dict(summarize(pb), recipe=pb["recipe"])

    @app.put("/api/playbooks/{playbook_id}")
    async def update_playbook(playbook_id: int, request: Request,
                              user_id: int = Depends(require_admin)):
        org = org_of(user_id)
        if not store.get_playbook(db(), org, playbook_id):
            raise HTTPException(404, detail="Playbook not found.")
        clean, _ = await read_recipe(request)
        store.update_playbook(db(), org, playbook_id, clean)
        audit("playbook_update", user_id, comment=f"playbook:{playbook_id}",
              detail=f"name={clean['name']!r}")
        return summarize(store.get_playbook(db(), org, playbook_id))

    @app.put("/api/playbooks/{playbook_id}/enabled")
    async def toggle_playbook(playbook_id: int, request: Request,
                              user_id: int = Depends(require_admin)):
        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
            raise HTTPException(400, detail="Body must be {\"enabled\": true|false}.")
        if not store.set_playbook_enabled(db(), org_of(user_id), playbook_id, body["enabled"]):
            raise HTTPException(404, detail="Playbook not found.")
        audit("playbook_enable" if body["enabled"] else "playbook_disable", user_id,
              comment=f"playbook:{playbook_id}")
        return {"status": "ok", "id": playbook_id, "enabled": body["enabled"]}

    @app.delete("/api/playbooks/{playbook_id}")
    def delete_playbook(playbook_id: int, user_id: int = Depends(require_admin)):
        org = org_of(user_id)
        pb = store.get_playbook(db(), org, playbook_id)
        if not pb or not store.delete_playbook(db(), org, playbook_id):
            raise HTTPException(404, detail="Playbook not found.")
        audit("playbook_delete", user_id, comment=f"playbook:{playbook_id}",
              detail=f"name={pb['name']!r}")
        return {"status": "ok", "id": playbook_id}

    # --- Runs -------------------------------------------------------------

    @app.get("/api/playbook-runs")
    def list_runs(status: str = None, playbook_id: int = None, limit: int = 50,
                  user_id: int = Depends(require_manager)):
        if limit < 1 or limit > 200:
            raise HTTPException(400, detail="limit must be between 1 and 200.")
        runs = store.list_runs(db(), org_of(user_id), status=status,
                               playbook_id=playbook_id, limit=limit)
        return {"runs": [public_run(r) for r in runs]}

    @app.get("/api/playbook-runs/{run_id}")
    def get_run(run_id: int, user_id: int = Depends(require_manager)):
        run = store.get_run(db(), org_of(user_id), run_id)
        if not run:
            raise HTTPException(404, detail="Run not found.")
        return public_run(run)

    @app.get("/api/findings/{finding_id}/playbook-runs")
    def finding_runs(finding_id: int, user_id: int = Depends(require_login)):
        check_finding_scope(finding_id, user_id)
        runs = store.list_runs(db(), org_of(user_id), finding_id=finding_id, limit=20)
        return {"runs": [public_run(r) for r in runs]}

    @app.post("/api/playbook-runs/{run_id}/approve")
    async def approve_run(run_id: int, request: Request,
                          user_id: int = Depends(require_manager)):
        require_elevation(request, user_id)   # PIN step-up
        org = org_of(user_id)
        if not store.get_run(db(), org, run_id):
            raise HTTPException(404, detail="Run not found.")
        try:
            run = await asyncio.to_thread(engine.approve, db(), org, run_id,
                                          email_of(user_id), pulse_config())
        except engine.ApprovalError as e:
            raise HTTPException(409, detail=str(e))
        return public_run(run)

    @app.post("/api/playbook-runs/{run_id}/deny")
    def deny_run(run_id: int, user_id: int = Depends(require_manager)):
        org = org_of(user_id)
        if not store.get_run(db(), org, run_id):
            raise HTTPException(404, detail="Run not found.")
        try:
            run = engine.deny(db(), org, run_id, email_of(user_id))
        except engine.ApprovalError as e:
            raise HTTPException(409, detail=str(e))
        return public_run(run)

    # --- Connectors -------------------------------------------------------

    @app.get("/api/connectors")
    def list_connectors(user_id: int = Depends(require_manager)):
        states = store.connector_states(db(), org_of(user_id))
        cfg = pulse_config()
        return {"connectors": [{
            "key": c.key, "name": c.name, "kind": c.kind, "actions": c.actions(),
            "enabled": states.get(c.key, True),
            "configured": bool(c.health_check(connectors.config_for(c, cfg))),
        } for c in connectors.all_connectors()]}

    @app.put("/api/connectors/{key}")
    async def toggle_connector(key: str, request: Request,
                               user_id: int = Depends(require_admin)):
        if connectors.get(key) is None:
            raise HTTPException(404, detail="Unknown connector.")
        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get("enabled"), bool):
            raise HTTPException(400, detail="Body must be {\"enabled\": true|false}.")
        store.set_connector_enabled(db(), org_of(user_id), key, body["enabled"],
                                    updated_by=user_id or None)
        audit("connector_enable" if body["enabled"] else "connector_disable", user_id,
              detail=f"connector={key}")
        return {"status": "ok", "key": key, "enabled": body["enabled"]}


def _valid(recipe):
    try:
        recipe_mod.normalize(recipe)
        return True
    except recipe_mod.RecipeError:
        return False
