"""Pulse Agent command-line entry point.

Run as ``python -m pulse.agent <subcommand>``. Subcommands:

  enroll <server_url> <enrollment_token>
    Trade an enrollment token for a long-lived agent token. Writes
    the resulting bearer to the config file (default location under
    %PROGRAMDATA%/Pulse/agent.yaml on Windows).

  run
    Start the heartbeat + scan loop. Blocks until Ctrl+C / SIGTERM.

  status
    Print the current agent config (with the bearer redacted) so the
    operator can verify enrollment landed in the expected file.

The packaged ``pulse-agent.exe`` (Sprint 7 Phase B) is just a
PyInstaller wrapper that runs ``python -m pulse.agent`` with the
bundled interpreter.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Optional, Sequence

from pulse.agent.config import default_config_path, load_config, save_config
from pulse.agent.runtime import AgentRuntime, enroll
from pulse.agent.transport import TransportError


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pulse-agent", description=__doc__)
    p.add_argument(
        "--config",
        help=f"Path to agent.yaml (default: {default_config_path()})",
        default=None,
    )
    p.add_argument(
        "--verbose", "-v", action="count", default=0,
        help="Increase log verbosity. -v = INFO, -vv = DEBUG",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_enroll = sub.add_parser("enroll", help="Exchange enrollment token for agent token")
    p_enroll.add_argument("server_url", help="Pulse server, e.g. https://pulse.example.com")
    p_enroll.add_argument("enrollment_token", help="One-time `pe_…` token from Settings → Agents")
    p_enroll.add_argument("--name", default="", help="Display name (defaults to whatever the server has)")
    p_enroll.add_argument(
        "--insecure", action="store_true",
        help="Skip TLS verification (dev only — never use in production)",
    )

    sub.add_parser("run", help="Start the heartbeat + scan loop")
    sub.add_parser("status", help="Print current config + connectivity check")

    return p


def _setup_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1: level = logging.INFO
    elif verbose >= 2: level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _redact(token: str) -> str:
    """Show only the prefix + last-4 of a token in operator-facing
    output. ``pa_AAAAAAAA…XXXX`` instead of the raw value."""
    if not token: return ""
    if len(token) < 10: return "***"
    return token[:3] + "…" + token[-4:]


def cmd_enroll(args) -> int:
    cfg = load_config(args.config)
    if args.insecure:
        cfg.verify_tls = False
    try:
        cfg = enroll(
            cfg, args.server_url, args.enrollment_token,
            name=args.name, config_path=args.config,
        )
    except TransportError as exc:
        print(f"enroll failed: {exc}", file=sys.stderr)
        return 1
    path = save_config(cfg, args.config)
    print(f"enrolled as agent #{cfg.agent_id} ({cfg.name or 'unnamed'})")
    print(f"agent token: {_redact(cfg.agent_token)} (saved to {path})")
    return 0


def cmd_run(args) -> int:
    cfg = load_config(args.config)
    if not cfg.server_url or not cfg.agent_token:
        print("agent is not enrolled. Run `pulse-agent enroll` first.", file=sys.stderr)
        return 2
    runtime = AgentRuntime(cfg)
    runtime.run_forever()
    return 0


def cmd_status(args) -> int:
    cfg = load_config(args.config)
    print(f"config:  {args.config or default_config_path()}")
    print(f"server:  {cfg.server_url or '<not set>'}")
    print(f"agent:   #{cfg.agent_id or '?'} ({cfg.name or '<unnamed>'})")
    print(f"token:   {_redact(cfg.agent_token) or '<not set>'}")
    print(f"enrolled: {cfg.enrolled_at or '<not set>'}")
    print(f"scan_interval_sec:      {cfg.scan_interval_sec}")
    print(f"heartbeat_interval_sec: {cfg.heartbeat_interval_sec}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    handlers = {"enroll": cmd_enroll, "run": cmd_run, "status": cmd_status}
    fn = handlers.get(args.cmd)
    if not fn:
        print(f"unknown command: {args.cmd}", file=sys.stderr)
        return 2
    return fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
