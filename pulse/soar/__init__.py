# pulse/soar/ — playbook engine (SOAR phase 2).
#
#   recipe.py     validate + flatten a playbook's JSON recipe
#   expr.py       safe placeholders and `if` expressions (no eval)
#   engine.py     match findings, run steps, pause for approval
#   store.py      playbooks / playbook_runs / connectors_config tables
#   templates.py  built-in example playbooks
#
# See docs/2026-09-26-soar-playbooks-and-integrations.md.
