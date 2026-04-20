# Contributing to Pulse

Thanks for your interest in Pulse! This guide covers how to get set up, run the tests, and submit changes.

---

## Getting set up

Pulse is pure Python with no build step. You just need Python 3.8 or newer.

```bash
# Clone the repo
git clone https://github.com/barrytd/Pulse.git
cd Pulse

# Install dependencies
pip install -r requirements.txt

# Run a scan against sample logs to confirm it works
python main.py --logs logs/
```

---

## Running the tests

All tests live in [`tests/`](tests/) and use `pytest`. There are no fixtures or external services to mock — the tests build fake event dictionaries that mirror the shape of real `.evtx` data.

```bash
# Run every test in the suite
python -m pytest -q

# Run every detection test
python -m pytest tests/test_detections.py -v

# Run a single test
python -m pytest tests/test_detections.py::test_brute_force_flags_five_failures -v

# Run tests matching a keyword
python -m pytest tests/test_detections.py -k "baseline"
```

Every new detection rule must ship with tests. Every bug fix must include a test that fails before the fix and passes after.

---

## Code style

- Keep functions focused — one detection rule per function, one test case per test function
- Name things clearly — `detect_brute_force` not `check_bf`
- Write docstrings that explain **why**, not **what**. The code already says what it does
- Comments only when the *why* is non-obvious (a Windows quirk, a subtle threshold, a workaround)
- Don't reach for a new library unless there's no reasonable way to do it with the standard library

---

## Adding a detection rule

1. Pick an event ID Pulse does not already cover. Add it to `RELEVANT_EVENT_IDS` in `pulse/core/parser.py` so the fast path picks it up.
2. Write a `detect_*` function in `pulse/core/detections.py`. Follow the shape of the existing rules — each finding is a dict with `rule`, `severity`, and `details`.
3. Add the MITRE ATT&CK technique ID to `MITRE_ATTACK_IDS` in `pulse/reports/reporter.py`.
4. Add remediation steps to the remediation tab in `pulse/reports/reporter.py`.
5. Call your new function from `run_all_detections` at the bottom of `pulse/core/detections.py`.
6. Write at least three tests: one positive case (should fire), one negative (should not fire), and one edge case.
7. Add a row to the detection rules table in `README.md`.

---

## Submitting changes

1. Fork the repo and create a branch off `main`
2. Make your changes
3. Run the full test suite — every test must pass
4. Open a pull request with a clear title and a short description of **why** the change is needed
5. Link to any relevant Windows event documentation or MITRE technique pages

Small focused PRs are reviewed faster than large ones. If you're adding more than one feature, please split them.

---

## Questions

Open a GitHub issue — I'd rather answer the same question twice in public than miss someone who didn't ask.
