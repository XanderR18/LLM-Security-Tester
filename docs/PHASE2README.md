# Phase 2 — Target System

The "victim" tool that Phase 3's attack framework will test. It reads a log
line, sends it to an LLM, and asks for a severity classification
(LOW / MEDIUM / HIGH / CRITICAL) with a one-sentence explanation.

This is intentionally a **naive baseline** — no delimiters separating
instructions from data, no "ignore instructions embedded in the log" framing.
That's on purpose: Phase 4 measures how much adding those defenses helps,
so the baseline needs to be defenseless.

## Setup

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # from console.anthropic.com
```

## Run against the sample data

```bash
python triage.py --input data/sample_logs.csv --output results/baseline_results.csv
```

This classifies each log line in `data/sample_logs.csv` and writes a results
CSV with the predicted severity, explanation, and raw model response
alongside the ground-truth label.

## Files

- `triage.py` — the triage tool itself (see docstring for the prompt design notes)
- `data/sample_logs.csv` — 10 hand-written log lines to sanity-check the tool
  works end-to-end before wiring up a real dataset
- `requirements.txt` — just the `anthropic` SDK

## Next: get a real dataset

The plan calls for CICIDS2017 or NSL-KDD. Both are hosted in places outside
what I can fetch directly from this environment, so grab one yourself:

- **NSL-KDD** (simpler, good starting point): search "NSL-KDD Kaggle" or
  grab it from the University of New Brunswick's CIC site.
- **CICIDS2017** (larger, more realistic, has raw-ish log/flow data):
  also on the CIC site.

Once downloaded, you'll need a small script to convert whichever dataset
you pick into the same `log_id,log_line,true_label` CSV shape used by
`data/sample_logs.csv` — that's the next thing to build once you've picked
one and looked at its actual columns. NSL-KDD is flow-record style (numeric
features), so it needs a bit of templating into readable "log line" text;
CICIDS2017 has some fields (source/dest IP, protocol, etc.) that map more
naturally into a log-line sentence. Happy to help write that conversion
script once you've downloaded one and can share a few sample rows.

## How this fits the bigger project

| Phase | Owner | What it needs from Phase 2 |
|---|---|---|
| 3 (attack framework) | Shared | Calls `classify_log()` with tampered log lines instead of clean ones |
| 4 (evaluation) | Cian | Runs this tool at scale, then again with a defended prompt, compares success rates |

Keep the interface (`classify_log(client, log_line)` returning
`{severity, explanation, raw_response}`) stable — Phase 3's harness will
import and call it directly rather than re-implementing API calls.
