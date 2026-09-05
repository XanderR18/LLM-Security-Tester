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

## Dataset: CICIDS2017
 
We're using CICIDS2017 (not NSL-KDD). Download it from the Kaggle mirror
(easier than UNB's gated form): https://www.kaggle.com/datasets/cicdataset/cicids2017
 
It comes as 8 CSVs, one per day/time-window (Monday–Friday, some days split
into morning/afternoon). Each row is a network *flow* (packet counts, byte
counts, duration, etc.) — there's no free-text field like a User-Agent or
filename, which is normally where an attacker would sneak injected text
into a real system.
 
**Workaround (documented for the Phase 5 report):** `prep_dataset.py`
converts each numeric row into a synthetic log line, e.g.:
 
> Connection from 192.168.1.5 to 10.0.0.9, protocol TCP, duration 4.20s,
> 12 fwd packets, flagged as PortScan.
 
...and appends one extra free-text `notes_field` (currently a bland
placeholder). **That field is the injection point for Phase 3** — the
attack harness will overwrite it per test case instead of touching the
synthesized log line itself.
 
### Running it
 
```bash
python prep_dataset.py --input data/CICIDS2017/data/CICIDS2017/GeneratedLabelledFlows/*.csv --output results/cicids_combined.csv --sample 500
```
 
- `--sample N` caps the output to N rows (CICIDS2017 has ~2.8M rows total — you don't want to send all of that to an LLM one-by-one)
- Handles both CICIDS2017 CSV variants: some releases include Source/Destination IP columns, the anonymized "MachineLearningCVE" release doesn't. The script falls back to synthetic placeholder IPs when they're missing and prints a warning when it does.

## How this fits the bigger project

| Phase | Owner | What it needs from Phase 2 |
|---|---|---|
| 3 (attack framework) | Shared | Calls `classify_log()` with tampered log lines instead of clean ones |
| 4 (evaluation) | Cian | Runs this tool at scale, then again with a defended prompt, compares success rates |

Keep the interface (`classify_log(client, log_line)` returning
`{severity, explanation, raw_response}`) stable — Phase 3's harness will
import and call it directly rather than re-implementing API calls.
