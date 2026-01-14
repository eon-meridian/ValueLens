# ValueLens

**ValueLens** is a CI-native linter that makes the *values implied by a codebase* visible, inspectable, and discussable. 

It does **not** claim to decide what’s right. It surfaces **evidence-backed signals** (power, privacy, accountability, optimization pressure, user agency) so teams can reason about risk and alignment.

## What you get
- A deterministic scan (`valuelens scan .`)
- Structured findings with evidence (file + line + snippet)
- Value *axes* summary (rough, confidence-weighted)
- Outputs for CI:
  - `valuelens.json` (canonical)
  - `valuelens.md` (human report)
  - `valuelens.sarif` (GitHub code scanning)

## Quick start

### Build
```bash
cargo build -p valuelens --release
```

### Scan a repo
```bash
./target/release/valuelens scan . \
  --rules rules/default.yml \
  --format json,md,sarif \
  --out-prefix valuelens \
  --fail-on high \
  --confidence-threshold 0.7
```

### Waivers (adoption-safe)
Create `valuelens_waivers.yml`:
```yaml
waivers:
  - rule_id: VL-TRACK-001
    owner: platform-team
    justification: "Telemetry required for incident response; redaction work in progress."
    expires: 2026-03-01
```

Active waivers:
- do **not** gate builds
- remain visible in reports (and downgrade SARIF level to `note`)

## Drift mode
Compare two reports:
```bash
./target/release/valuelens drift --baseline baseline.json --current valuelens.json --format md --out-prefix valuelens-drift
```


## Declared values + contradictions
Create a `valuelens.yml` to declare acceptable axis ranges. ValueLens will report **aligned / drift / contradiction**.

Example:
```yaml
axis_max:
  privacy: 0.50
axis_min:
  accountability: 0.20
```
After running, inspect:
- `valuelens.json`
- `valuelens.md` (includes axis summary)
- `valuelens.sarif`


## Wavers
Identify the rules you want to wave: jq -r '.findings[]
  | select((.severity=="High" or .severity=="Critical") and (.confidence >= 0.7))
  | .rule_id' valuelens.json | sort -u

Add to valuelens_wavers.yml

## Rules
Rules are YAML-defined regex checks with file globs. See `rules/default.yml`.

## License
GNU GENERAL PUBLIC LICENSE
