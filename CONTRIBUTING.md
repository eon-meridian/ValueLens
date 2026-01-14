# Contributing to ValueLens

Thanks for helping build value transparency into software delivery.

## Principles
- **Evidence first**: findings must cite concrete code/config evidence.
- **Deterministic by default**: CI output should be reproducible.
- **Non-moralizing language**: describe signals and tradeoffs, not virtue.
- **Noise discipline**: avoid spammy results.

## Dev setup
```bash
cargo fmt
cargo clippy --all-targets --all-features
cargo test
```

## Adding a rule
Rules live in `rules/*.yml`.

Each rule should:
- have a stable `id`
- specify file `globs`
- include a regex `pattern`
- map to 1–3 axes with weights

## Reporting bugs
Please include:
- the rule id(s)
- the file(s) that triggered the finding
- a minimal repro snippet
