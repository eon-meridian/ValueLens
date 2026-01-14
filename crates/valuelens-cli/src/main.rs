use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use chrono::NaiveDate;
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;
use serde::Deserialize;
use std::{collections::{BTreeMap, HashMap}, fs, path::Path};
use walkdir::WalkDir;

use valuelens_core::{to_sarif, Evidence, Finding, Report, Severity, WaiverInfo};

const MAX_MATCHES_PER_FILE_RULE: usize = 1;   // default dedup: 1 per (rule,file)
const MAX_FINDINGS_PER_RULE: usize = 200;     // noise budget per rule across repo
const MAX_SNIPPET_CHARS: usize = 240;

#[derive(Parser)]
#[command(name="valuelens", version="0.1.0", about="ValueLens: value transparency for CI/CD")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a repository and emit findings (JSON/MD/SARIF).
    Scan {
        #[arg(default_value = ".")]
        path: String,

        #[arg(long, default_value = "rules/default.yml")]
        rules: String,

        /// Comma-separated: json,md,sarif
        #[arg(long, default_value = "json,md,sarif")]
        format: String,

        #[arg(long, default_value = "valuelens")]
        out_prefix: String,

        /// Fail the command if any (non-waived) finding meets or exceeds this severity.
        #[arg(long, default_value = "high")]
        fail_on: String,

        /// Ignore findings below this confidence for gating.
        #[arg(long, default_value_t = 0.70)]
        confidence_threshold: f32,

        /// Optional waivers file. Waived findings do not gate builds until waiver expires.
        #[arg(long, default_value = "valuelens_waivers.yml")]
        waivers: String,
    },

    /// Compare two JSON reports and output a drift summary.
    Drift {
        /// Path to baseline report JSON (often last main build artifact)
        #[arg(long)]
        baseline: String,

        /// Path to current report JSON
        #[arg(long)]
        current: String,

        /// Output format: md or json
        #[arg(long, default_value = "md")]
        format: String,

        /// Output file prefix (e.g., valuelens-drift -> valuelens-drift.md)
        #[arg(long, default_value = "valuelens-drift")]
        out_prefix: String,
    }
}

#[derive(Debug, Deserialize)]
struct RulePack {
    rules: Vec<RegexRule>,
}

#[derive(Debug, Deserialize)]
struct RegexRule {
    id: String,
    title: String,
    description: String,
    severity: String,
    confidence: f32,
    globs: Vec<String>,
    pattern: String,
    axes: HashMap<String, f32>,
}

struct CompiledRule {
    id: String,
    title: String,
    description: String,
    severity: Severity,
    confidence: f32,
    axes: Vec<(String, f32)>,
    globset: GlobSet,
    regex: Regex,
}

#[derive(Debug, Deserialize)]
struct WaiversFile {
    waivers: Vec<Waiver>,
}

#[derive(Debug, Deserialize, Clone)]
struct Waiver {
    rule_id: String,
    owner: String,
    justification: String,
    expires: NaiveDate, // YYYY-MM-DD
}

#[derive(Clone)]
enum WaiverStatus {
    Active(Waiver),
    Expired(Waiver),
}

fn load_waivers(path: &str) -> Result<Vec<Waiver>> {
    if !std::path::Path::new(path).exists() {
        return Ok(vec![]);
    }
    let s = fs::read_to_string(path).with_context(|| format!("reading waivers {}", path))?;
    let w: WaiversFile = serde_yaml::from_str(&s).with_context(|| "parsing waivers YAML")?;
    Ok(w.waivers)
}

fn index_waivers(waivers: &[Waiver]) -> BTreeMap<String, Vec<Waiver>> {
    let mut m: BTreeMap<String, Vec<Waiver>> = BTreeMap::new();
    for w in waivers {
        m.entry(w.rule_id.clone()).or_default().push(w.clone());
    }
    m
}

fn waiver_status_for(rule_id: &str, waiver_index: &BTreeMap<String, Vec<Waiver>>) -> Option<WaiverStatus> {
    let today = chrono::Utc::now().date_naive();
    let ws = waiver_index.get(rule_id)?;

    // First look for any active waiver
    for w in ws {
        if w.expires >= today {
            return Some(WaiverStatus::Active(w.clone()));
        }
    }

    // Otherwise return the most recent expired waiver if any exist
    let mut sorted = ws.clone();
    sorted.sort_by_key(|w| w.expires);
    sorted.last().cloned().map(WaiverStatus::Expired)
}

fn compile_rule(r: &RegexRule) -> Result<CompiledRule> {
    let severity = Severity::from_str(&r.severity)
        .with_context(|| format!("invalid severity '{}' for rule {}", r.severity, r.id))?;

    let mut b = GlobSetBuilder::new();
    for g in &r.globs {
        b.add(Glob::new(g).with_context(|| format!("invalid glob '{}' in {}", g, r.id))?);
    }
    let globset = b.build()?;

    let regex = Regex::new(&r.pattern).with_context(|| format!("invalid regex in {}", r.id))?;

    Ok(CompiledRule {
        id: r.id.clone(),
        title: r.title.clone(),
        description: r.description.clone(),
        severity,
        confidence: r.confidence,
        axes: r.axes.iter().map(|(k, v)| (k.clone(), *v)).collect(),
        globset,
        regex,
    })
}

fn should_skip(path: &str) -> bool {
    let p = path.replace('\\', "/");
    p.contains("/target/")
        || p.contains("/.git/")
        || p.contains("/node_modules/")
        || p.contains("/dist/")
        || p.contains("/build/")
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            rules,
            format,
            out_prefix,
            fail_on,
            confidence_threshold,
            waivers,
        } => {
            let pack_str = fs::read_to_string(&rules).with_context(|| format!("reading {}", rules))?;
            let pack: RulePack = serde_yaml::from_str(&pack_str).with_context(|| "parsing rules YAML")?;
            let compiled: Vec<CompiledRule> = pack.rules.iter().map(compile_rule).collect::<Result<_>>()?;

            let waiver_list = load_waivers(&waivers)?;
            let waiver_index = index_waivers(&waiver_list);

            let mut report = Report {
                tool: "valuelens".to_string(),
                version: "0.1.0".to_string(),
                generated_at: chrono::Utc::now(),
                target: path.clone(),
                findings: vec![],
            };

            report.findings = scan_path(&path, &compiled, &waiver_index)?;

            write_outputs(&report, &format, &out_prefix)?;

            gate(&report, &fail_on, confidence_threshold)?;
        }

        Commands::Drift { baseline, current, format, out_prefix } => {
            let b: Report = serde_json::from_str(&fs::read_to_string(&baseline).context("read baseline")?)?;
            let c: Report = serde_json::from_str(&fs::read_to_string(&current).context("read current")?)?;

            let drift = compute_drift(&b, &c);

            if format.to_lowercase() == "json" {
                let p = format!("{}.json", out_prefix);
                fs::write(&p, serde_json::to_string_pretty(&drift)?)?;
                eprintln!("wrote {}", p);
            } else {
                let p = format!("{}.md", out_prefix);
                fs::write(&p, render_drift_markdown(&drift))?;
                eprintln!("wrote {}", p);
            }
        }
    }

    Ok(())
}

fn scan_path(root: &str, rules: &[CompiledRule], waiver_index: &BTreeMap<String, Vec<Waiver>>) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();
    let mut per_rule_count: HashMap<String, usize> = HashMap::new();

    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let full_path = entry.path().to_string_lossy().replace('\\', "/");
        if should_skip(&full_path) {
            continue;
        }

        let rel = pathdiff::diff_paths(entry.path(), Path::new(root))
            .unwrap_or_else(|| entry.path().to_path_buf())
            .to_string_lossy()
            .replace('\\', "/");

        let content = match fs::read_to_string(entry.path()) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for rule in rules {
            if !rule.globset.is_match(&rel) {
                continue;
            }

            let c = per_rule_count.entry(rule.id.clone()).or_insert(0);
            if *c >= MAX_FINDINGS_PER_RULE {
                continue;
            }

            let mut emitted = 0usize;
            for m in rule.regex.find_iter(&content) {
                let line = content[..m.start()].lines().count() as u32 + 1;
                let snippet = content
                    .lines()
                    .nth((line.saturating_sub(1)) as usize)
                    .map(|s| {
                        let mut t = s.trim().to_string();
                        if t.len() > MAX_SNIPPET_CHARS {
                            t.truncate(MAX_SNIPPET_CHARS);
                            t.push_str("…");
                        }
                        t
                    });

                let waived = match waiver_status_for(&rule.id, waiver_index) {
                    Some(WaiverStatus::Active(w)) => Some(WaiverInfo {
                        owner: w.owner,
                        justification: w.justification,
                        expires: w.expires.to_string(),
                        status: "active".to_string(),
                    }),
                    Some(WaiverStatus::Expired(w)) => Some(WaiverInfo {
                        owner: w.owner,
                        justification: w.justification,
                        expires: w.expires.to_string(),
                        status: "expired".to_string(),
                    }),
                    None => None,
                };

                findings.push(Finding {
                    rule_id: rule.id.clone(),
                    title: rule.title.clone(),
                    description: rule.description.clone(),
                    severity: rule.severity,
                    confidence: rule.confidence,
                    axes: rule.axes.clone(),
                    evidence: vec![Evidence {
                        file: rel.clone(),
                        line: Some(line),
                        snippet,
                    }],
                    waived,
                });

                *c += 1;
                emitted += 1;

                if emitted >= MAX_MATCHES_PER_FILE_RULE || *c >= MAX_FINDINGS_PER_RULE {
                    break;
                }
            }
        }
    }

    Ok(findings)
}

fn write_outputs(report: &Report, format: &str, out_prefix: &str) -> Result<()> {
    let formats: Vec<&str> = format
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if formats.contains(&"json") {
        let p = format!("{}.json", out_prefix);
        fs::write(&p, serde_json::to_string_pretty(report)?)?;
        eprintln!("wrote {}", p);
    }

    if formats.contains(&"md") {
        let p = format!("{}.md", out_prefix);
        fs::write(&p, render_markdown(report))?;
        eprintln!("wrote {}", p);
    }

    if formats.contains(&"sarif") {
        let p = format!("{}.sarif", out_prefix);
        let sarif = to_sarif(report);
        fs::write(&p, serde_json::to_string_pretty(&sarif)?)?;
        eprintln!("wrote {}", p);
    }

    Ok(())
}

fn gate(report: &Report, fail_on: &str, confidence_threshold: f32) -> Result<()> {
    let gate_rank = Severity::from_str(fail_on).unwrap_or(Severity::High).rank();

    let violates = report.findings.iter().any(|f| {
        // Don't gate on active waivers
        if f.waived.as_ref().map(|w| w.status.as_str()) == Some("active") {
            return false;
        }
        f.confidence >= confidence_threshold && f.severity.rank() >= gate_rank
    });

    if violates {
        anyhow::bail!(
            "ValueLens gate failed (fail_on={}, confidence>={})",
            fail_on,
            confidence_threshold
        );
    }
    Ok(())
}

fn render_markdown(report: &Report) -> String {
    let mut s = String::new();
    s.push_str("# ValueLens Report\n\n");
    s.push_str(&format!(
        "- Target: `{}`\n- Generated: `{}`\n- Findings: `{}`\n\n",
        report.target, report.generated_at, report.findings.len()
    ));

    // Axis summary (rough): sum axis weights * confidence
    use std::collections::BTreeMap;
    let mut axis_totals: BTreeMap<String, f32> = BTreeMap::new();
    for f in &report.findings {
        for (k, v) in &f.axes {
            *axis_totals.entry(k.clone()).or_insert(0.0) += *v * f.confidence;
        }
    }
    if !axis_totals.is_empty() {
        s.push_str("## Axis signal totals (rough)\n\n");
        for (k, v) in axis_totals {
            s.push_str(&format!("- `{}`: `{:+.2}`\n", k, v));
        }
        s.push('\n');
    }

    // Group by rule_id
    let mut by_rule: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for f in &report.findings {
        by_rule.entry(f.rule_id.clone()).or_default().push(f);
    }

    s.push_str("## Findings\n\n");
    for (rule_id, fs_) in by_rule {
        let title = fs_.first().map(|f| f.title.clone()).unwrap_or_default();
        s.push_str(&format!("### {} — {}\n\n", rule_id, title));

        for f in fs_ {
            s.push_str(&format!("- Severity: `{:?}`\n- Confidence: `{:.2}`\n", f.severity, f.confidence));

            if let Some(w) = &f.waived {
                if w.status == "active" {
                    s.push_str(&format!("- Waiver: ✅ active (owner `{}`, expires `{}`)\n- Waiver reason: {}\n", w.owner, w.expires, w.justification));
                } else {
                    s.push_str(&format!("- Waiver: ⚠️ expired (owner `{}`, expired `{}`)\n- Waiver reason: {}\n", w.owner, w.expires, w.justification));
                }
            }

            if !f.axes.is_empty() {
                s.push_str("- Axes:\n");
                for (k, v) in &f.axes {
                    s.push_str(&format!("  - `{}`: `{:+.2}`\n", k, v));
                }
            }
            s.push('\n');
            s.push_str(&format!("{}\n\n", f.description));

            s.push_str("**Evidence**\n");
            for e in &f.evidence {
                s.push_str(&format!("- `{}`", e.file));
                if let Some(line) = e.line {
                    s.push_str(&format!(":{}", line));
                }
                s.push('\n');
                if let Some(sn) = &e.snippet {
                    s.push_str(&format!("  - `{}`\n", sn.replace('`', "\\`")));
                }
            }
            s.push('\n');
        }
    }

    s
}

// ===== Drift mode =====

#[derive(serde::Serialize)]
struct DriftSummary {
    baseline_generated_at: String,
    current_generated_at: String,
    new_findings: Vec<String>,
    resolved_findings: Vec<String>,
    axis_delta: BTreeMap<String, f32>,
}

fn finding_key(f: &Finding) -> String {
    // Stable-ish key: rule_id + file + line
    let (file, line) = f.evidence.first().map(|e| (e.file.clone(), e.line.unwrap_or(0))).unwrap_or(("".into(), 0));
    format!("{}|{}|{}", f.rule_id, file, line)
}

fn axis_totals(report: &Report) -> BTreeMap<String, f32> {
    let mut m: BTreeMap<String, f32> = BTreeMap::new();
    for f in &report.findings {
        for (k, v) in &f.axes {
            *m.entry(k.clone()).or_insert(0.0) += *v * f.confidence;
        }
    }
    m
}

fn compute_drift(baseline: &Report, current: &Report) -> DriftSummary {
    use std::collections::BTreeSet;

    let bset: BTreeSet<String> = baseline.findings.iter().map(finding_key).collect();
    let cset: BTreeSet<String> = current.findings.iter().map(finding_key).collect();

    let new_findings: Vec<String> = cset.difference(&bset).cloned().collect();
    let resolved_findings: Vec<String> = bset.difference(&cset).cloned().collect();

    let bt = axis_totals(baseline);
    let ct = axis_totals(current);

    let mut keys: BTreeSet<String> = BTreeSet::new();
    keys.extend(bt.keys().cloned());
    keys.extend(ct.keys().cloned());

    let mut axis_delta: BTreeMap<String, f32> = BTreeMap::new();
    for k in keys {
        let dv = ct.get(&k).cloned().unwrap_or(0.0) - bt.get(&k).cloned().unwrap_or(0.0);
        if dv.abs() > 0.001 {
            axis_delta.insert(k, dv);
        }
    }

    DriftSummary {
        baseline_generated_at: baseline.generated_at.to_string(),
        current_generated_at: current.generated_at.to_string(),
        new_findings,
        resolved_findings,
        axis_delta,
    }
}

fn render_drift_markdown(d: &DriftSummary) -> String {
    let mut s = String::new();
    s.push_str("# ValueLens Drift Report\n\n");
    s.push_str(&format!("- Baseline: `{}`\n- Current: `{}`\n\n", d.baseline_generated_at, d.current_generated_at));

    s.push_str("## Axis deltas (current - baseline)\n\n");
    if d.axis_delta.is_empty() {
        s.push_str("- (none)\n\n");
    } else {
        for (k, v) in &d.axis_delta {
            s.push_str(&format!("- `{}`: `{:+.2}`\n", k, v));
        }
        s.push('\n');
    }

    s.push_str(&format!("## New findings ({})\n\n", d.new_findings.len()));
    if d.new_findings.is_empty() {
        s.push_str("- (none)\n\n");
    } else {
        for k in d.new_findings.iter().take(200) {
            s.push_str(&format!("- `{}`\n", k));
        }
        s.push('\n');
    }

    s.push_str(&format!("## Resolved findings ({})\n\n", d.resolved_findings.len()));
    if d.resolved_findings.is_empty() {
        s.push_str("- (none)\n\n");
    } else {
        for k in d.resolved_findings.iter().take(200) {
            s.push_str(&format!("- `{}`\n", k));
        }
        s.push('\n');
    }

    s
}
