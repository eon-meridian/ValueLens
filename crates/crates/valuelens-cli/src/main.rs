use clap::{Parser,Subcommand};
use anyhow::Result;
use std::{fs,collections::HashMap};
use regex::Regex;
use walkdir::WalkDir;
use globset::{Glob,GlobSetBuilder};
use serde::Deserialize;
use valuelens_core::*;

#[derive(Parser)]
struct Cli{ #[command(subcommand)] cmd:Cmd }

#[derive(Subcommand)]
enum Cmd{
    Scan{
        #[arg(default_value=".")] path:String,
        #[arg(long,default_value="rules/default.yml")] rules:String
    }
}

#[derive(Deserialize)]
struct RulePack{ rules:Vec<Rule> }

#[derive(Deserialize)]
struct Rule{
    id:String,title:String,description:String,severity:String,confidence:f32,
    globs:Vec<String>,pattern:String,axes:HashMap<String,f32>
}

fn main()->Result<()>{
    let cli=Cli::parse();
    match cli.cmd{
        Cmd::Scan{path,rules}=>{
            let pack:RulePack=serde_yaml::from_str(&fs::read_to_string(rules)?)?;
            let mut findings=vec![];
            for r in pack.rules{
                let mut gb=GlobSetBuilder::new();
                for g in r.globs{ gb.add(Glob::new(&g)?); }
                let gs=gb.build()?;
                let re=Regex::new(&r.pattern)?;
                for e in WalkDir::new(&path).into_iter().filter_map(|e|e.ok()){
                    if !e.file_type().is_file(){continue;}
                    let p=e.path().to_string_lossy().to_string();
                    if !gs.is_match(&p){continue;}
                    let c=fs::read_to_string(e.path()).unwrap_or_default();
                    if let Some(m)=re.find(&c){
                        let line=c[..m.start()].lines().count() as u32 + 1;
                        findings.push(Finding{
                            rule_id:r.id.clone(),title:r.title.clone(),
                            description:r.description.clone(),
                            severity:Severity::from_str(&r.severity).unwrap(),
                            confidence:r.confidence,
                            axes:r.axes.iter().map(|(k,v)|(k.clone(),*v)).collect(),
                            evidence:vec![Evidence{file:p,line:Some(line),snippet:None}]
                        });
                    }
                }
            }
            let mut rep = Report{
                tool:"valuelens".into(),
                version:"0.1.0".into(),
                generated_at:chrono::Utc::now(),
                target:path,
                findings,
                axis_totals: std::collections::BTreeMap::new(),
            };

            // Axis aggregation: sum(axis_weight * confidence) across findings
            for f in &rep.findings {
                for (k, v) in &f.axes {
                    let entry = rep.axis_totals.entry(k.clone()).or_insert(0.0);
                    *entry += (*v) * f.confidence;
                }
            }
            fs::write("valuelens.json",serde_json::to_string_pretty(&rep)?)?;
            fs::write("valuelens.sarif",serde_json::to_string_pretty(&to_sarif(&rep))?)?;
            fs::write("valuelens.md", render_markdown(&rep))?;
            println!("wrote valuelens.json, valuelens.md, and valuelens.sarif");
        }
    }
    Ok(())
}
fn render_markdown(rep: &Report) -> String {
    let mut s = String::new();
    s.push_str("# ValueLens Report\n\n");
    s.push_str(&format!("- Target: `{}`\n- Generated: `{}`\n- Findings: `{}`\n\n",
        rep.target, rep.generated_at, rep.findings.len()
    ));

    s.push_str("## Axis summary (confidence-weighted)\n\n");
    if rep.axis_totals.is_empty() {
        s.push_str("- (none)\n\n");
    } else {
        // sort by absolute magnitude descending
        let mut items: Vec<(&String, &f32)> = rep.axis_totals.iter().collect();
        items.sort_by(|a,b| b.1.abs().partial_cmp(&a.1.abs()).unwrap_or(std::cmp::Ordering::Equal));
        for (k,v) in items {
            s.push_str(&format!("- `{}`: `{:+.2}`\n", k, v));
        }
        s.push('\n');
    }

    s.push_str("## Findings\n\n");
    for f in &rep.findings {
        s.push_str(&format!("### {} — {}\n\n", f.rule_id, f.title));
        s.push_str(&format!("- Severity: `{:?}`\n- Confidence: `{:.2}`\n\n", f.severity, f.confidence));
        s.push_str(&format!("{}\n\n", f.description));
        s.push_str("**Axes**\n");
        if f.axes.is_empty() {
            s.push_str("- (none)\n");
        } else {
            for (k,v) in &f.axes {
                s.push_str(&format!("- `{}`: `{:+.2}`\n", k, v));
            }
        }
        s.push_str("\n**Evidence**\n");
        for e in &f.evidence {
            s.push_str(&format!("- `{}`", e.file));
            if let Some(line) = e.line { s.push_str(&format!(":{}", line)); }
            s.push('\n');
            if let Some(sn) = &e.snippet {
                s.push_str(&format!("  - `{}`\n", sn.replace('`', "\\`")));
            }
        }
        s.push('\n');
    }

    s
}
