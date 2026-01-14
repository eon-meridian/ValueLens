use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "info" => Some(Severity::Info),
            "low" => Some(Severity::Low),
            "medium" => Some(Severity::Medium),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub file: String,
    pub line: Option<u32>,
    pub snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f32, // 0..1
    pub axes: Vec<(String, f32)>,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub waived: Option<WaiverInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WaiverInfo {
    pub owner: String,
    pub justification: String,
    pub expires: String, // YYYY-MM-DD
    pub status: String,  // "active" | "expired"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub target: String,
    pub findings: Vec<Finding>,
}

/// Minimal SARIF 2.1.0 for GitHub code scanning.
/// Emits one SARIF result per finding using the first evidence location (file/line).
pub fn to_sarif(report: &Report) -> serde_json::Value {
    let mut rules = Vec::new();
    let mut results = Vec::new();

    for f in &report.findings {
        rules.push(serde_json::json!({
            "id": f.rule_id,
            "name": f.title,
            "shortDescription": { "text": f.title },
            "fullDescription": { "text": f.description },
            "properties": {
                "precision": (f.confidence * 100.0).round() as i64
            }
        }));

        let (file, line) = f
            .evidence
            .first()
            .map(|e| (e.file.clone(), e.line))
            .unwrap_or(("".into(), None));

        // GitHub treats "error"/"warning"/"note" levels specially in UI
        let level = match f.severity {
            Severity::Info => "note",
            Severity::Low => "note",
            Severity::Medium => "warning",
            Severity::High => "error",
            Severity::Critical => "error",
        };

        // If waived, downgrade to note to reduce PR noise but keep visibility
        let level = if f.waived.as_ref().map(|w| w.status.as_str()) == Some("active") {
            "note"
        } else {
            level
        };

        let loc = if !file.is_empty() {
            serde_json::json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": file },
                    "region": { "startLine": line.unwrap_or(1) }
                }
            })
        } else {
            serde_json::json!({})
        };

        let waived_suffix = if let Some(w) = &f.waived {
            format!(" [waiver: {} until {}]", w.status, w.expires)
        } else {
            "".to_string()
        };

        results.push(serde_json::json!({
            "ruleId": f.rule_id,
            "level": level,
            "message": { "text": format!("{} (confidence {:.2}){}", f.title, f.confidence, waived_suffix) },
            "locations": [ loc ]
        }));
    }

    serde_json::json!({
      "version": "2.1.0",
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "runs": [{
        "tool": { "driver": { "name": "valuelens", "version": report.version, "rules": rules } },
        "results": results
      }]
    })
}
