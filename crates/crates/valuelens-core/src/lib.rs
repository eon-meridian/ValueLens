use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Severity { Info, Low, Medium, High, Critical }

impl Severity {
    pub fn rank(self) -> u8 {
        match self { Self::Info=>0, Self::Low=>1, Self::Medium=>2, Self::High=>3, Self::Critical=>4 }
    }
    pub fn from_str(s:&str)->Option<Self>{
        match s.to_lowercase().as_str(){
            "info"=>Some(Self::Info),"low"=>Some(Self::Low),"medium"=>Some(Self::Medium),
            "high"=>Some(Self::High),"critical"=>Some(Self::Critical),_=>None
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence { pub file:String, pub line:Option<u32>, pub snippet:Option<String> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id:String, pub title:String, pub description:String,
    pub severity:Severity, pub confidence:f32, pub axes:Vec<(String,f32)>,
    pub evidence:Vec<Evidence>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub tool: String,
    pub version: String,
    pub generated_at: DateTime<Utc>,
    pub target: String,
    pub findings: Vec<Finding>,
    #[serde(default)]
    pub axis_totals: BTreeMap<String, f32>,
}

pub fn to_sarif(report:&Report)->serde_json::Value{
    serde_json::json!({
        "version":"2.1.0",
        "runs":[{
            "tool":{"driver":{"name":"valuelens","version":report.version}},
            "results": report.findings.iter().map(|f|{
                serde_json::json!({
                    "ruleId":f.rule_id,
                    "level": match f.severity {
                        Severity::High|Severity::Critical=>"error",
                        Severity::Medium=>"warning",
                        _=>"note"
                    },
                    "message":{"text":format!("{} ({:.2})",f.title,f.confidence)}
                })
            }).collect::<Vec<_>>()
        }]
    })
}
