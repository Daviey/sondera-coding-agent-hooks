//! Sondera guardrail classifier benchmark.
//!
//! Loads a labeled corpus, runs the real IFC + Policy classifiers against it,
//! and records per-case accuracy, latency, and token usage. Outputs a JSON
//! results file and prints a summary table.
//!
//! Usage:
//!   sondera-benchmark --corpus benchmarks/corpus.jsonl --policies policies/
//!   SONDERA_PROVIDER=zai SONDERA_MODEL=glm-4.5-flash sondera-benchmark ...
//!
//! Environment is loaded from /etc/sondera/env then ~/.sondera/env, same as
//! the harness server. Override the model/provider with the usual SONDERA_*
//! variables to benchmark different configurations.

use anyhow::{Context, Result};
use chrono::Utc;
use clap::Parser;
use serde::{Deserialize, Serialize};
use sondera_information_flow_control::{DataModel, Label};
use sondera_policy::PolicyModel;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "sondera-benchmark")]
#[command(about = "Benchmark Sondera guardrail classifiers against a labeled corpus")]
struct Args {
    /// Path to the corpus file (JSONL, one test case per line).
    #[arg(long, default_value = "benchmarks/corpus.jsonl")]
    corpus: PathBuf,

    /// Path to the policy directory containing ifc.toml and policies.toml.
    #[arg(short, long, default_value = "policies")]
    policies: PathBuf,

    /// Output JSON results file path. Default: benchmarks/results-{timestamp}.json
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Label for this run (e.g. "glm-4.5-flash", "gemini-2.5-flash").
    #[arg(short, long)]
    label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CorpusEntry {
    id: String,
    category: String,
    content: String,
    expected_label: String,
    expected_compliant: bool,
    #[serde(default)]
    event_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CaseResult {
    id: String,
    category: String,
    content_preview: String,
    predicted_label: String,
    expected_label: String,
    label_correct: bool,
    predicted_compliant: bool,
    expected_compliant: bool,
    compliance_correct: bool,
    ifc_latency_ms: u64,
    policy_latency_ms: u64,
    ifc_error: Option<String>,
    policy_error: Option<String>,
}

#[derive(Debug, Serialize)]
struct BenchmarkReport {
    label: String,
    timestamp: String,
    total_cases: usize,
    label_accuracy: f64,
    compliance_accuracy: f64,
    both_correct: f64,
    false_positive_rate: f64,
    false_negative_rate: f64,
    avg_ifc_latency_ms: f64,
    avg_policy_latency_ms: f64,
    p95_ifc_latency_ms: u64,
    p95_policy_latency_ms: u64,
    per_category: Vec<CategoryReport>,
    cases: Vec<CaseResult>,
}

#[derive(Debug, Serialize)]
struct CategoryReport {
    category: String,
    count: usize,
    label_accuracy: f64,
    compliance_accuracy: f64,
    avg_ifc_latency_ms: f64,
    avg_policy_latency_ms: f64,
}

fn parse_label(s: &str) -> Label {
    match s.to_ascii_lowercase().as_str() {
        "public" => Label::Public,
        "internal" => Label::Internal,
        "confidential" => Label::Confidential,
        "highlyconfidential" | "highly-confidential" => Label::HighlyConfidential,
        _ => Label::Public,
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    sondera_config::load();

    let label = args.label.clone().unwrap_or_else(|| {
        let model = std::env::var("SONDERA_MODEL").unwrap_or_default();
        let provider = std::env::var("SONDERA_PROVIDER").unwrap_or_default();
        if model.is_empty() {
            "default".to_string()
        } else {
            format!("{provider}/{model}")
        }
    });

    eprintln!("Loading corpus from {}", args.corpus.display());
    let corpus_text = std::fs::read_to_string(&args.corpus)
        .with_context(|| format!("reading corpus: {}", args.corpus.display()))?;
    let entries: Vec<CorpusEntry> = corpus_text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("parsing corpus line"))
        .collect::<Result<_>>()?;
    eprintln!("Loaded {} test cases", entries.len());

    eprintln!("Loading classifiers from {}", args.policies.display());
    let ifc = DataModel::from_toml(args.policies.join("ifc.toml"))
        .context("loading ifc.toml")?;
    let policy = PolicyModel::from_toml(args.policies.join("policies.toml"))
        .context("loading policies.toml")?;

    let provider = std::env::var("SONDERA_PROVIDER").unwrap_or_default();
    let model = std::env::var("SONDERA_MODEL").unwrap_or_default();
    eprintln!("Provider: {provider}, Model: {model}");
    eprintln!("Running benchmarks...\n");

    let source_agent = "benchmark";

    let mut results = Vec::with_capacity(entries.len());

    for entry in &entries {
        let preview = if entry.content.len() > 60 {
            format!("{}...", &entry.content[..57])
        } else {
            entry.content.clone()
        };

        eprint!("  {:<5} {:<16} ", entry.id, entry.category);

        let ifc_start = Instant::now();
        let ifc_result = ifc.classify(&entry.content, source_agent).await;
        let ifc_latency = ifc_start.elapsed().as_millis() as u64;

        let policy_start = Instant::now();
        let policy_result = policy.evaluate_content(&entry.content, source_agent).await;
        let policy_latency = policy_start.elapsed().as_millis() as u64;

        let (predicted_label, ifc_error) = match &ifc_result {
            Ok(classification) => (classification.max_label().to_string(), None),
            Err(e) => ("ERROR".to_string(), Some(e.to_string())),
        };
        let (predicted_compliant, policy_error) = match &policy_result {
            Ok(classification) => (classification.compliant, None),
            Err(e) => (false, Some(e.to_string())),
        };

        let expected_label = parse_label(&entry.expected_label);
        let label_correct = ifc_result.as_ref().map(|c| c.max_label() == expected_label).unwrap_or(false);
        let compliance_correct = predicted_compliant == entry.expected_compliant;

        let status = if label_correct && compliance_correct {
            "OK"
        } else if !label_correct && !compliance_correct {
            "BOTH_WRONG"
        } else if !label_correct {
            "LABEL_WRONG"
        } else {
            "POLICY_WRONG"
        };

        eprintln!(
            "{status:<12} L:{ifc_latency:>5}ms P:{policy_latency:>5}ms  [{predicted_label} vs {expected}] [{predicted_compliant} vs {}]",
            entry.expected_compliant,
            expected = entry.expected_label,
        );

        results.push(CaseResult {
            id: entry.id.clone(),
            category: entry.category.clone(),
            content_preview: preview,
            predicted_label,
            expected_label: entry.expected_label.clone(),
            label_correct,
            predicted_compliant,
            expected_compliant: entry.expected_compliant,
            compliance_correct,
            ifc_latency_ms: ifc_latency,
            policy_latency_ms: policy_latency,
            ifc_error,
            policy_error,
        });
    }

    // Compute metrics.
    let total = results.len();
    let label_correct_count = results.iter().filter(|r| r.label_correct).count();
    let compliance_correct_count = results.iter().filter(|r| r.compliance_correct).count();
    let both_correct_count = results.iter().filter(|r| r.label_correct && r.compliance_correct).count();

    // False positive: predicted non-compliant when expected compliant.
    let expected_compliant = results.iter().filter(|r| r.expected_compliant).count();
    let false_positives = results
        .iter()
        .filter(|r| r.expected_compliant && !r.predicted_compliant)
        .count();
    // False negative: predicted compliant when expected non-compliant.
    let expected_non_compliant = results.iter().filter(|r| !r.expected_compliant).count();
    let false_negatives = results
        .iter()
        .filter(|r| !r.expected_compliant && r.predicted_compliant)
        .count();

    let mut ifc_latencies: Vec<u64> = results.iter().map(|r| r.ifc_latency_ms).collect();
    let mut policy_latencies: Vec<u64> = results.iter().map(|r| r.policy_latency_ms).collect();
    ifc_latencies.sort_unstable();
    policy_latencies.sort_unstable();

    let avg_ifc = ifc_latencies.iter().sum::<u64>() as f64 / total as f64;
    let avg_policy = policy_latencies.iter().sum::<u64>() as f64 / total as f64;

    // Per-category breakdown.
    let categories: Vec<String> = {
        let mut cats: Vec<String> = entries.iter().map(|e| e.category.clone()).collect();
        cats.sort();
        cats.dedup();
        cats
    };
    let per_category = categories
        .iter()
        .map(|cat| {
            let cat_results: Vec<&CaseResult> = results.iter().filter(|r| &r.category == cat).collect();
            let count = cat_results.len();
            let label_acc = cat_results.iter().filter(|r| r.label_correct).count() as f64 / count as f64;
            let policy_acc = cat_results.iter().filter(|r| r.compliance_correct).count() as f64 / count as f64;
            let ifc_avg = cat_results.iter().map(|r| r.ifc_latency_ms).sum::<u64>() as f64 / count as f64;
            let policy_avg = cat_results.iter().map(|r| r.policy_latency_ms).sum::<u64>() as f64 / count as f64;
            CategoryReport {
                category: cat.clone(),
                count,
                label_accuracy: label_acc,
                compliance_accuracy: policy_acc,
                avg_ifc_latency_ms: ifc_avg,
                avg_policy_latency_ms: policy_avg,
            }
        })
        .collect();

    let report = BenchmarkReport {
        label: label.clone(),
        timestamp: Utc::now().to_rfc3339(),
        total_cases: total,
        label_accuracy: label_correct_count as f64 / total as f64,
        compliance_accuracy: compliance_correct_count as f64 / total as f64,
        both_correct: both_correct_count as f64 / total as f64,
        false_positive_rate: if expected_compliant > 0 {
            false_positives as f64 / expected_compliant as f64
        } else {
            0.0
        },
        false_negative_rate: if expected_non_compliant > 0 {
            false_negatives as f64 / expected_non_compliant as f64
        } else {
            0.0
        },
        avg_ifc_latency_ms: avg_ifc,
        avg_policy_latency_ms: avg_policy,
        p95_ifc_latency_ms: percentile(&ifc_latencies, 0.95),
        p95_policy_latency_ms: percentile(&policy_latencies, 0.95),
        per_category,
        cases: results,
    };

    // Print summary.
    eprintln!();
    eprintln!("================ RESULTS: {label} ================");
    eprintln!("Cases: {total}");
    eprintln!("Label accuracy:       {:.1}% ({label_correct_count}/{total})", report.label_accuracy * 100.0);
    eprintln!("Compliance accuracy:  {:.1}% ({compliance_correct_count}/{total})", report.compliance_accuracy * 100.0);
    eprintln!("Both correct:         {:.1}% ({both_correct_count}/{total})", report.both_correct * 100.0);
    eprintln!("False positive rate:  {:.1}% ({false_positives}/{expected_compliant})", report.false_positive_rate * 100.0);
    eprintln!("False negative rate:  {:.1}% ({false_negatives}/{expected_non_compliant})", report.false_negative_rate * 100.0);
    eprintln!("IFC latency:    avg {avg_ifc:.0}ms   p95 {}ms", report.p95_ifc_latency_ms);
    eprintln!("Policy latency: avg {avg_policy:.0}ms   p95 {}ms", report.p95_policy_latency_ms);
    eprintln!();
    eprintln!("{:<22} {:>5}  {:>8}  {:>8}  {:>10}  {:>10}", "Category", "N", "Label%", "Policy%", "IFC avg", "Pol avg");
    eprintln!("{}", "-".repeat(75));
    for cat in &report.per_category {
        eprintln!(
            "{:<22} {:>5}  {:>7.1}%  {:>7.1}%  {:>8.0}ms  {:>8.0}ms",
            cat.category,
            cat.count,
            cat.label_accuracy * 100.0,
            cat.compliance_accuracy * 100.0,
            cat.avg_ifc_latency_ms,
            cat.avg_policy_latency_ms,
        );
    }
    eprintln!();

    // Write JSON output.
    let output_path = args.output.unwrap_or_else(|| {
        PathBuf::from(format!(
            "benchmarks/results-{}-{}.json",
            label.replace('/', "_"),
            Utc::now().format("%Y%m%dT%H%M%S")
        ))
    });
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&output_path, json)?;
    eprintln!("Full results written to {}", output_path.display());

    Ok(())
}
