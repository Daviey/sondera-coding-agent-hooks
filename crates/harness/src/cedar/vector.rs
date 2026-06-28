//! Lightweight TF-IDF vector classifier for fast guardrail classification.
//!
//! Two roles:
//! 1. Fast-path: classify content without the LLM when confidence is high
//! 2. Prompt reduction: select the K most relevant template examples for
//!    a given input, so the LLM prompt is smaller and faster
//!
//! Trained from the benchmark corpus at startup + every LLM result at runtime.

use std::collections::HashMap;

/// Minimum cosine similarity to accept a vector classification without the LLM.
const CONFIDENCE_THRESHOLD: f64 = 0.15;

/// A multi-class TF-IDF classifier with per-class centroid vectors.
pub struct VectorClassifier {
    vocab: HashMap<String, usize>,
    df: Vec<usize>,
    centroids: HashMap<String, Vec<f64>>,
    n_docs: usize,
}

impl VectorClassifier {
    pub fn new() -> Self {
        Self { vocab: HashMap::new(), df: Vec::new(), centroids: HashMap::new(), n_docs: 0 }
    }

    pub fn train(&mut self, content: &str, label: &str) {
        let tokens = tokenize(content);
        let mut tf: HashMap<usize, f64> = HashMap::new();
        self.n_docs += 1;

        for token in &tokens {
            let idx = if let Some(&i) = self.vocab.get(token) {
                i
            } else {
                let i = self.vocab.len();
                self.vocab.insert(token.clone(), i);
                self.df.push(0);
                i
            };
            *tf.entry(idx).or_default() += 1.0;
        }
        for &idx in tf.keys() {
            self.df[idx] += 1;
        }

        let vec = self.tfidf_vector(&tf);
        let centroid = self.centroids.entry(label.to_string()).or_insert_with(|| vec![0.0; self.vocab.len()]);
        while centroid.len() < self.vocab.len() {
            centroid.push(0.0);
        }
        for (i, v) in vec.iter().enumerate() {
            centroid[i] += v;
        }
    }

    pub fn finalise(&mut self) {
        for centroid in self.centroids.values_mut() {
            let norm: f64 = centroid.iter().map(|v| v * v).sum::<f64>().sqrt();
            if norm > 0.0 {
                for v in centroid.iter_mut() { *v /= norm; }
            }
        }
    }

    /// Classify content. Returns label if confident, else None (fall back to LLM).
    pub fn classify(&self, content: &str) -> Option<String> {
        if self.centroids.len() < 2 || self.vocab.is_empty() { return None; }
        let vec = self.content_vector(content);
        let vec_norm: f64 = vec.iter().map(|v| v * v).sum::<f64>().sqrt();
        if vec_norm == 0.0 { return None; }

        let mut best: Option<(String, f64)> = None;
        for (label, centroid) in &self.centroids {
            let dot: f64 = vec.iter().zip(centroid.iter()).map(|(a, b)| a * b).sum();
            let sim = dot / vec_norm;
            if best.as_ref().is_none_or(|(_, s)| sim > *s) {
                best = Some((label.clone(), sim));
            }
        }
        let (label, sim) = best?;
        (sim >= CONFIDENCE_THRESHOLD).then_some(label)
    }

    /// Select the K most similar items from a list, returning indices.
    pub fn select_nearest(&self, content: &str, candidates: &[String], k: usize) -> Vec<usize> {
        if candidates.is_empty() { return Vec::new(); }
        let query = self.content_vector(content);
        let query_norm: f64 = query.iter().map(|v| v * v).sum::<f64>().sqrt();

        let mut scored: Vec<(usize, f64)> = candidates
            .iter()
            .map(|c| {
                let cand = self.content_vector(c);
                let cand_norm: f64 = cand.iter().map(|v| v * v).sum::<f64>().sqrt();
                let sim = if query_norm > 0.0 && cand_norm > 0.0 {
                    query.iter().zip(cand.iter()).map(|(a, b)| a * b).sum::<f64>() / (query_norm * cand_norm)
                } else { 0.0 };
                // dummy index, will fix
                (0usize, sim)
            })
            .enumerate()
            .map(|(i, (_, sim))| (i, sim))
            .collect();

        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().take(k).map(|(i, _)| i).collect()
    }

    pub fn size(&self) -> usize { self.n_docs }

    fn content_vector(&self, content: &str) -> Vec<f64> {
        let tokens = tokenize(content);
        let mut tf: HashMap<usize, f64> = HashMap::new();
        for token in &tokens {
            if let Some(&idx) = self.vocab.get(token) {
                *tf.entry(idx).or_default() += 1.0;
            }
        }
        self.tfidf_vector(&tf)
    }

    fn tfidf_vector(&self, tf: &HashMap<usize, f64>) -> Vec<f64> {
        let mut vec = vec![0.0; self.vocab.len()];
        let n = self.n_docs.max(1) as f64;
        for (&idx, &count) in tf {
            let idf = ((n / self.df[idx].max(1) as f64) + 1.0).ln();
            vec[idx] = count * idf;
        }
        let norm: f64 = vec.iter().map(|v| v * v).sum::<f64>().sqrt();
        if norm > 0.0 { for v in &mut vec { *v /= norm; } }
        vec
    }
}

impl Default for VectorClassifier { fn default() -> Self { Self::new() } }

fn tokenize(content: &str) -> Vec<String> {
    content
        .split(|c: char| c.is_whitespace() || matches!(c, '"'|'\''|'('|')'|'{'|'}'|'['|']'|','|';'|'|'|'='|':'))
        .filter(|s| !s.is_empty() && s.len() > 1)
        .map(|s| s.to_lowercase())
        .collect()
}

/// Load training data from the benchmark corpus JSONL file.
/// Each line: {"content":"...", "expected_label":"...", "expected_compliant":true/false, ...}
pub fn train_from_corpus(path: &std::path::Path) -> (VectorClassifier, VectorClassifier) {
    let mut ifc = VectorClassifier::new();
    let mut policy = VectorClassifier::new();

    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines() {
            if line.trim().is_empty() { continue; }
            if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
                let content = entry["content"].as_str().unwrap_or("");
                let label = entry["expected_label"].as_str().unwrap_or("Public");
                let compliant = entry["expected_compliant"].as_bool().unwrap_or(true);
                if !content.is_empty() {
                    ifc.train(content, label);
                    policy.train(content, if compliant { "compliant" } else { "non-compliant" });
                }
            }
        }
    }

    ifc.finalise();
    policy.finalise();
    (ifc, policy)
}
