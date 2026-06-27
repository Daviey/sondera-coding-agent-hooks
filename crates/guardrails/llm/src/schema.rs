//! JSON-schema shaping shared by the structured-output backends.
//!
//! Both Anthropic's structured outputs and OpenAI's strict `json_schema` response format reject
//! schemas that `schemars` emits naively for the guardrail result types. [`harden_schema`] adjusts
//! a generated schema so it is accepted by those engines. [`ensure_all_properties_required`] adds
//! the extra constraint OpenAI strict mode imposes (every property listed in `required`).
//!
//! These rules were debugged against the live APIs; keep them.

use serde_json::{Map, Value};

/// Adjust a `schemars`-generated schema so Anthropic structured outputs and OpenAI strict
/// `json_schema` accept it: inline `$ref`/`$defs`, collapse `oneOf`/`anyOf` const unions into a
/// flat string `enum`, set `additionalProperties: false` on objects, and strip `minimum`/`maximum`
/// (Anthropic rejects those on numeric nodes; OpenAI tolerates them, so dropping them is safe for
/// both). Root `$schema`/`title` metadata are removed.
pub(crate) fn harden_schema(mut schema: Value) -> Value {
    inline_refs(&mut schema);
    collapse_const_unions(&mut schema);
    set_additional_properties(&mut schema);
    strip_unsupported_numeric_keywords(&mut schema);
    if let Value::Object(map) = &mut schema {
        map.remove("$schema");
        map.remove("title");
    }
    schema
}

/// OpenAI strict `json_schema` requires every property of every object to appear in `required`
/// (nullable optionals are expressed differently). [`harden_schema`] alone does not guarantee
/// this, so the strict path calls this after hardening. For our all-required result types it is a
/// no-op, but it makes the strict path robust if an optional field is ever added.
pub(crate) fn ensure_all_properties_required(mut schema: Value) -> Value {
    ensure_required_inner(&mut schema);
    schema
}

fn ensure_required_inner(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let is_object = map.get("type").and_then(Value::as_str) == Some("object");
            if is_object {
                if let Some(props) = map.get("properties").and_then(Value::as_object) {
                    let names: Vec<String> = props.keys().cloned().collect();
                    if !names.is_empty() {
                        let required = map
                            .entry("required")
                            .or_insert_with(|| Value::Array(Vec::new()));
                        if let Some(arr) = required.as_array_mut() {
                            for name in names {
                                let needle = Value::String(name);
                                if !arr.contains(&needle) {
                                    arr.push(needle);
                                }
                            }
                        }
                    }
                }
            }
            for child in map.values_mut() {
                ensure_required_inner(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                ensure_required_inner(child);
            }
        }
        _ => {}
    }
}

/// Inline every `$ref: "#/$defs/Name"` by substituting the referenced subschema, then drop the
/// now-unused `$defs`. `schemars` factors named types (such as an enum) into `$defs` and
/// references them, but the structured-output engines expect a single self-contained schema. The
/// result types here are acyclic, so a straightforward recursive substitution suffices.
fn inline_refs(schema: &mut Value) {
    let defs = schema
        .get("$defs")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    substitute_refs(schema, &defs);
    if let Value::Object(map) = schema {
        map.remove("$defs");
    }
}

fn substitute_refs(value: &mut Value, defs: &Map<String, Value>) {
    match value {
        Value::Object(map) => {
            if let Some(name) = map
                .get("$ref")
                .and_then(Value::as_str)
                .and_then(|r| r.strip_prefix("#/$defs/"))
            {
                if let Some(target) = defs.get(name) {
                    let mut resolved = target.clone();
                    substitute_refs(&mut resolved, defs);
                    *value = resolved;
                    return;
                }
            }
            for child in map.values_mut() {
                substitute_refs(child, defs);
            }
        }
        Value::Array(items) => {
            for child in items {
                substitute_refs(child, defs);
            }
        }
        _ => {}
    }
}

/// Recursively collapse `oneOf`/`anyOf` unions of string `const`s into a single
/// `{"type":"string","enum":[...]}` node. `schemars` renders a Rust enum whose variants carry doc
/// comments as `oneOf: [{const: "a", description: ...}, ...]`, which the structured-output engines
/// reject. Collapsing preserves the allowed values (dropping per-variant descriptions, which the
/// engines do not use for constraint anyway).
fn collapse_const_unions(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for key in ["oneOf", "anyOf"] {
                let consts = map.get(key).and_then(string_consts);
                if let Some(values) = consts {
                    map.remove("oneOf");
                    map.remove("anyOf");
                    map.insert("type".into(), Value::String("string".into()));
                    map.insert("enum".into(), Value::Array(values));
                    break;
                }
            }
            for child in map.values_mut() {
                collapse_const_unions(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                collapse_const_unions(child);
            }
        }
        _ => {}
    }
}

/// If `value` is an array in which every element is an object with a string `const`, return the
/// list of those const values; otherwise `None`.
fn string_consts(value: &Value) -> Option<Vec<Value>> {
    let arr = value.as_array()?;
    if arr.is_empty() {
        return None;
    }
    arr.iter()
        .map(|v| match v.get("const") {
            Some(c @ Value::String(_)) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

/// Recursively remove numeric keywords that Anthropic's structured outputs reject. `schemars`
/// emits `minimum`/`maximum` (and a `uint8`-style `format`) for bounded integer types such as
/// `u8`; Anthropic returns a 400 for them. OpenAI strict tolerates them, so stripping is harmless.
fn strip_unsupported_numeric_keywords(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let is_numeric = matches!(
                map.get("type").and_then(Value::as_str),
                Some("integer") | Some("number")
            );
            if is_numeric {
                map.remove("minimum");
                map.remove("maximum");
                map.remove("exclusiveMinimum");
                map.remove("exclusiveMaximum");
                map.remove("format");
            }
            for child in map.values_mut() {
                strip_unsupported_numeric_keywords(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                strip_unsupported_numeric_keywords(child);
            }
        }
        _ => {}
    }
}

/// Recursively add `additionalProperties: false` to every object-typed schema node that declares
/// `properties`.
fn set_additional_properties(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for child in map.values_mut() {
                set_additional_properties(child);
            }
            let is_object = map.get("type").and_then(Value::as_str) == Some("object");
            if is_object && map.contains_key("properties") {
                map.entry("additionalProperties")
                    .or_insert(Value::Bool(false));
            }
        }
        Value::Array(items) => {
            for child in items {
                set_additional_properties(child);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::JsonSchema;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct Sample {
        flag: u8,
        label: String,
        kind: Kind,
    }

    #[derive(Serialize, Deserialize, JsonSchema)]
    #[serde(rename_all = "snake_case")]
    enum Kind {
        /// First variant — doc comment forces schemars into a `oneOf` of consts.
        Alpha,
        /// Second variant.
        Beta,
    }

    #[test]
    fn hardened_schema_marks_object_closed_and_strips_meta() {
        let schema = harden_schema(serde_json::to_value(schemars::schema_for!(Sample)).unwrap());
        let map = schema.as_object().unwrap();
        assert!(!map.contains_key("$schema"));
        assert!(!map.contains_key("title"));
        assert_eq!(
            map.get("additionalProperties"),
            Some(&Value::Bool(false)),
            "root object schema must be closed"
        );
        assert!(map.contains_key("properties"));
    }

    #[test]
    fn hardened_schema_strips_numeric_bounds_for_integers() {
        let schema = harden_schema(serde_json::to_value(schemars::schema_for!(Sample)).unwrap());
        let flag = schema
            .get("properties")
            .and_then(|p| p.get("flag"))
            .and_then(Value::as_object)
            .expect("flag property schema");
        assert_eq!(flag.get("type").and_then(Value::as_str), Some("integer"));
        assert!(!flag.contains_key("minimum"), "minimum must be stripped");
        assert!(!flag.contains_key("maximum"), "maximum must be stripped");
        assert!(!flag.contains_key("format"), "format must be stripped");
    }

    #[test]
    fn hardened_schema_inlines_refs_and_collapses_enum_to_string_enum() {
        let schema = harden_schema(serde_json::to_value(schemars::schema_for!(Sample)).unwrap());
        assert!(
            schema.get("$defs").is_none(),
            "$defs must be removed after inlining"
        );
        let kind = schema
            .get("properties")
            .and_then(|p| p.get("kind"))
            .and_then(Value::as_object)
            .expect("kind property schema");
        assert!(!kind.contains_key("$ref"), "$ref must be inlined");
        assert!(!kind.contains_key("oneOf"), "oneOf must be collapsed");
        assert!(!kind.contains_key("anyOf"), "anyOf must be collapsed");
        assert_eq!(kind.get("type").and_then(Value::as_str), Some("string"));
        assert_eq!(
            kind.get("enum").and_then(Value::as_array),
            Some(&vec![Value::from("alpha"), Value::from("beta")]),
            "variants must be preserved as a string enum"
        );
    }

    #[test]
    fn ensure_required_lists_every_property() {
        #[derive(JsonSchema)]
        #[allow(dead_code)]
        struct WithOptional {
            a: String,
            b: Option<u8>,
        }
        let mut schema = harden_schema(serde_json::to_value(schemars::schema_for!(WithOptional)).unwrap());
        // schemars omits `b` from required (it's Option); OpenAI strict needs it present.
        schema = ensure_all_properties_required(schema);
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("required array");
        let names: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
        assert!(names.contains(&"a") && names.contains(&"b"));
    }
}
