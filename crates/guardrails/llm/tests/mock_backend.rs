//! Mock-server tests for the OpenAI-compatible and Anthropic backends.
//!
//! These verify the wire shape each provider sends (strict `json_schema` vs `json_object` fallback,
//! auth headers) and the response/error parsing, without needing live credentials. The Vertex ADC
//! path is covered by the live `#[ignore]`d test in `vertex.rs`; its URL/body construction is unit
//! tested there and shares `build_json_object_body` with the OpenAI-compat backend tested here.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sondera_llm::{LlmClient, LlmConfig, LlmError, Provider};
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Debug, Serialize, Deserialize, JsonSchema)]
struct Verdict {
    violation: u8,
    policy_category: String,
}

/// Build an LlmClient for a given provider pointed at the mock server.
fn client(provider: Provider, server: &MockServer, api_key: Option<&str>) -> LlmClient {
    let config = LlmConfig {
        provider,
        model: "test-model".into(),
        temperature: 0.0,
        base_url: Some(server.uri()),
        api_key: api_key.map(String::from),
        vertex_project: None,
        vertex_location: None,
        vertex_endpoint_id: None,
        vertex_project_number: None,
    };
    LlmClient::try_new(config).expect("client should construct")
}

/// A canned OpenAI Chat Completions success body whose message content is valid JSON.
fn chat_completion(content: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "choices": [{ "message": { "role": "assistant", "content": content } }],
    }))
}

/// The single recorded request's body parsed as JSON.
async fn received_body(server: &MockServer) -> Value {
    let req = server
        .received_requests()
        .await
        .expect("server should record requests")
        .into_iter()
        .next()
        .expect("a request should have been received");
    serde_json::from_slice(&req.body).expect("request body should be JSON")
}

async fn received_request(server: &MockServer) -> wiremock::Request {
    server
        .received_requests()
        .await
        .expect("server should record requests")
        .into_iter()
        .next()
        .expect("a request should have been received")
}

#[tokio::test]
async fn openai_sends_strict_json_schema() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(chat_completion(
            r#"{"violation":0,"policy_category":"none"}"#,
        ))
        .mount(&server)
        .await;

    let client = client(Provider::Openai, &server, Some("sk-test"));
    let value = client
        .complete_json_as::<Verdict>("sys", "hello", Duration::from_secs(5), "test")
        .await
        .expect("call should succeed");

    assert_eq!(value.violation, 0);
    let body = received_body(&server).await;
    assert_eq!(
        body["response_format"]["type"].as_str(),
        Some("json_schema"),
        "OpenAI must request strict json_schema"
    );
    assert_eq!(
        body["response_format"]["json_schema"]["strict"].as_bool(),
        Some(true)
    );
    // Hardened schema: object closed, no $defs/$ref.
    let schema = &body["response_format"]["json_schema"]["schema"];
    assert_eq!(schema["additionalProperties"].as_bool(), Some(false));
    assert!(schema.get("$defs").is_none());
}

#[tokio::test]
async fn openai_sends_bearer_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(chat_completion(
            r#"{"violation":0,"policy_category":"none"}"#,
        ))
        .mount(&server)
        .await;

    let client = client(Provider::Openai, &server, Some("sk-test"));
    let _ = client
        .complete_json_as::<Verdict>("sys", "hello", Duration::from_secs(2), "test")
        .await;

    let req = received_request(&server).await;
    assert_eq!(
        req.headers.get("authorization").unwrap().to_str().unwrap(),
        "Bearer sk-test"
    );
}

#[tokio::test]
async fn zai_falls_back_to_json_object_with_schema_in_prompt() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(chat_completion(
            r#"{"violation":0,"policy_category":"none"}"#,
        ))
        .mount(&server)
        .await;

    let client = client(Provider::Zai, &server, Some("zai-key"));
    let _ = client
        .complete_json_as::<Verdict>("classify.", "hello", Duration::from_secs(2), "test")
        .await;

    let body = received_body(&server).await;
    assert_eq!(
        body["response_format"]["type"].as_str(),
        Some("json_object"),
        "z.ai must use json_object (no strict support)"
    );
    // The fallback injects the schema into the system message.
    let system = body["messages"][0]["content"].as_str().unwrap();
    assert!(
        system.contains("JSON SCHEMA"),
        "system prompt should describe the schema"
    );
    assert!(
        system.contains("violation"),
        "schema text should include the result fields"
    );
}

#[tokio::test]
async fn ollama_sends_no_auth_header() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(chat_completion(
            r#"{"violation":0,"policy_category":"none"}"#,
        ))
        .mount(&server)
        .await;

    let client = client(Provider::Ollama, &server, None);
    let _ = client
        .complete_json_as::<Verdict>("sys", "hello", Duration::from_secs(2), "test")
        .await;

    let req = received_request(&server).await;
    assert!(
        req.headers.get("authorization").is_none(),
        "Ollama must not send an Authorization header"
    );
}

#[tokio::test]
async fn http_error_surfaces_status_and_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(serde_json::json!({ "error": { "message": "rate limited" } })),
        )
        .mount(&server)
        .await;

    let client = client(Provider::Openai, &server, Some("sk-test"));
    let err = client
        .complete_json_as::<Verdict>("sys", "hello", Duration::from_secs(2), "test")
        .await
        .expect_err("should error");

    match err {
        LlmError::Api { status, message } => {
            assert_eq!(status, 429);
            assert!(message.contains("rate limited"));
        }
        other => panic!("expected Api error, got {other:?}"),
    }
}

#[tokio::test]
async fn empty_content_is_no_content_error() {
    let server = MockServer::start().await;
    // OpenAI returns null content (e.g. tool-call-only response); the client must treat it as
    // having no usable text.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(chat_completion(r#"null"#))
        .mount(&server)
        .await;

    // Note: "null" string parses as JSON null, not empty. Use an actual empty string to exercise
    // the NoContent path.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(chat_completion(""))
        .mount(&server)
        .await;

    let client = client(Provider::Openai, &server, Some("sk-test"));
    let err = client
        .complete_json_as::<Verdict>("sys", "hello", Duration::from_secs(2), "test")
        .await
        .expect_err("should error");
    assert!(matches!(err, LlmError::NoContent), "got {err:?}");
}

#[tokio::test]
async fn anthropic_sends_structured_output_config_and_api_key() {
    use wiremock::matchers::header;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "sk-anthropic"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "content": [{ "type": "text", "text": r#"{"violation":0,"policy_category":"none"}"# }],
            "stop_reason": "end_turn",
        })))
        .mount(&server)
        .await;

    let client = client(Provider::Anthropic, &server, Some("sk-anthropic"));
    let value = client
        .complete_json_as::<Verdict>("sys", "hello", Duration::from_secs(5), "test")
        .await
        .expect("call should succeed");
    assert_eq!(value.violation, 0);

    let body = received_body(&server).await;
    assert_eq!(
        body["output_config"]["format"]["type"].as_str(),
        Some("json_schema"),
        "Anthropic must use structured-output json_schema"
    );
    let schema = &body["output_config"]["format"]["schema"];
    assert_eq!(schema["additionalProperties"].as_bool(), Some(false));
    assert!(schema.get("$defs").is_none());
}

#[tokio::test]
async fn retries_on_transient_429() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_json(serde_json::json!({ "error": { "message": "slow down" } })),
        )
        .mount(&server)
        .await;

    let client = client(Provider::Openai, &server, Some("sk-test"));
    let err = client
        .complete_json_as::<Verdict>("sys", "hello", Duration::from_secs(2), "test")
        .await
        .expect_err("should error after retries");

    assert!(
        matches!(err, LlmError::Api { status: 429, .. }),
        "got {err:?}"
    );
    let attempts = server
        .received_requests()
        .await
        .expect("requests recorded")
        .len();
    assert_eq!(
        attempts, 3,
        "should make MAX_ATTEMPTS (3) attempts before giving up"
    );
}

#[tokio::test]
async fn lenient_parse_strips_code_fence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(chat_completion(
            "```json\n{\"violation\":1,\"policy_category\":\"SC2\"}\n```",
        ))
        .mount(&server)
        .await;

    let client = client(Provider::Zai, &server, Some("zai-key"));
    let value = client
        .complete_json_as::<Verdict>("sys", "hello", Duration::from_secs(2), "test")
        .await
        .expect("fenced JSON should parse leniently");
    assert_eq!(value.violation, 1);
    assert_eq!(value.policy_category, "SC2");
}

#[tokio::test]
async fn lenient_parse_extracts_json_from_prose() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(chat_completion(
            "Sure! Here is the verdict: {\"violation\":0,\"policy_category\":\"none\"} — hope that helps.",
        ))
        .mount(&server)
        .await;

    let client = client(Provider::Zai, &server, Some("zai-key"));
    let value = client
        .complete_json_as::<Verdict>("sys", "hello", Duration::from_secs(2), "test")
        .await
        .expect("prose-wrapped JSON should parse leniently");
    assert_eq!(value.violation, 0);
}
