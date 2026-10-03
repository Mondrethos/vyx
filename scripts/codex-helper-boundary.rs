//! Vyx's complete client-facing RPC surface. Model output is never re-dispatched as RPC.
use codex_app_server_protocol::JSONRPCRequest;
use serde_json::{Map, Value, json};

fn object(value: &Value) -> Result<&Map<String, Value>, String> {
    value.as_object().ok_or_else(|| "Vyx helper requires an object".into())
}
fn keys(value: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    if value.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("Vyx helper does not expose this request field".into());
    }
    Ok(())
}
fn fixed(params: &mut Map<String, Value>, key: &str, value: Value) -> Result<(), String> {
    if params.get(key).is_some_and(|given| !given.is_null() && given != &value) {
        return Err("Vyx helper configuration cannot be overridden".into());
    }
    params.insert(key.into(), value);
    Ok(())
}
fn text_items(value: &Value, history: bool) -> Result<(), String> {
    let items = value.as_array().ok_or("Vyx helper requires text items")?;
    for item in items {
        let item = object(item)?;
        if history {
            keys(item, &["type", "role", "content", "id", "status", "phase"])?;
            if item.get("type").and_then(Value::as_str) != Some("message")
                || !matches!(item.get("role").and_then(Value::as_str), Some("user" | "assistant"))
            {
                return Err("Vyx history accepts only user and assistant text messages".into());
            }
            let content = item.get("content").and_then(Value::as_array).ok_or("Vyx history requires text content")?;
            for block in content {
                let block = object(block)?;
                keys(block, &["type", "text"])?;
                if !matches!(block.get("type").and_then(Value::as_str), Some("input_text" | "output_text"))
                    || !block.get("text").is_some_and(Value::is_string)
                {
                    return Err("Vyx history does not accept tools, files, images or URLs".into());
                }
            }
        } else {
            keys(item, &["type", "text", "text_elements"])?;
            if item.get("type").and_then(Value::as_str) != Some("text")
                || !item.get("text").is_some_and(Value::is_string)
                || item.get("text_elements").is_some_and(|value| value.as_array().is_none_or(|array| !array.is_empty()))
            {
                return Err("Vyx helper accepts plain text input only".into());
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_request(request: &mut JSONRPCRequest) -> Result<(), String> {
    if request.trace.is_some() {
        return Err("Vyx helper does not accept telemetry metadata".into());
    }
    let params = request.params.get_or_insert_with(|| json!({}));
    if params.is_null() { *params = json!({}); }
    let params = params.as_object_mut().ok_or("Vyx helper requires object parameters")?;
    match request.method.as_str() {
        "initialize" => keys(params, &["clientInfo", "capabilities"]),
        "account/read" => keys(params, &["refreshToken"]),
        "account/login/cancel" => keys(params, &["loginId"]),
        "account/login/start" => {
            keys(params, &["type"])?;
            if !matches!(params.get("type").and_then(Value::as_str), Some("chatgpt" | "chatgptDeviceCode")) {
                return Err("Vyx helper supports official ChatGPT subscription login only".into());
            }
            Ok(())
        }
        "model/list" => keys(params, &["cursor", "limit", "includeHidden"]),
        "thread/start" | "thread/resume" | "thread/fork" => {
            keys(params, &[
                "threadId", "model", "modelProvider", "allowProviderModelFallback", "cwd",
                "approvalPolicy", "sandbox", "baseInstructions", "developerInstructions", "config",
                "ephemeral", "environments", "dynamicTools", "selectedCapabilityRoots",
                "experimentalRawEvents",
            ])?;
            if let Some(config) = params.get("config").filter(|value| !value.is_null()) {
                keys(object(config)?, &["model_reasoning_effort"])?;
            }
            fixed(params, "modelProvider", json!("openai"))?;
            fixed(params, "cwd", json!("/work"))?;
            fixed(params, "approvalPolicy", json!("never"))?;
            fixed(params, "sandbox", json!("read-only"))?;
            for key in ["environments", "dynamicTools", "selectedCapabilityRoots"] {
                // Only thread/start currently has all three fields. Never permit non-empty
                // values on another operation even if a future upstream schema adds them.
                if params.get(key).is_some_and(|value| !value.is_null() && value.as_array().is_none_or(|items| !items.is_empty())) {
                    return Err("Vyx helper has no environments, tools or capability roots".into());
                }
            }
            if request.method == "thread/start" {
                fixed(params, "allowProviderModelFallback", json!(false))?;
                fixed(params, "ephemeral", json!(true))?;
                fixed(params, "environments", json!([]))?;
                fixed(params, "dynamicTools", json!([]))?;
                fixed(params, "selectedCapabilityRoots", json!([]))?;
                fixed(params, "experimentalRawEvents", json!(false))?;
            } else if request.method == "thread/fork" {
                fixed(params, "ephemeral", json!(true))?;
            }
            Ok(())
        }
        "thread/inject_items" => {
            keys(params, &["threadId", "items"])?;
            text_items(params.get("items").ok_or("Vyx history requires items")?, true)
        }
        "turn/start" => {
            keys(params, &["threadId", "input", "effort", "model", "cwd", "approvalPolicy", "environments", "outputSchema"])?;
            fixed(params, "cwd", json!("/work"))?;
            fixed(params, "approvalPolicy", json!("never"))?;
            fixed(params, "environments", json!([]))?;
            text_items(params.get("input").ok_or("Vyx turn requires input")?, false)
        }
        "turn/interrupt" => keys(params, &["threadId", "turnId"]),
        _ => Err("This RPC is not available in the tool-free Vyx helper".into()),
    }
}
