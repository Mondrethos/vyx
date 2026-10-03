//! Native provider routes for Vyx AI.
//!
//! Only the native host calls these functions. A request carries exactly the
//! conversation text the app assembled after user review: nothing here reads
//! sessions, terminals, the vault, or ambient state. Endpoints come from
//! [`Profile::endpoint`], which pins official providers to their documented URL
//! and allows plain HTTP only for this computer. Credentials travel only in
//! request headers marked sensitive, redirects are never followed, and provider
//! errors are reduced to bounded, redacted text. Dropping the future returned by
//! [`stream`] closes the HTTP connection. Codex uses the separately installed, verified Vyx helper.

use std::{
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Result, anyhow, bail, ensure};
use reqwest::{
    Client, RequestBuilder, Response, StatusCode, Url,
    header::{self, HeaderMap, HeaderValue},
};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::vault::Secret;

use super::{ApiStyle, Message, Profile, ProviderKind, Role, Usage, codex, context_start};

const ANTHROPIC_VERSION: &str = "2023-06-01";
const USER_AGENT: &str = concat!("vyx/", env!("CARGO_PKG_VERSION"));
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Reasoning models can think silently for minutes before their first byte.
const READ_TIMEOUT: Duration = Duration::from_secs(300);
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
pub(super) const MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;
const MAX_SSE_LINE: usize = 1024 * 1024;
const MAX_EVENT_DATA: usize = 2 * 1024 * 1024;
const MAX_JSON_BODY: usize = 8 * 1024 * 1024;
const MAX_ERROR_BODY: usize = 64 * 1024;
const MAX_ERROR_TEXT: usize = 400;
const MAX_MODEL_ID: usize = 256;
pub(super) const MAX_MODELS: usize = 5000;
const MAX_MODEL_PAGES: usize = 10;

/// One reply request. `data_dir` is the Vyx data directory; only Codex profiles
/// use it to locate the optional runtime. Its account/runtime scratch is volatile.
pub struct Request {
    pub profile: Profile,
    pub messages: Vec<Message>,
    pub context_chars: usize,
    pub streaming: bool,
    pub data_dir: PathBuf,
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("profile", &self.profile.id)
            .field("kind", &self.profile.kind)
            .field("model", &self.profile.model)
            .field("messages", &self.messages.len())
            .field("context_chars", &self.context_chars)
            .field("streaming", &self.streaming)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub enum ProviderEvent {
    Delta(String),
    Usage(Usage),
    Status(String),
    /// Vyx-owned subscription credentials; the app commits these to encrypted local state.
    CodexAuth(Option<Secret>),
    /// Ephemeral native sign-in instructions, never chat history or diagnostic output.
    CodexLogin {
        url: Secret,
        code: Option<Secret>,
    },
}

impl fmt::Debug for ProviderEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Delta(text) => write!(formatter, "Delta({} bytes)", text.len()),
            Self::Usage(usage) => formatter.debug_tuple("Usage").field(usage).finish(),
            Self::Status(text) => write!(formatter, "Status({} bytes)", text.len()),
            Self::CodexAuth(_) => formatter.write_str("CodexAuth([REDACTED])"),
            Self::CodexLogin { .. } => formatter.write_str("CodexLogin([REDACTED])"),
        }
    }
}

/// Sends the conversation and reports the reply through `sender`.
///
/// System messages become the provider's instructions; the rest of the history is
/// selected with [`context_start`] and omissions are reported as a `Status`. Streaming
/// requests forward each text delta; otherwise the whole reply arrives as one `Delta`.
/// Usage, when the provider reports it, follows the text. Returns once the reply is
/// complete. Dropping or aborting the future cancels the request.
pub async fn stream(request: Request, sender: mpsc::Sender<ProviderEvent>) -> Result<()> {
    let Request {
        profile,
        messages,
        context_chars,
        streaming,
        data_dir,
    } = request;
    let streaming = streaming && profile.streaming;
    profile.ready()?;
    let prepared = prepare(messages, context_chars)?;
    if prepared.omitted > 0 {
        let notice = format!(
            "Omitted {} earlier message(s) to stay within the {context_chars}-character context limit.",
            prepared.omitted
        );
        send_event(&sender, ProviderEvent::Status(notice)).await?;
    }
    if profile.kind == ProviderKind::Codex {
        return codex::stream(&profile, &data_dir, &prepared, streaming, &sender).await;
    }
    let route = route(&profile)?;
    let url = profile.endpoint(match route {
        Route::Chat(_) => "chat/completions",
        Route::Responses => "responses",
        Route::Anthropic => "messages",
    })?;
    let target = profile.recipient();
    let secret = credential(&profile);
    let body = serde_json::to_vec(&request_body(route, &profile, &prepared, streaming))?;
    drop(prepared);
    let client = client(&url, None)?;
    let request = client
        .post(url)
        .headers(auth_headers(&profile)?)
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::ACCEPT,
            if streaming {
                "text/event-stream"
            } else {
                "application/json"
            },
        )
        .body(body);
    let response = send(request, &target, secret).await?;
    let mut output = Output::new(&sender, streaming);
    if streaming && !is_json(&response) {
        read_stream(response, route, &target, secret, &mut output).await?;
    } else {
        read_whole(response, route, &target, secret, &mut output).await?;
    }
    output.finish().await
}

/// Lists the model IDs the provider reports. Manual IDs remain valid for endpoints
/// without discovery.
pub async fn models(
    profile: &Profile,
    data_dir: &Path,
    sender: mpsc::Sender<ProviderEvent>,
) -> Result<Vec<String>> {
    profile.validate()?;
    if profile.kind == ProviderKind::Codex {
        return codex::models(profile, data_dir, sender).await;
    }
    let target = profile.recipient();
    let secret = credential(profile);
    let url = profile.endpoint("models")?;
    let client = client(&url, Some(QUERY_TIMEOUT))?;
    let ids = match profile.kind {
        ProviderKind::Anthropic => {
            let mut ids = Vec::new();
            let mut after: Option<String> = None;
            for _ in 0..MAX_MODEL_PAGES {
                let mut page_url = url.clone();
                page_url.query_pairs_mut().append_pair("limit", "1000");
                if let Some(after) = &after {
                    page_url.query_pairs_mut().append_pair("after_id", after);
                }
                let page =
                    get_json(&client, page_url, auth_headers(profile)?, &target, secret).await?;
                ids.extend(model_ids(&page, &target)?);
                match (
                    page.get("has_more").and_then(Value::as_bool),
                    page.get("last_id").and_then(Value::as_str),
                ) {
                    (Some(true), Some(last))
                        if after.as_deref() != Some(last) && ids.len() < MAX_MODELS =>
                    {
                        after = Some(last.to_owned());
                    }
                    _ => break,
                }
            }
            ids
        }
        // The OpenRouter catalog is public, so the key is not sent at all.
        ProviderKind::OpenRouter => model_ids(
            &get_json(&client, url, HeaderMap::new(), &target, None).await?,
            &target,
        )?,
        _ => model_ids(
            &get_json(&client, url, auth_headers(profile)?, &target, secret).await?,
            &target,
        )?,
    };
    Ok(finish_ids(ids))
}

/// Explicit connection test. It never runs inference.
pub async fn test(
    profile: &Profile,
    data_dir: &Path,
    sender: mpsc::Sender<ProviderEvent>,
) -> Result<String> {
    profile.validate()?;
    if profile.kind == ProviderKind::Codex {
        return codex::test(profile, data_dir, sender).await;
    }
    let target = profile.recipient();
    let secret = credential(profile);
    let billing = profile.kind.billing_notice();
    match profile.kind {
        ProviderKind::OpenRouter => {
            let url = profile.endpoint("key")?;
            let client = client(&url, Some(QUERY_TIMEOUT))?;
            let key = get_json(&client, url, auth_headers(profile)?, &target, secret).await?;
            ensure!(
                key.get("data").is_some_and(Value::is_object),
                "OpenRouter did not return account information."
            );
            Ok(openrouter_summary(&key, billing))
        }
        ProviderKind::Anthropic => {
            let mut url = profile.endpoint("models")?;
            url.query_pairs_mut().append_pair("limit", "1");
            let client = client(&url, Some(QUERY_TIMEOUT))?;
            let page = get_json(&client, url, auth_headers(profile)?, &target, secret).await?;
            model_ids(&page, &target)?;
            Ok(format!("Connected to {target} with this key. {billing}"))
        }
        _ => {
            let url = profile.endpoint("models")?;
            let client = client(&url, Some(QUERY_TIMEOUT))?;
            let response = client
                .get(url)
                .headers(auth_headers(profile)?)
                .header(header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|error| transport_error(&target, &error))?;
            if profile.kind == ProviderKind::Compatible
                && matches!(
                    response.status(),
                    StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
                )
            {
                return Ok(format!(
                    "Reached {target}, but it does not list models. Enter the model ID manually. {billing}"
                ));
            }
            let response = checked(response, &target, secret).await?;
            let page = parse_json(&read_body(response, MAX_JSON_BODY, &target).await?, &target)?;
            let count = model_ids(&page, &target)?.len();
            Ok(format!(
                "Connected to {target} ({count} models listed). {billing}"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
// Conversation selection

/// Conversation text selected for one provider request.
pub(super) struct Prepared {
    pub(super) system: String,
    pub(super) turns: Vec<Turn>,
    pub(super) omitted: usize,
}

pub(super) struct Turn {
    pub(super) user: bool,
    pub(super) text: String,
}

/// Joins every system message into the instructions and selects the history with
/// [`context_start`], the single definition of what a request sends.
pub(super) fn prepare(messages: Vec<Message>, context_chars: usize) -> Result<Prepared> {
    let mut system = String::new();
    let mut conversation = Vec::with_capacity(messages.len());
    for message in messages {
        if message.text.trim().is_empty() {
            continue;
        }
        if message.role == Role::System {
            if !system.is_empty() {
                system.push_str("\n\n");
            }
            system.push_str(&message.text);
        } else {
            conversation.push(message);
        }
    }
    ensure!(
        conversation
            .last()
            .is_some_and(|message| message.role.is_user_turn()),
        "The conversation must end with your message before it can be sent."
    );
    let start = context_start(&conversation, context_chars);
    // Action results are user-side data: never instructions and never assistant text.
    let turns = conversation
        .drain(start..)
        .map(|message| Turn {
            user: message.role.is_user_turn(),
            text: message.text,
        })
        .collect();
    Ok(Prepared {
        system,
        turns,
        omitted: start,
    })
}

// ---------------------------------------------------------------------------
// HTTP

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dialect {
    OpenAi,
    OpenRouter,
    Compatible,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Chat(Dialect),
    Responses,
    Anthropic,
}

fn route(profile: &Profile) -> Result<Route> {
    let style = if profile.kind.selectable_api_style() {
        profile.api_style
    } else {
        profile.kind.default_api_style()
    };
    Ok(match (profile.kind, style) {
        (ProviderKind::Codex, _) => bail!("Codex profiles do not use an HTTP route."),
        (ProviderKind::Anthropic, _) => Route::Anthropic,
        (_, ApiStyle::Responses) => Route::Responses,
        (ProviderKind::OpenAi, ApiStyle::ChatCompletions) => Route::Chat(Dialect::OpenAi),
        (ProviderKind::OpenRouter, ApiStyle::ChatCompletions) => Route::Chat(Dialect::OpenRouter),
        (ProviderKind::Compatible, ApiStyle::ChatCompletions) => Route::Chat(Dialect::Compatible),
    })
}

/// [`Profile::endpoint`] only yields plain HTTP for this computer; such requests
/// never use a proxy, and every other request is HTTPS-only.
fn client(url: &Url, total: Option<Duration>) -> Result<Client> {
    let local = url.scheme() == "http";
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut builder = Client::builder()
        .user_agent(USER_AGENT)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .https_only(!local);
    if local {
        builder = builder.no_proxy();
    }
    if let Some(total) = total {
        builder = builder.timeout(total);
    }
    builder
        .build()
        .map_err(|_| anyhow!("Could not prepare the secure provider HTTP client."))
}

fn credential(profile: &Profile) -> Option<&str> {
    profile
        .credential
        .as_ref()
        .map(|secret| secret.expose())
        .filter(|key| !key.is_empty())
}

fn auth_headers(profile: &Profile) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    let key = credential(profile);
    if profile.kind.requires_credential() && key.is_none() {
        bail!("Add an API key to {}.", profile.name);
    }
    match (profile.kind, key) {
        (ProviderKind::Codex, _) => bail!("Codex profiles never send API keys."),
        (ProviderKind::Anthropic, Some(key)) => {
            headers.insert("x-api-key", sensitive(key)?);
            headers.insert(
                "anthropic-version",
                HeaderValue::from_static(ANTHROPIC_VERSION),
            );
        }
        (_, Some(key)) => {
            headers.insert(header::AUTHORIZATION, bearer(key)?);
        }
        (_, None) => {}
    }
    Ok(headers)
}

fn bearer(key: &str) -> Result<HeaderValue> {
    let value = Zeroizing::new(format!("Bearer {key}"));
    sensitive(value.as_str())
}

fn sensitive(value: &str) -> Result<HeaderValue> {
    let mut header = HeaderValue::from_str(value).map_err(|_| {
        anyhow!("The API key contains characters that cannot be sent in an HTTP header.")
    })?;
    header.set_sensitive(true);
    Ok(header)
}

async fn send(request: RequestBuilder, target: &str, secret: Option<&str>) -> Result<Response> {
    let response = request
        .send()
        .await
        .map_err(|error| transport_error(target, &error))?;
    checked(response, target, secret).await
}

async fn checked(response: Response, target: &str, secret: Option<&str>) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    if status.is_redirection() {
        bail!(
            "{target} answered with a redirect (HTTP {status}). Vyx never follows provider redirects, so nothing was sent anywhere else."
        );
    }
    let body = read_prefix(response, MAX_ERROR_BODY).await;
    Err(anyhow!(http_error(target, status, &body, secret)))
}

async fn get_json(
    client: &Client,
    url: Url,
    headers: HeaderMap,
    target: &str,
    secret: Option<&str>,
) -> Result<Value> {
    let request = client
        .get(url)
        .headers(headers)
        .header(header::ACCEPT, "application/json");
    let response = send(request, target, secret).await?;
    let value = parse_json(&read_body(response, MAX_JSON_BODY, target).await?, target)?;
    ensure!(
        !value.get("error").is_some_and(|error| !error.is_null()),
        "{target} reported an error: {}",
        describe_error(&value, secret)
    );
    Ok(value)
}

fn parse_json(body: &[u8], target: &str) -> Result<Value> {
    serde_json::from_slice(body)
        .map_err(|_| anyhow!("{target} returned a response Vyx could not read."))
}

fn is_json(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim()
                .to_ascii_lowercase()
                .starts_with("application/json")
        })
}

async fn read_body(mut response: Response, limit: usize, target: &str) -> Result<Vec<u8>> {
    if let Some(length) = response.content_length() {
        ensure!(
            length <= limit as u64,
            "{target} returned more than {limit} bytes, which Vyx does not accept."
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| transport_error(target, &error))?
    {
        ensure!(
            body.len() + chunk.len() <= limit,
            "{target} returned more than {limit} bytes, which Vyx does not accept."
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Reads at most `limit` bytes of an error body and ignores transport failures.
async fn read_prefix(mut response: Response, limit: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < limit {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let take = chunk.len().min(limit - body.len());
                body.extend_from_slice(&chunk[..take]);
            }
            _ => break,
        }
    }
    body
}

fn transport_error(target: &str, error: &reqwest::Error) -> anyhow::Error {
    let what = if error.is_timeout() {
        "timed out"
    } else if error.is_connect() {
        "could not be reached"
    } else if error.is_redirect() {
        "attempted a redirect, which Vyx refuses"
    } else if error.is_body() || error.is_decode() {
        "interrupted the reply"
    } else {
        "request failed"
    };
    // TLS/proxy/library causes can contain credentials or ambient proxy URLs.
    // Never attach an untrusted transport error chain to a user-visible error.
    anyhow!("{target} {what}. Check the endpoint, transport security, and network connection.")
}

fn http_error(target: &str, status: StatusCode, body: &[u8], secret: Option<&str>) -> String {
    let detail = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| error_message(&value))
        .map(|message| clean(&message, secret))
        .filter(|message| !message.is_empty());
    let hint = match status.as_u16() {
        401 => " Check the API key.",
        402 => " The account needs more credits.",
        403 => " This key is not allowed to use that model or endpoint.",
        404 => " Check the model ID and endpoint.",
        429 => " The rate limit or quota is exhausted; Vyx did not switch providers or billing.",
        500..=599 => " The provider reported a server problem; try again later.",
        _ => "",
    };
    match detail {
        Some(detail) => format!("{target} returned HTTP {status}: {detail}{hint}"),
        None => format!("{target} returned HTTP {status}.{hint}"),
    }
}

/// Extracts a provider's human-readable error from the common JSON error shapes.
fn error_message(value: &Value) -> Option<String> {
    let error = value
        .get("error")
        .filter(|error| !error.is_null())
        .unwrap_or(value);
    let message = error
        .get("message")
        .and_then(Value::as_str)
        .or_else(|| error.as_str())
        .or_else(|| value.get("message").and_then(Value::as_str))
        .or_else(|| value.get("detail").and_then(Value::as_str))?;
    let kind = error
        .get("type")
        .or_else(|| error.get("code"))
        .and_then(|kind| {
            kind.as_str()
                .map(str::to_owned)
                .or_else(|| kind.as_i64().map(|code| code.to_string()))
        });
    Some(match kind {
        Some(kind) if !kind.is_empty() && !message.contains(kind.as_str()) => {
            format!("{message} ({kind})")
        }
        _ => message.to_owned(),
    })
}

fn describe_error(value: &Value, secret: Option<&str>) -> String {
    error_message(value)
        .map(|message| clean(&message, secret))
        .filter(|message| !message.is_empty())
        .unwrap_or_else(|| "no details were provided".to_owned())
}

/// Bounded, single-line, credential-free text for errors and notices.
///
/// Removes the profile credential verbatim plus anything shaped like an API key
/// or bearer token, so provider errors that echo a key cannot leak it.
pub(super) fn clean(text: &str, secret: Option<&str>) -> String {
    let mut text = text.to_owned();
    if let Some(secret) = secret.filter(|secret| !secret.is_empty()) {
        text = text.replace(secret, "[redacted]");
    }
    let mut cleaned = String::with_capacity(text.len().min(MAX_ERROR_TEXT * 4));
    let mut word = String::new();
    let mut space = false;
    for character in text.chars().chain(std::iter::once(' ')) {
        if character.is_ascii_alphanumeric()
            || matches!(character, '-' | '_' | '.' | '*' | '~' | '+' | '=')
        {
            word.push(character);
            continue;
        }
        if !word.is_empty() {
            cleaned.push_str(if token_like(&word) {
                "[redacted]"
            } else {
                &word
            });
            word.clear();
            space = false;
        }
        if character.is_whitespace() || character.is_control() {
            if !space && !cleaned.is_empty() {
                cleaned.push(' ');
            }
            space = true;
        } else {
            cleaned.push(character);
            space = false;
        }
    }
    let cleaned = cleaned.trim();
    if cleaned.chars().count() <= MAX_ERROR_TEXT {
        return cleaned.to_owned();
    }
    let mut bounded: String = cleaned.chars().take(MAX_ERROR_TEXT).collect();
    bounded.push('…');
    bounded
}

fn token_like(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    if word.len() > 6
        && ["sk-", "sk_", "rk-", "rk_", "eyj"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
    {
        return true;
    }
    word.len() >= 40
        && word.chars().any(|character| character.is_ascii_digit())
        && word
            .chars()
            .any(|character| character.is_ascii_alphabetic())
}

async fn send_event(sender: &mpsc::Sender<ProviderEvent>, event: ProviderEvent) -> Result<()> {
    sender
        .send(event)
        .await
        .map_err(|_| anyhow!("The reply was cancelled."))
}

// ---------------------------------------------------------------------------
// Request bodies

fn role(turn: &Turn) -> &'static str {
    if turn.user { "user" } else { "assistant" }
}

/// Sends only controls the profile set; [`Profile::validate`] already bounded them per provider.
fn request_body(route: Route, profile: &Profile, prepared: &Prepared, streaming: bool) -> Value {
    let effort = profile.reasoning_effort.as_deref();
    let turns: Vec<Value> = prepared
        .turns
        .iter()
        .map(|turn| json!({ "role": role(turn), "content": turn.text }))
        .collect();
    let mut body = match route {
        Route::Chat(dialect) => {
            let mut messages = Vec::with_capacity(turns.len() + 1);
            if !prepared.system.is_empty() {
                messages.push(json!({ "role": "system", "content": prepared.system }));
            }
            messages.extend(turns);
            let limit = if dialect == Dialect::OpenAi {
                "max_completion_tokens"
            } else {
                "max_tokens"
            };
            let mut body =
                json!({ "model": profile.model, "messages": messages, "stream": streaming });
            body[limit] = json!(profile.max_output_tokens);
            if let Some(effort) = effort {
                body["reasoning_effort"] = json!(effort);
            }
            // Unknown fields can break strict self-hosted servers, so compatible
            // endpoints only report usage if they include it on their own.
            if streaming && dialect != Dialect::Compatible {
                body["stream_options"] = json!({ "include_usage": true });
            }
            if dialect == Dialect::OpenRouter {
                // Do not silently ignore controls or try another upstream after a failure.
                body["provider"] = json!({ "require_parameters": true, "allow_fallbacks": false });
            }
            body
        }
        Route::Responses => {
            // `store: false` keeps the conversation out of provider-side response storage.
            let mut body = json!({
                "model": profile.model,
                "input": turns,
                "stream": streaming,
                "store": false,
                "max_output_tokens": profile.max_output_tokens,
            });
            if !prepared.system.is_empty() {
                body["instructions"] = json!(prepared.system);
            }
            if let Some(effort) = effort {
                body["reasoning"] = json!({ "effort": effort });
            }
            body
        }
        Route::Anthropic => {
            let mut body = json!({
                "model": profile.model,
                "max_tokens": profile.max_output_tokens,
                "messages": turns,
                "stream": streaming,
            });
            if !prepared.system.is_empty() {
                body["system"] = json!(prepared.system);
            }
            if let Some(effort) = effort {
                body["output_config"] = json!({ "effort": effort });
            }
            body
        }
    };
    if let Some(temperature) = profile.temperature {
        body["temperature"] = json!(temperature);
    }
    body
}

// ---------------------------------------------------------------------------
// Replies

pub(super) enum Step {
    Text(String),
    Usage(Usage),
    Notice(String),
    Done,
}

/// Forwards reply text within the size bound and reports usage once at the end.
pub(super) struct Output<'a> {
    sender: &'a mpsc::Sender<ProviderEvent>,
    streaming: bool,
    text: String,
    bytes: usize,
    usage: Option<Usage>,
}

impl<'a> Output<'a> {
    pub(super) fn new(sender: &'a mpsc::Sender<ProviderEvent>, streaming: bool) -> Self {
        Self {
            sender,
            streaming,
            text: String::new(),
            bytes: 0,
            usage: None,
        }
    }

    /// Returns whether the provider signalled the end of the reply.
    pub(super) async fn apply(&mut self, step: Step) -> Result<bool> {
        match step {
            Step::Text(text) => {
                if text.is_empty() {
                    return Ok(false);
                }
                self.bytes += text.len();
                ensure!(
                    self.bytes <= MAX_REPLY_BYTES,
                    "The reply exceeded Vyx's {} MiB limit and was stopped.",
                    MAX_REPLY_BYTES / (1024 * 1024)
                );
                if self.streaming {
                    send_event(self.sender, ProviderEvent::Delta(text)).await?;
                } else {
                    self.text.push_str(&text);
                }
            }
            Step::Usage(usage) => self.usage = Some(usage),
            Step::Notice(notice) => send_event(self.sender, ProviderEvent::Status(notice)).await?,
            Step::Done => return Ok(true),
        }
        Ok(false)
    }

    pub(super) async fn finish(mut self) -> Result<()> {
        if self.bytes == 0 {
            send_event(
                self.sender,
                ProviderEvent::Status("The provider returned no text.".to_owned()),
            )
            .await?;
        }
        if !self.text.is_empty() {
            let text = std::mem::take(&mut self.text);
            send_event(self.sender, ProviderEvent::Delta(text)).await?;
        }
        if let Some(usage) = self.usage.take() {
            send_event(self.sender, ProviderEvent::Usage(usage)).await?;
        }
        Ok(())
    }
}

pub(super) fn usage(input_tokens: u64, output_tokens: u64, cost_usd: Option<f64>) -> Usage {
    Usage {
        input_tokens,
        output_tokens,
        cost_usd: cost_usd.filter(|cost| cost.is_finite() && *cost >= 0.0),
    }
}

fn count(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

#[derive(Default)]
struct Parse {
    finished: bool,
    announced: bool,
    input: u64,
    output: u64,
    cache_creation: u64,
    cache_read: u64,
    usage_reported: bool,
}

impl Parse {
    fn anthropic_usage(&mut self, reported: &Value) {
        // Each reported counter is cumulative; absent counters retain their
        // previous values, particularly cache counts from message_start.
        for (key, stored) in [
            ("input_tokens", &mut self.input),
            ("output_tokens", &mut self.output),
            ("cache_creation_input_tokens", &mut self.cache_creation),
            ("cache_read_input_tokens", &mut self.cache_read),
        ] {
            if let Some(value) = reported.get(key).and_then(Value::as_u64) {
                *stored = value;
                self.usage_reported = true;
            }
        }
    }
}

async fn read_stream(
    mut response: Response,
    route: Route,
    target: &str,
    secret: Option<&str>,
    output: &mut Output<'_>,
) -> Result<()> {
    let mut sse = Sse::default();
    let mut state = Parse::default();
    let mut events = Vec::new();
    let mut steps = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|error| transport_error(target, &error))?;
        let ended = chunk.is_none();
        match chunk {
            Some(chunk) => sse.feed(&chunk, &mut events)?,
            None => sse.finish(&mut events)?,
        }
        for data in events.drain(..) {
            handle_event(route, &data, &mut state, target, secret, &mut steps)?;
            for step in steps.drain(..) {
                if output.apply(step).await? {
                    return Ok(());
                }
            }
        }
        if ended {
            break;
        }
    }
    // Some compatible servers close after the final chunk without `[DONE]`.
    ensure!(
        matches!(route, Route::Chat(_)) && state.finished,
        "{target} closed the connection before the reply finished."
    );
    Ok(())
}

async fn read_whole(
    response: Response,
    route: Route,
    target: &str,
    secret: Option<&str>,
    output: &mut Output<'_>,
) -> Result<()> {
    let value = parse_json(&read_body(response, MAX_JSON_BODY, target).await?, target)?;
    let mut state = Parse::default();
    let mut steps = Vec::new();
    match route {
        Route::Chat(dialect) => {
            chat_value(&value, dialect, &mut state, target, secret, &mut steps)?;
            ensure!(
                state.finished,
                "{target} did not return a completed chat reply."
            );
        }
        Route::Responses => responses_final(&value, true, target, secret, &mut steps)?,
        Route::Anthropic => anthropic_message(&value, target, secret, &mut steps)?,
    }
    for step in steps {
        output.apply(step).await?;
    }
    Ok(())
}

fn handle_event(
    route: Route,
    data: &str,
    state: &mut Parse,
    target: &str,
    secret: Option<&str>,
    steps: &mut Vec<Step>,
) -> Result<()> {
    let data = data.trim();
    if data.is_empty() {
        return Ok(());
    }
    if data == "[DONE]" {
        ensure!(
            matches!(route, Route::Chat(_)) && state.finished,
            "{target} ended the stream without a completed reply."
        );
        steps.push(Step::Done);
        return Ok(());
    }
    let value: Value = serde_json::from_str(data)
        .map_err(|_| anyhow!("{target} sent a streaming event Vyx could not read."))?;
    match route {
        Route::Chat(dialect) => chat_value(&value, dialect, state, target, secret, steps),
        Route::Responses => responses_event(&value, target, secret, steps),
        Route::Anthropic => anthropic_event(&value, state, target, secret, steps),
    }
}

fn finish_notice(reason: &str) -> Option<&'static str> {
    match reason {
        "length" | "max_tokens" | "max_output_tokens" => {
            Some("The reply stopped at the output token limit and may be incomplete.")
        }
        "content_filter" => Some("The provider's content filter stopped the reply."),
        "tool_calls" | "function_call" | "tool_use" => {
            Some("The model tried to call a tool. Vyx AI provides no tools, so the reply ended.")
        }
        "model_context_window_exceeded" => {
            Some("The reply stopped because the model's context window is full.")
        }
        _ => None,
    }
}

/// Chat Completions chunks (streaming) and complete responses share one shape.
fn chat_value(
    value: &Value,
    dialect: Dialect,
    state: &mut Parse,
    target: &str,
    secret: Option<&str>,
    steps: &mut Vec<Step>,
) -> Result<()> {
    if let Some(error) = value.get("error").filter(|error| !error.is_null()) {
        bail!(
            "{target} reported an error: {}",
            describe_error(&json!({ "error": error }), secret)
        );
    }
    if dialect == Dialect::OpenRouter && !state.announced {
        if let Some(provider) = value
            .get("provider")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        {
            state.announced = true;
            steps.push(Step::Notice(format!(
                "OpenRouter served this reply through {}.",
                clean(provider, secret)
            )));
        }
    }
    if let Some(choice) = value
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
    {
        if let Some(part) = choice.get("delta").or_else(|| choice.get("message")) {
            for key in ["content", "refusal"] {
                if let Some(text) = part
                    .get(key)
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                {
                    steps.push(Step::Text(text.to_owned()));
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
            ensure!(reason != "error", "{target} ended the reply with an error.");
            if !state.finished {
                state.finished = true;
                if let Some(notice) = finish_notice(reason) {
                    steps.push(Step::Notice(notice.to_owned()));
                }
            }
        }
    }
    if let Some(reported) = value.get("usage").filter(|usage| usage.is_object()) {
        let cost = reported.get("cost").and_then(Value::as_f64);
        steps.push(Step::Usage(usage(
            count(reported, "prompt_tokens"),
            count(reported, "completion_tokens"),
            cost,
        )));
    }
    Ok(())
}

fn responses_event(
    value: &Value,
    target: &str,
    secret: Option<&str>,
    steps: &mut Vec<Step>,
) -> Result<()> {
    match value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "response.output_text.delta" | "response.refusal.delta" => {
            if let Some(delta) = value
                .get("delta")
                .and_then(Value::as_str)
                .filter(|delta| !delta.is_empty())
            {
                steps.push(Step::Text(delta.to_owned()));
            }
        }
        "response.completed" | "response.incomplete" => {
            responses_final(
                value.get("response").unwrap_or(&Value::Null),
                false,
                target,
                secret,
                steps,
            )?;
            steps.push(Step::Done);
        }
        "response.failed" => {
            let response = value.get("response").unwrap_or(&Value::Null);
            bail!(
                "{target} reported an error: {}",
                describe_error(response, secret)
            );
        }
        "error" => bail!(
            "{target} reported an error: {}",
            describe_error(value, secret)
        ),
        _ => {}
    }
    Ok(())
}

/// A complete Responses object; `with_text` is false when the text already streamed.
fn responses_final(
    response: &Value,
    with_text: bool,
    target: &str,
    secret: Option<&str>,
    steps: &mut Vec<Step>,
) -> Result<()> {
    if response.get("status").and_then(Value::as_str) == Some("failed")
        || response.get("error").is_some_and(|error| !error.is_null())
    {
        bail!(
            "{target} reported an error: {}",
            describe_error(response, secret)
        );
    }
    ensure!(
        matches!(
            response.get("status").and_then(Value::as_str),
            Some("completed" | "incomplete")
        ),
        "{target} did not return a completed Responses reply."
    );
    if with_text {
        ensure!(
            response.get("output").is_some_and(Value::is_array),
            "{target} omitted its reply output."
        );
    }
    if with_text {
        for item in response
            .get("output")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if item.get("type").and_then(Value::as_str) != Some("message") {
                continue;
            }
            for part in item
                .get("content")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let text = match part.get("type").and_then(Value::as_str) {
                    Some("output_text") => part.get("text"),
                    Some("refusal") => part.get("refusal"),
                    _ => None,
                };
                if let Some(text) = text.and_then(Value::as_str).filter(|text| !text.is_empty()) {
                    steps.push(Step::Text(text.to_owned()));
                }
            }
        }
    }
    if response.get("status").and_then(Value::as_str) == Some("incomplete") {
        let reason = response
            .pointer("/incomplete_details/reason")
            .and_then(Value::as_str)
            .unwrap_or_default();
        steps.push(Step::Notice(
            finish_notice(reason)
                .unwrap_or("The provider marked the reply incomplete.")
                .to_owned(),
        ));
    }
    if let Some(reported) = response.get("usage").filter(|usage| usage.is_object()) {
        steps.push(Step::Usage(usage(
            count(reported, "input_tokens"),
            count(reported, "output_tokens"),
            None,
        )));
    }
    Ok(())
}

fn anthropic_input(reported: &Value) -> u64 {
    count(reported, "input_tokens")
        .saturating_add(count(reported, "cache_creation_input_tokens"))
        .saturating_add(count(reported, "cache_read_input_tokens"))
}

fn anthropic_stop(
    reason: &str,
    details: Option<&Value>,
    target: &str,
    secret: Option<&str>,
    steps: &mut Vec<Step>,
) -> Result<()> {
    if reason == "refusal" {
        let details = details.unwrap_or(&Value::Null);
        let explanation = details
            .get("explanation")
            .and_then(Value::as_str)
            .map(|text| clean(text, secret))
            .unwrap_or_else(|| "no explanation was provided".to_owned());
        let category = details
            .get("category")
            .and_then(Value::as_str)
            .map(|category| format!(" ({})", clean(category, secret)))
            .unwrap_or_default();
        bail!(
            "{target} declined this request{category}: {explanation} Any partial text is incomplete."
        );
    }
    if let Some(notice) = finish_notice(reason) {
        steps.push(Step::Notice(notice.to_owned()));
    }
    Ok(())
}

fn anthropic_event(
    value: &Value,
    state: &mut Parse,
    target: &str,
    secret: Option<&str>,
    steps: &mut Vec<Step>,
) -> Result<()> {
    match value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default()
    {
        "message_start" => {
            ensure!(
                !state.announced,
                "{target} restarted the reply unexpectedly."
            );
            state.announced = true;
            if let Some(reported) = value.pointer("/message/usage") {
                state.anthropic_usage(reported);
            }
        }
        "content_block_start" => {
            if value.pointer("/content_block/type").and_then(Value::as_str) == Some("text") {
                if let Some(text) = value
                    .pointer("/content_block/text")
                    .and_then(Value::as_str)
                    .filter(|text| !text.is_empty())
                {
                    steps.push(Step::Text(text.to_owned()));
                }
            }
        }
        "content_block_delta" => {
            if value.pointer("/delta/type").and_then(Value::as_str) == Some("text_delta") {
                if let Some(text) = value.pointer("/delta/text").and_then(Value::as_str) {
                    steps.push(Step::Text(text.to_owned()));
                }
            }
        }
        "message_delta" => {
            // Usage in message_delta is cumulative.
            if let Some(reported) = value.get("usage").filter(|usage| usage.is_object()) {
                state.anthropic_usage(reported);
            }
            if let Some(reason) = value.pointer("/delta/stop_reason").and_then(Value::as_str) {
                let details = value
                    .pointer("/delta/stop_details")
                    .or_else(|| value.get("stop_details"));
                anthropic_stop(reason, details, target, secret, steps)?;
                state.finished = true;
            }
        }
        "message_stop" => {
            ensure!(
                state.announced && state.finished,
                "{target} ended the stream without a completed message."
            );
            if state.usage_reported {
                let input = state
                    .input
                    .saturating_add(state.cache_creation)
                    .saturating_add(state.cache_read);
                steps.push(Step::Usage(usage(input, state.output, None)));
            }
            steps.push(Step::Done);
        }
        "error" => bail!(
            "{target} reported an error: {}",
            describe_error(value, secret)
        ),
        _ => {}
    }
    Ok(())
}

fn anthropic_message(
    value: &Value,
    target: &str,
    secret: Option<&str>,
    steps: &mut Vec<Step>,
) -> Result<()> {
    if value.get("type").and_then(Value::as_str) == Some("error") {
        bail!(
            "{target} reported an error: {}",
            describe_error(value, secret)
        );
    }
    ensure!(
        value.get("type").and_then(Value::as_str) == Some("message")
            && value.get("content").is_some_and(Value::is_array)
            && value.get("stop_reason").is_some_and(Value::is_string),
        "{target} did not return a completed Anthropic message."
    );
    if let Some(reason) = value.get("stop_reason").and_then(Value::as_str) {
        anthropic_stop(reason, value.get("stop_details"), target, secret, steps)?;
    }
    for block in value
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if block.get("type").and_then(Value::as_str) == Some("text") {
            if let Some(text) = block
                .get("text")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
            {
                steps.push(Step::Text(text.to_owned()));
            }
        }
    }
    if let Some(reported) = value.get("usage").filter(|usage| usage.is_object()) {
        steps.push(Step::Usage(usage(
            anthropic_input(reported),
            count(reported, "output_tokens"),
            None,
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Server-sent events

/// Incremental SSE decoder. Lines are decoded only once complete, so multi-byte
/// UTF-8 characters split across network chunks stay intact.
#[derive(Default)]
struct Sse {
    line: Vec<u8>,
    data: String,
    has_data: bool,
    skip_lf: bool,
    seen_line: bool,
}

impl Sse {
    fn feed(&mut self, mut bytes: &[u8], events: &mut Vec<String>) -> Result<()> {
        while !bytes.is_empty() {
            if self.skip_lf {
                self.skip_lf = false;
                if bytes[0] == b'\n' {
                    bytes = &bytes[1..];
                    continue;
                }
            }
            let Some(end) = bytes
                .iter()
                .position(|&byte| byte == b'\n' || byte == b'\r')
            else {
                return self.extend(bytes);
            };
            self.extend(&bytes[..end])?;
            self.take_line(events)?;
            self.skip_lf = bytes[end] == b'\r';
            bytes = &bytes[end + 1..];
        }
        Ok(())
    }

    fn finish(&mut self, events: &mut Vec<String>) -> Result<()> {
        if !self.line.is_empty() {
            self.take_line(events)?;
        }
        ensure!(
            !self.has_data,
            "The provider closed an incomplete streaming event."
        );
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.line.len() + bytes.len() <= MAX_SSE_LINE,
            "The provider sent an oversized streaming line."
        );
        self.line.extend_from_slice(bytes);
        Ok(())
    }

    fn take_line(&mut self, events: &mut Vec<String>) -> Result<()> {
        let line = std::str::from_utf8(&self.line)
            .map_err(|_| anyhow!("The provider sent invalid UTF-8."))?;
        let line = if self.seen_line {
            line
        } else {
            line.strip_prefix('\u{feff}').unwrap_or(line)
        };
        self.seen_line = true;
        if line.is_empty() {
            self.line.clear();
            self.dispatch(events);
            return Ok(());
        }
        if !line.starts_with(':') {
            let (field, value) = match line.split_once(':') {
                Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
                None => (line, ""),
            };
            if field == "data" {
                ensure!(
                    self.data.len() + value.len() < MAX_EVENT_DATA,
                    "The provider sent an oversized streaming event."
                );
                self.data.push_str(value);
                self.data.push('\n');
                self.has_data = true;
            }
        }
        self.line.clear();
        Ok(())
    }

    fn dispatch(&mut self, events: &mut Vec<String>) {
        if self.has_data {
            let mut data = std::mem::take(&mut self.data);
            data.pop();
            events.push(data);
            self.has_data = false;
        }
    }
}

// ---------------------------------------------------------------------------
// Model lists and account summaries

fn model_ids(value: &Value, target: &str) -> Result<Vec<String>> {
    let data = value.get("data").and_then(Value::as_array).ok_or_else(|| {
        anyhow!("{target} did not return a model list. Enter a model ID manually.")
    })?;
    Ok(data
        .iter()
        .filter_map(|model| model.get("id").and_then(Value::as_str))
        .filter(|id| valid_model_id(id))
        .take(MAX_MODELS)
        .map(str::to_owned)
        .collect())
}

pub(super) fn valid_model_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_MODEL_ID
        && !id
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

pub(super) fn finish_ids(mut ids: Vec<String>) -> Vec<String> {
    ids.sort();
    ids.dedup();
    ids.truncate(MAX_MODELS);
    ids
}

fn openrouter_summary(value: &Value, billing: &str) -> String {
    let data = value.get("data").unwrap_or(value);
    let money = |key: &str| {
        data.get(key)
            .and_then(Value::as_f64)
            .filter(|amount| amount.is_finite())
    };
    let mut text = format!("Connected to OpenRouter with this key. {billing}");
    if let Some(spent) = money("usage") {
        text.push_str(&format!(" Key usage so far: ${spent:.2}."));
    }
    match (money("limit"), money("limit_remaining")) {
        (Some(limit), Some(remaining)) => {
            let reset = data
                .get("limit_reset")
                .and_then(Value::as_str)
                .filter(|reset| !reset.is_empty())
                .map(|reset| format!(", resets {}", clean(reset, None)))
                .unwrap_or_default();
            text.push_str(&format!(
                " Remaining key limit: ${remaining:.2} of ${limit:.2}{reset}."
            ));
        }
        _ if data.get("limit") == Some(&Value::Null) => {
            text.push_str(" This key has no spending limit.")
        }
        _ => text.push_str(" Spending-limit information is unavailable."),
    }
    if data.get("is_free_tier").and_then(Value::as_bool) == Some(true) {
        text.push_str(" The account is on the free tier.");
    }
    text
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };

    use super::*;
    use crate::vault::Secret;

    const KEY: &str = "fixture-secret-0123456789abcdef";

    fn summarize(steps: &[Step]) -> Vec<String> {
        steps
            .iter()
            .map(|step| match step {
                Step::Text(text) => format!("text:{text}"),
                Step::Usage(usage) => format!(
                    "usage:{}/{}/{:?}",
                    usage.input_tokens, usage.output_tokens, usage.cost_usd
                ),
                Step::Notice(_) => "notice".to_owned(),
                Step::Done => "done".to_owned(),
            })
            .collect()
    }

    fn run(route: Route, events: &[&str]) -> Result<Vec<String>> {
        let mut state = Parse::default();
        let mut steps = Vec::new();
        for event in events {
            handle_event(route, event, &mut state, "Provider", Some(KEY), &mut steps)?;
        }
        Ok(summarize(&steps))
    }

    #[test]
    fn sse_reassembles_events_across_arbitrary_chunk_boundaries() {
        let transcript = "\u{feff}: keep-alive\r\nevent: message\r\ndata: {\"text\":\"é😀\"}\r\n\r\ndata: line one\rdata: line two\r\rid: 7\ndata:no-space\n\ndata: [DONE]\n\n";
        let expected = [
            "{\"text\":\"é😀\"}",
            "line one\nline two",
            "no-space",
            "[DONE]",
        ];
        for size in [1, 2, 3, 5, 7, 11, transcript.len()] {
            let mut sse = Sse::default();
            let mut events = Vec::new();
            for chunk in transcript.as_bytes().chunks(size) {
                sse.feed(chunk, &mut events).unwrap();
            }
            sse.finish(&mut events).unwrap();
            assert_eq!(events, expected, "chunk size {size}");
        }
    }

    #[test]
    fn sse_rejects_oversized_lines_and_invalid_utf8() {
        let mut events = Vec::new();
        assert!(
            Sse::default()
                .feed(&vec![b'a'; MAX_SSE_LINE + 1], &mut events)
                .is_err()
        );
        assert!(Sse::default().feed(b"data: \xff\n", &mut events).is_err());
    }

    #[test]
    fn incomplete_events_and_early_terminators_do_not_complete_replies() {
        for bytes in [b"data: partial".as_slice(), b"data: partial\n".as_slice()] {
            let mut sse = Sse::default();
            let mut events = Vec::new();
            sse.feed(bytes, &mut events).unwrap();
            assert!(sse.finish(&mut events).is_err());
            assert!(events.is_empty(), "an unterminated event was published");
        }
        assert!(
            run(
                Route::Chat(Dialect::Compatible),
                &[r#"{"choices":[{"delta":{"content":"partial"}}]}"#, "[DONE]",]
            )
            .is_err()
        );
        assert!(run(Route::Responses, &["[DONE]"]).is_err());
        assert!(
            run(
                Route::Anthropic,
                &[
                    r#"{"type":"message_start","message":{"usage":{"input_tokens":1}}}"#,
                    r#"{"type":"message_stop"}"#,
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_whole_responses_are_not_successful_empty_answers() {
        let mut steps = Vec::new();
        for value in [
            json!({}),
            json!({"status":"in_progress","output":[]}),
            json!({"status":"completed"}),
        ] {
            assert!(responses_final(&value, true, "Provider", None, &mut steps).is_err());
        }
        assert!(
            anthropic_message(
                &json!({"type":"message","content":[]}),
                "Provider",
                None,
                &mut steps
            )
            .is_err()
        );
        assert!(steps.is_empty());
    }

    #[test]
    fn chat_stream_reports_text_length_notice_and_usage() {
        let steps = run(Route::Chat(Dialect::OpenAi), &[
            r#"{"choices":[{"delta":{"role":"assistant","content":""}}]}"#,
            r#"{"choices":[{"delta":{"content":"Hel"}}]}"#,
            r#"{"choices":[{"delta":{"content":"lo"},"finish_reason":"length"}]}"#,
            r#"{"choices":[],"usage":{"prompt_tokens":12,"completion_tokens":2,"total_tokens":14}}"#,
            "[DONE]",
        ])
        .unwrap();
        assert_eq!(
            steps,
            ["text:Hel", "text:lo", "notice", "usage:12/2/None", "done"]
        );
    }

    #[test]
    fn openrouter_mid_stream_error_fails_without_leaking_the_key() {
        let error = run(Route::Chat(Dialect::OpenRouter), &[
            r#"{"provider":"openai","choices":[{"delta":{"content":"par"}}]}"#,
            &format!(r#"{{"error":{{"code":"server_error","message":"upstream rejected {KEY}"}},"choices":[{{"delta":{{"content":""}},"finish_reason":"error"}}]}}"#),
        ])
        .unwrap_err()
        .to_string();
        assert!(error.contains("upstream rejected"), "{error}");
        assert!(!error.contains(KEY), "{error}");
    }

    #[test]
    fn openrouter_usage_frame_repeats_finish_without_a_second_notice() {
        let steps = run(Route::Chat(Dialect::OpenRouter), &[
            r#"{"provider":"anthropic","choices":[{"delta":{"content":"hi"},"finish_reason":"length"}]}"#,
            r#"{"choices":[{"delta":{"content":""},"finish_reason":"length"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"cost":0.25}}"#,
            "[DONE]",
        ])
        .unwrap();
        assert_eq!(
            steps,
            [
                "notice",
                "text:hi",
                "notice",
                "usage:3/1/Some(0.25)",
                "done"
            ]
        );
    }

    #[test]
    fn responses_stream_completes_with_usage_and_failures_are_errors() {
        let steps = run(Route::Responses, &[
            r#"{"type":"response.created","response":{"status":"in_progress"}}"#,
            r#"{"type":"response.output_text.delta","delta":"Hi"}"#,
            r#"{"type":"response.completed","response":{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"Hi"}]}],"usage":{"input_tokens":9,"output_tokens":1}}}"#,
        ])
        .unwrap();
        assert_eq!(steps, ["text:Hi", "usage:9/1/None", "done"]);
        let failed = run(
            Route::Responses,
            &[
                r#"{"type":"response.failed","response":{"status":"failed","error":{"code":"server_error","message":"model crashed"}}}"#,
            ],
        );
        assert!(failed.unwrap_err().to_string().contains("model crashed"));
        assert!(
            run(
                Route::Responses,
                &[r#"{"type":"error","message":"quota exhausted"}"#]
            )
            .is_err()
        );
    }

    #[test]
    fn anthropic_stream_accumulates_usage_and_refusals_fail() {
        let steps = run(Route::Anthropic, &[
            r#"{"type":"message_start","message":{"usage":{"input_tokens":20,"cache_read_input_tokens":5,"output_tokens":1}}}"#,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            r#"{"type":"ping"}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"hidden"}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#,
            r#"{"type":"message_delta","delta":{"stop_reason":"max_tokens"},"usage":{"input_tokens":20,"output_tokens":15}}"#,
            r#"{"type":"message_stop"}"#,
        ])
        .unwrap();
        assert_eq!(steps, ["text:Hello", "notice", "usage:25/15/None", "done"]);
        let refused = run(
            Route::Anthropic,
            &[
                r#"{"type":"message_delta","delta":{"stop_reason":"refusal","stop_details":{"category":"cyber","explanation":"Declined."}}}"#,
            ],
        );
        assert!(refused.unwrap_err().to_string().contains("cyber"));
        let overloaded = run(
            Route::Anthropic,
            &[r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#],
        );
        assert!(overloaded.unwrap_err().to_string().contains("Overloaded"));
        let unreported = run(
            Route::Anthropic,
            &[
                r#"{"type":"message_start","message":{}}"#,
                r#"{"type":"content_block_delta","delta":{"type":"text_delta","text":"hi"}}"#,
                r#"{"type":"message_delta","delta":{"stop_reason":"end_turn"}}"#,
                r#"{"type":"message_stop"}"#,
            ],
        )
        .unwrap();
        assert_eq!(
            unreported,
            ["text:hi", "done"],
            "missing counters must not become reported zero usage"
        );
    }

    #[test]
    fn prepare_sends_instructions_and_the_selected_history() {
        let messages = || {
            vec![
                Message::new(Role::System, "policy"),
                Message::new(Role::User, "a".repeat(10)),
                Message::new(Role::Assistant, "b".repeat(10)),
                Message::new(Role::Assistant, "   "),
                Message::new(Role::User, "c".repeat(10)),
            ]
        };
        let prepared = prepare(messages(), 25).unwrap();
        assert_eq!(prepared.system, "policy");
        assert_eq!(prepared.omitted, 2);
        assert!(matches!(&prepared.turns[..], [turn] if turn.user && turn.text == "c".repeat(10)));
        let everything = prepare(messages(), 1000).unwrap();
        assert_eq!((everything.turns.len(), everything.omitted), (3, 0));
        let mut ending_with_reply = messages();
        ending_with_reply.pop();
        assert!(
            prepare(ending_with_reply, 1000).is_err(),
            "a reply needs a final user message"
        );
    }

    #[test]
    fn clean_redacts_credentials_and_bounds_text() {
        let text = format!(
            "bad key {KEY}\nsk-ant-api03-AbC123xyz and {} for claude-opus-5-5",
            "Z9".repeat(24)
        );
        let cleaned = clean(&text, Some(KEY));
        assert!(
            !cleaned.contains(KEY) && !cleaned.contains("sk-ant") && !cleaned.contains("Z9Z9"),
            "{cleaned}"
        );
        assert!(
            cleaned.contains("claude-opus-5-5") && !cleaned.contains('\n'),
            "{cleaned}"
        );
        assert!(!clean("Rejected key xy!", Some("xy")).contains("xy"));
        assert!(
            !format!(
                "{:?}",
                ProviderEvent::Status(format!("sign-in code: {KEY}"))
            )
            .contains(KEY)
        );
        assert!(!format!("{:?}", ProviderEvent::CodexAuth(Some(Secret::new(KEY)))).contains(KEY));
        let long = clean(&"word ".repeat(200), None);
        assert!(long.chars().count() == MAX_ERROR_TEXT + 1 && long.ends_with('…'));
    }

    fn compatible(address: SocketAddr) -> Profile {
        let mut profile = Profile::new(ProviderKind::Compatible);
        profile.base_url = format!("http://{address}/v1");
        profile.api_style = ApiStyle::ChatCompletions;
        profile.model = "fixture-model".to_owned();
        profile.credential = Some(Secret::new(KEY));
        profile.max_output_tokens = 64;
        profile
    }

    fn request(address: SocketAddr, streaming: bool) -> Request {
        Request {
            profile: compatible(address),
            messages: vec![
                Message::new(Role::System, "be brief"),
                Message::new(Role::User, "hello"),
            ],
            context_chars: 10_000,
            streaming,
            data_dir: PathBuf::new(),
        }
    }

    async fn read_request(socket: &mut TcpStream) -> (String, Vec<u8>) {
        let mut data = Vec::new();
        let mut buffer = [0; 4096];
        let head_end = loop {
            let read = socket.read(&mut buffer).await.unwrap();
            assert!(read > 0, "client closed before sending a request");
            data.extend_from_slice(&buffer[..read]);
            if let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
        };
        let head = String::from_utf8(data[..head_end].to_vec()).unwrap();
        let length = head
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length:")
                    .map(|value| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut body = data[head_end..].to_vec();
        while body.len() < length {
            let read = socket.read(&mut buffer).await.unwrap();
            assert!(read > 0);
            body.extend_from_slice(&buffer[..read]);
        }
        (head, body)
    }

    async fn respond_once(listener: TcpListener, response: String) {
        let (mut socket, _) = listener.accept().await.unwrap();
        read_request(&mut socket).await;
        socket.write_all(response.as_bytes()).await.unwrap();
    }

    async fn collect(mut receiver: mpsc::Receiver<ProviderEvent>) -> Vec<ProviderEvent> {
        let mut events = Vec::new();
        while let Some(event) = receiver.recv().await {
            events.push(event);
        }
        events
    }

    #[tokio::test]
    async fn compatible_stream_round_trip_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, body) = read_request(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
            let events = "data: {\"choices\":[{\"delta\":{\"content\":\"Hé\"}}]}\r\n\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"llo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n".as_bytes();
            // Split inside a field, inside the two-byte `é`, and inside CRLF.
            for piece in [
                &events[..20],
                &events[20..41],
                &events[41..48],
                &events[48..],
            ] {
                socket.write_all(piece).await.unwrap();
                socket.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            (head, body)
        });
        let (sender, receiver) = mpsc::channel(16);
        stream(request(address, true), sender).await.unwrap();
        let events = collect(receiver).await;
        let text: String = events
            .iter()
            .filter_map(|event| match event {
                ProviderEvent::Delta(text) => Some(text.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "Héllo");
        assert!(
            matches!(events.last(), Some(ProviderEvent::Usage(usage)) if usage.input_tokens == 7 && usage.output_tokens == 2)
        );
        let (head, body) = server.await.unwrap();
        let head = head.to_ascii_lowercase();
        assert!(
            head.starts_with("post /v1/chat/completions http/1.1"),
            "{head}"
        );
        assert!(
            head.contains(&format!("authorization: bearer {KEY}")),
            "{head}"
        );
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["model"], "fixture-model");
        assert_eq!(body["stream"], true);
        assert_eq!(body["max_tokens"], 64);
        assert!(body.get("stream_options").is_none() && body.get("temperature").is_none());
        assert_eq!(
            body["messages"],
            json!([{ "role": "system", "content": "be brief" }, { "role": "user", "content": "hello" }])
        );
    }

    #[tokio::test]
    async fn non_streaming_reply_arrives_as_one_delta_then_usage() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"whole reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}"#;
        tokio::spawn(respond_once(
            listener,
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            ),
        ));
        let (sender, receiver) = mpsc::channel(16);
        stream(request(address, false), sender).await.unwrap();
        let events = collect(receiver).await;
        assert!(
            matches!(&events[..], [ProviderEvent::Delta(text), ProviderEvent::Usage(_)] if text == "whole reply")
        );
    }

    #[tokio::test]
    async fn redirects_are_refused_and_nothing_reaches_the_new_location() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let elsewhere = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let location = format!(
            "http://{}/v1/chat/completions",
            elsewhere.local_addr().unwrap()
        );
        tokio::spawn(respond_once(
            listener,
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nlocation: {location}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            ),
        ));
        let (sender, _receiver) = mpsc::channel(16);
        let error = stream(request(address, true), sender)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("redirect"), "{error}");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), elsewhere.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn http_errors_are_bounded_and_never_echo_the_key() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body = format!(
            r#"{{"error":{{"message":"Incorrect API key provided: {KEY}","type":"invalid_request_error"}}}}"#
        );
        tokio::spawn(respond_once(
            listener,
            format!(
                "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            ),
        ));
        let (sender, _receiver) = mpsc::channel(16);
        let error = format!(
            "{:#}",
            stream(request(address, true), sender).await.unwrap_err()
        );
        assert!(
            error.contains("401") && error.contains("Incorrect API key"),
            "{error}"
        );
        assert!(!error.contains(KEY), "{error}");
    }

    #[tokio::test]
    async fn dropping_the_stream_closes_the_provider_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            read_request(&mut socket).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
                .await
                .unwrap();
            let mut buffer = [0; 64];
            matches!(
                tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buffer)).await,
                Ok(Ok(0) | Err(_))
            )
        });
        let (sender, mut receiver) = mpsc::channel(16);
        let task = tokio::spawn(stream(request(address, true), sender));
        assert!(
            matches!(receiver.recv().await, Some(ProviderEvent::Delta(text)) if text == "partial")
        );
        task.abort();
        assert!(
            server.await.unwrap(),
            "the provider connection stayed open after cancellation"
        );
    }
}
