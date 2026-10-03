//! Subscription-only client for the pinned, optional Vyx Codex helper.
//!
//! `codex_runtime::launch` verifies the dedicated helper's digest, source revision,
//! fixed configuration and deny-all tool ceiling before starting its app-server.
//! A stock Codex executable is not accepted. Each operation owns volatile state;
//! each reply uses a new ephemeral thread containing only the prepared conversation.
//! Dropping this future drops the runtime Session and kills its process.
//!
//! Protocol: <https://developers.openai.com/codex/app-server>, pinned to rust-v0.157.1.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    future::Future,
    io,
    path::Path,
    time::Duration,
};

use anyhow::{Result, anyhow, bail, ensure};
use reqwest::Url;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
    time::timeout,
};
use zeroize::Zeroizing;

use super::{
    Profile, ProviderKind, codex_runtime,
    model::{MAX_MESSAGE_BYTES, MAX_MESSAGES, validate_codex_auth},
    providers::{MAX_MODELS, MAX_REPLY_BYTES, Output, Prepared, ProviderEvent, Step, usage},
};
use crate::vault::Secret;

pub const BILLING_NOTICE: &str = "Uses your ChatGPT account's Codex entitlement and its usage limits, not OpenAI API credits. The optional Vyx Codex helper must be installed explicitly. Vyx never switches to API billing or another model after a failure.";
const PROTOCOL_VERSION: &str = "0.157.1";
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;
const MAX_OPERATION_BYTES: usize = 64 * 1024 * 1024;
const MAX_EVENTS: usize = 100_000;
const MAX_PENDING: usize = 128;
const MAX_ITEMS: usize = 4096;
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(300);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const TURN_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const CANCELLED: &str = "The Codex operation was cancelled.";
const BOUNDARY: &str = "The Codex helper attempted an unsupported tool, permission, or credential interaction. Vyx denied it and stopped the operation.";
const PROTOCOL_ERROR: &str = "The Codex helper returned an invalid or mismatched protocol message. The operation was stopped.";

#[derive(Clone, Copy, Debug)]
pub enum LoginMethod {
    Browser,
    DeviceCode,
}

/// Explicit opt-in only: launching a profile never downloads its runtime.
pub async fn install(data_dir: &Path) -> Result<String> {
    codex_runtime::install(data_dir).await
}

/// Whether this profile's helper metadata is present. Not a hash, ELF, or account check.
pub fn helper_installed(profile: &Profile, data_dir: &Path) -> bool {
    codex_runtime::installed(profile, data_dir)
}

pub async fn login(
    profile: &Profile,
    data_dir: &Path,
    method: LoginMethod,
    sender: mpsc::Sender<ProviderEvent>,
) -> Result<String> {
    run(profile, data_dir, Operation::Login(method), &sender)
        .await?
        .summary()
}

/// Reads only the account seeded from this Vyx profile, never ~/.codex or a keyring.
pub async fn status(
    profile: &Profile,
    data_dir: &Path,
    sender: mpsc::Sender<ProviderEvent>,
) -> Result<String> {
    run(profile, data_dir, Operation::Status, &sender)
        .await?
        .summary()
}

/// Refreshes this profile's account and lists models. It never creates a turn.
pub async fn test(
    profile: &Profile,
    data_dir: &Path,
    sender: mpsc::Sender<ProviderEvent>,
) -> Result<String> {
    run(profile, data_dir, Operation::Test, &sender)
        .await?
        .summary()
}

pub async fn models(
    profile: &Profile,
    data_dir: &Path,
    sender: mpsc::Sender<ProviderEvent>,
) -> Result<Vec<String>> {
    match run(profile, data_dir, Operation::Models, &sender).await? {
        Reply::Models(models) => Ok(models),
        _ => unreachable!("model operation returns model IDs"),
    }
}

pub(super) async fn stream(
    profile: &Profile,
    data_dir: &Path,
    prepared: &Prepared,
    streaming: bool,
    sender: &mpsc::Sender<ProviderEvent>,
) -> Result<()> {
    validate_conversation(prepared)?;
    run(
        profile,
        data_dir,
        Operation::Stream(prepared, streaming),
        sender,
    )
    .await?;
    Ok(())
}

#[derive(Clone, Copy)]
enum Operation<'a> {
    Login(LoginMethod),
    Status,
    Test,
    Models,
    Stream(&'a Prepared, bool),
}

enum Reply {
    Summary(String),
    Models(Vec<String>),
    Complete,
}

impl Reply {
    fn summary(self) -> Result<String> {
        match self {
            Self::Summary(text) => Ok(text),
            _ => unreachable!("account operation returns a summary"),
        }
    }
}

async fn run(
    profile: &Profile,
    data_dir: &Path,
    operation: Operation<'_>,
    sender: &mpsc::Sender<ProviderEvent>,
) -> Result<Reply> {
    profile.validate()?;
    ensure!(
        profile.kind == ProviderKind::Codex,
        "This operation requires a Codex subscription profile."
    );
    let mut session = cancellable(sender, codex_runtime::launch(profile, data_dir)).await?;
    let credential_reader = session.credential_reader();
    let (result, previous_auth) = {
        let mut wire = Wire::new(&mut session.input, &mut session.output);
        wire.last_auth = profile.codex_auth.clone();
        if !matches!(operation, Operation::Login(_)) {
            wire.credential_reader = Some(&credential_reader);
        }
        let deadline = match operation {
            Operation::Login(_) => LOGIN_TIMEOUT,
            Operation::Stream(..) => TURN_TIMEOUT,
            _ => READ_TIMEOUT,
        };
        let result = cancellable(sender, async {
            timeout(deadline, operate(&mut wire, profile, operation, sender))
                .await
                .unwrap_or_else(|_| Err(anyhow!("The Codex operation timed out and was stopped.")))
        })
        .await;
        if result.is_err() {
            // Best effort only; Session teardown is the unconditional cancellation boundary.
            wire.cancel().await;
        }
        (result, wire.last_auth.take())
    };
    // A failed turn can still rotate a refresh token. Preserve it before returning
    // the error, but never persist an incomplete or cancelled login.
    let credentials = if result.is_ok() || !matches!(operation, Operation::Login(_)) {
        session.credentials()
    } else {
        Ok(None)
    };
    let shutdown = session.shutdown().await;
    let result = finish_operation(
        previous_auth.as_ref(),
        operation,
        result,
        credentials,
        sender,
    )
    .await;
    shutdown?;
    result
}

async fn cancellable<T>(
    sender: &mpsc::Sender<ProviderEvent>,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        biased;
        _ = sender.closed() => Err(anyhow!(CANCELLED)),
        result = operation => result,
    }
}

async fn finish_operation(
    previous_auth: Option<&Secret>,
    operation: Operation<'_>,
    result: Result<Reply>,
    credentials: Result<Option<Secret>>,
    sender: &mpsc::Sender<ProviderEvent>,
) -> Result<Reply> {
    if matches!(operation, Operation::Login(_)) && result.is_err() {
        return result;
    }
    let credentials = credentials?;
    if result.is_ok() {
        if matches!(
            operation,
            Operation::Login(_) | Operation::Test | Operation::Models | Operation::Stream(..)
        ) {
            ensure!(
                credentials.is_some(),
                "Codex did not retain this Vyx profile's ChatGPT sign-in. Sign in again."
            );
        }
    }
    publish_credentials(previous_auth, credentials, sender).await?;
    result
}

async fn publish_credentials(
    previous: Option<&Secret>,
    current: Option<Secret>,
    sender: &mpsc::Sender<ProviderEvent>,
) -> Result<()> {
    if let Some(auth) = &current {
        validate_codex_auth(auth)?;
    }
    if previous != current.as_ref() {
        emit(sender, ProviderEvent::CodexAuth(current)).await?;
    }
    Ok(())
}

async fn operate<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    wire: &mut Wire<'_, R, W>,
    profile: &Profile,
    operation: Operation<'_>,
    sender: &mpsc::Sender<ProviderEvent>,
) -> Result<Reply> {
    wire.initialize().await?;
    let reply: Result<Reply> = match operation {
        Operation::Login(method) => {
            login_account(wire, method, sender).await?;
            let account = read_account(wire, false, sender).await?;
            ensure!(
                account.is_some(),
                "Codex sign-in completed without a ChatGPT account."
            );
            Ok(Reply::Summary(account_summary(account)))
        }
        Operation::Status => Ok(Reply::Summary(account_summary(
            read_account(wire, false, sender).await?,
        ))),
        Operation::Test | Operation::Models => {
            let account = read_account(wire, true, sender).await?;
            ensure!(
                account.is_some(),
                "Sign in to ChatGPT for this Vyx profile first."
            );
            let catalog = model_catalog(wire).await?;
            if matches!(operation, Operation::Test) {
                Ok(Reply::Summary(format!(
                    "{} Model discovery succeeded. No inference was requested.",
                    account_summary(account)
                )))
            } else {
                Ok(Reply::Models(
                    catalog.into_iter().map(|model| model.id).collect(),
                ))
            }
        }
        Operation::Stream(prepared, streaming) => {
            ensure!(
                read_account(wire, true, sender).await?.is_some(),
                "Sign in to ChatGPT for this Vyx profile first."
            );
            let catalog = model_catalog(wire).await?;
            let model = select_model(&catalog, profile)?;
            wire.drain_background(sender).await?;
            emit(sender, ProviderEvent::Status(format!(
                "Using {} with your ChatGPT Codex entitlement. Codex does not expose a maximum-output-token control; the configured {}-token limit cannot be applied. Vyx still bounds reply size and supports Stop.",
                model.id, profile.max_output_tokens
            ))).await?;
            stream_turn(wire, profile, prepared, &model.id, streaming, sender).await?;
            Ok(Reply::Complete)
        }
    };
    let reply = reply?;
    if !matches!(operation, Operation::Stream(..)) {
        wire.drain_background(sender).await?;
    }
    Ok(reply)
}

fn account_summary(account: Option<&'static str>) -> String {
    match account {
        Some(plan) => format!("ChatGPT signed in ({plan}). {BILLING_NOTICE}"),
        None => "This Vyx profile is not signed in to ChatGPT. Use Sign in; Vyx does not import another Codex account.".into(),
    }
}

async fn read_account<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    wire: &mut Wire<'_, R, W>,
    refresh: bool,
    sender: &mpsc::Sender<ProviderEvent>,
) -> Result<Option<&'static str>> {
    let response = wire
        .request("account/read", json!({"refreshToken": refresh}))
        .await?;
    let account = account_kind(&response)?;
    // A completed refresh is committed before model discovery or a cancellable
    // inference can begin. An aborted turn must not roll back a rotated token.
    wire.checkpoint_credentials(sender, account.is_some())
        .await?;
    Ok(account)
}

fn account_kind(response: &Value) -> Result<Option<&'static str>> {
    ensure!(
        response["requiresOpenaiAuth"] == true,
        "Codex is not using the required ChatGPT authentication boundary."
    );
    let account = response
        .get("account")
        .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
    if account.is_null() {
        return Ok(None);
    }
    ensure!(
        account["type"] == "chatgpt",
        "Codex returned a non-ChatGPT account. Vyx will not use API billing for a subscription profile."
    );
    // Never interpolate arbitrary helper strings, email addresses, or error bodies.
    Ok(Some(match account["planType"].as_str() {
        Some("free") => "Free",
        Some("go") => "Go",
        Some("plus") => "Plus",
        Some("pro") => "Pro",
        Some("team") => "Team",
        Some("business") => "Business",
        Some("enterprise") => "Enterprise",
        Some("edu") => "Edu",
        _ => "plan not reported",
    }))
}

async fn login_account<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    wire: &mut Wire<'_, R, W>,
    method: LoginMethod,
    sender: &mpsc::Sender<ProviderEvent>,
) -> Result<()> {
    let kind = match method {
        LoginMethod::Browser => "chatgpt",
        LoginMethod::DeviceCode => "chatgptDeviceCode",
    };
    let response = wire
        .request("account/login/start", json!({"type": kind}))
        .await?;
    ensure!(response["type"] == kind, PROTOCOL_ERROR);
    let login_id = identifier(&response["loginId"])?;
    wire.login_id = Some(login_id.to_owned());
    let (url, code) = match method {
        LoginMethod::Browser => (login_url(&response["authUrl"])?, None),
        LoginMethod::DeviceCode => {
            let url = login_url(&response["verificationUrl"])?;
            let code = response["userCode"]
                .as_str()
                .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
            ensure!(
                !code.is_empty()
                    && code.len() <= 64
                    && code.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-'),
                PROTOCOL_ERROR
            );
            (url, Some(Secret::new(code)))
        }
    };
    emit(
        sender,
        ProviderEvent::CodexLogin {
            url: Secret::new(url),
            code,
        },
    )
    .await?;
    loop {
        let notice = wire.notification().await?;
        match notice.method.as_str() {
            "account/login/completed" => {
                ensure!(
                    notice.params["loginId"].as_str() == Some(login_id),
                    PROTOCOL_ERROR
                );
                ensure!(
                    notice.params["success"] == true,
                    "ChatGPT sign-in did not complete. The code may have expired or sign-in was declined; start sign-in again."
                );
                wire.login_id = None;
                return Ok(());
            }
            _ => background_notice(&notice, sender).await?,
        }
    }
}

fn login_url(value: &Value) -> Result<&str> {
    let text = value.as_str().ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
    ensure!(
        text.len() <= 8192 && !text.chars().any(char::is_control),
        PROTOCOL_ERROR
    );
    let url = Url::parse(text).map_err(|_| anyhow!(PROTOCOL_ERROR))?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("auth.openai.com")
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url.fragment().is_none(),
        "Codex returned an unexpected sign-in destination. No link was opened."
    );
    Ok(text)
}

struct Model {
    id: String,
    default: bool,
    efforts: Vec<String>,
}

async fn model_catalog<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    wire: &mut Wire<'_, R, W>,
) -> Result<Vec<Model>> {
    let mut models = Vec::new();
    let mut ids = HashSet::new();
    let mut cursors = HashSet::new();
    let mut cursor = None::<String>;
    for _ in 0..10 {
        let response = wire
            .request(
                "model/list",
                json!({"cursor": cursor, "limit": 500, "includeHidden": false}),
            )
            .await?;
        let data = response["data"]
            .as_array()
            .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
        ensure!(
            models.len() + data.len() <= MAX_MODELS,
            "Codex returned too many models."
        );
        for entry in data {
            let id = identifier(&entry["model"])?;
            ensure!(
                id.len() <= 256 && ids.insert(id.to_owned()),
                "Codex returned invalid or duplicate model IDs."
            );
            let efforts = entry["supportedReasoningEfforts"]
                .as_array()
                .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
            ensure!(efforts.len() <= 16, PROTOCOL_ERROR);
            let efforts = efforts
                .iter()
                .map(|effort| {
                    let effort = identifier(&effort["reasoningEffort"])?;
                    ensure!(effort.len() <= 32, PROTOCOL_ERROR);
                    Ok(effort.to_owned())
                })
                .collect::<Result<Vec<_>>>()?;
            let default = entry["isDefault"]
                .as_bool()
                .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
            models.push(Model {
                id: id.to_owned(),
                default,
                efforts,
            });
        }
        match response.get("nextCursor") {
            Some(Value::Null) => {
                ensure!(!models.is_empty(), "Codex returned no subscription models.");
                models.sort_by(|left, right| left.id.cmp(&right.id));
                return Ok(models);
            }
            Some(next) => {
                let next = identifier(next)?;
                ensure!(
                    cursors.insert(next.to_owned()),
                    "Codex repeated its model-list cursor."
                );
                cursor = Some(next.to_owned());
            }
            None => bail!(PROTOCOL_ERROR),
        }
    }
    bail!("Codex model discovery exceeded the page limit.")
}

fn select_model<'a>(models: &'a [Model], profile: &Profile) -> Result<&'a Model> {
    let mut candidates = models.iter().filter(|model| {
        if profile.model.is_empty() {
            model.default
        } else {
            model.id == profile.model
        }
    });
    let selected = candidates.next().ok_or_else(|| anyhow!("The selected Codex model is unavailable. Choose a listed model; Vyx will not substitute another one."))?;
    ensure!(
        candidates.next().is_none(),
        "Codex returned an ambiguous default model."
    );
    if let Some(effort) = &profile.reasoning_effort {
        ensure!(
            selected.efforts.contains(effort),
            "The selected Codex model does not support this reasoning effort. Change the profile setting explicitly."
        );
    }
    Ok(selected)
}

fn validate_conversation(prepared: &Prepared) -> Result<()> {
    ensure!(
        !prepared.turns.is_empty()
            && prepared.turns.len() <= MAX_MESSAGES
            && prepared.turns.last().is_some_and(|turn| turn.user),
        "Codex needs a bounded conversation ending with your message."
    );
    let mut bytes = prepared.system.len();
    for turn in &prepared.turns {
        ensure!(
            turn.text.len() <= MAX_MESSAGE_BYTES,
            "A Codex conversation message is too large."
        );
        bytes = bytes
            .checked_add(turn.text.len())
            .ok_or_else(|| anyhow!("The Codex conversation is too large."))?;
    }
    ensure!(
        bytes <= MAX_LINE_BYTES,
        "The Codex conversation is too large."
    );
    Ok(())
}

async fn stream_turn<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    wire: &mut Wire<'_, R, W>,
    profile: &Profile,
    prepared: &Prepared,
    model: &str,
    streaming: bool,
    sender: &mpsc::Sender<ProviderEvent>,
) -> Result<()> {
    let mut config = json!({});
    if let Some(effort) = &profile.reasoning_effort {
        config["model_reasoning_effort"] = json!(effort);
    }
    let response = wire
        .request(
            "thread/start",
            json!({
                "model": model, "modelProvider": "openai", "allowProviderModelFallback": false,
                "cwd": "/work", "approvalPolicy": "never", "sandbox": "read-only",
                "ephemeral": true, "baseInstructions": prepared.system, "developerInstructions": "",
                "environments": [], "dynamicTools": [], "selectedCapabilityRoots": [],
                "experimentalRawEvents": false, "config": config,
            }),
        )
        .await?;
    let thread = identifier(&response["thread"]["id"])?;
    ensure!(
        response["thread"]["ephemeral"] == true
            && response["thread"]["path"].is_null()
            && response["model"] == model
            && response["modelProvider"] == "openai"
            && response["approvalPolicy"] == "never"
            && response["sandbox"]["type"] == "readOnly"
            && response["cwd"] == "/work",
        "Codex did not honor the ephemeral, subscription-only thread boundary."
    );
    if let Some(effort) = &profile.reasoning_effort {
        ensure!(
            response["reasoningEffort"].as_str() == Some(effort),
            "Codex did not honor the requested reasoning effort."
        );
    }
    if let Some(sources) = response.get("instructionSources") {
        ensure!(
            sources.as_array().is_some_and(Vec::is_empty),
            "Codex loaded an unexpected instruction source."
        );
    }
    let (last, history) = prepared
        .turns
        .split_last()
        .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
    if !history.is_empty() {
        let items: Vec<Value> = history.iter().map(|turn| json!({
            "type": "message", "role": if turn.user { "user" } else { "assistant" },
            "content": [{"type": if turn.user { "input_text" } else { "output_text" }, "text": turn.text}],
        })).collect();
        wire.request(
            "thread/inject_items",
            json!({"threadId": thread, "items": items}),
        )
        .await?;
    }
    let response = wire
        .request(
            "turn/start",
            json!({
                "threadId": thread, "model": model, "effort": profile.reasoning_effort,
                "input": [{"type": "text", "text": last.text, "text_elements": []}],
            }),
        )
        .await?;
    let turn = identifier(&response["turn"]["id"])?;
    ensure!(response["turn"]["status"] == "inProgress", PROTOCOL_ERROR);
    wire.active_turn = Some((thread.to_owned(), turn.to_owned()));
    let mut state = TurnState::new(thread.to_owned(), turn.to_owned());
    let mut output = Output::new(sender, streaming);
    loop {
        let notice = wire.notification().await?;
        if notice.method == "account/updated" {
            wire.checkpoint_credentials(sender, false).await?;
        }
        if state.apply(notice, &mut output, sender).await? {
            wire.active_turn = None;
            return output.finish().await;
        }
    }
}

struct TextItem {
    text: String,
    complete: bool,
}

struct TurnState {
    thread: String,
    turn: String,
    text: HashMap<String, TextItem>,
    bytes: usize,
}

impl TurnState {
    fn new(thread: String, turn: String) -> Self {
        Self {
            thread,
            turn,
            text: HashMap::new(),
            bytes: 0,
        }
    }

    async fn apply(
        &mut self,
        notice: Notice,
        output: &mut Output<'_>,
        sender: &mpsc::Sender<ProviderEvent>,
    ) -> Result<bool> {
        let params = &notice.params;
        if let Some(thread) = params.get("threadId").filter(|id| !id.is_null()) {
            ensure!(thread.as_str() == Some(&self.thread), PROTOCOL_ERROR);
        }
        if let Some(turn) = params.get("turnId") {
            ensure!(turn.as_str() == Some(&self.turn), PROTOCOL_ERROR);
        }
        match notice.method.as_str() {
            "thread/started" => ensure!(
                params["thread"]["id"].as_str() == Some(&self.thread),
                PROTOCOL_ERROR
            ),
            "turn/started" => {
                self.thread_scope(params)?;
                ensure!(
                    params["turn"]["id"].as_str() == Some(&self.turn),
                    PROTOCOL_ERROR
                );
            }
            "item/started" => {
                self.scope(params)?;
                allowed_item(&params["item"])?;
                if params["item"]["type"] == "agentMessage" {
                    let id = identifier(&params["item"]["id"])?;
                    ensure!(
                        self.text.len() < MAX_ITEMS && !self.text.contains_key(id),
                        PROTOCOL_ERROR
                    );
                    self.text.insert(
                        id.to_owned(),
                        TextItem {
                            text: String::new(),
                            complete: false,
                        },
                    );
                }
            }
            "item/agentMessage/delta" => {
                self.scope(params)?;
                let id = identifier(&params["itemId"])?;
                let delta = params["delta"]
                    .as_str()
                    .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
                let item = self
                    .text
                    .get_mut(id)
                    .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
                ensure!(!item.complete, PROTOCOL_ERROR);
                self.bytes += delta.len();
                ensure!(
                    self.bytes <= MAX_REPLY_BYTES,
                    "The Codex reply exceeded Vyx's size limit and was stopped."
                );
                item.text.push_str(delta);
                output.apply(Step::Text(delta.to_owned())).await?;
            }
            "item/completed" => {
                self.scope(params)?;
                self.complete_item(&params["item"], output).await?;
            }
            "thread/tokenUsage/updated" => {
                self.scope(params)?;
                let total = &params["tokenUsage"]["total"];
                let input = total["inputTokens"]
                    .as_u64()
                    .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
                let out = total["outputTokens"]
                    .as_u64()
                    .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
                output.apply(Step::Usage(usage(input, out, None))).await?;
            }
            "turn/completed" => {
                self.thread_scope(params)?;
                let turn = &params["turn"];
                ensure!(turn["id"].as_str() == Some(&self.turn), PROTOCOL_ERROR);
                match turn["status"].as_str() {
                    Some("completed") => {}
                    Some("interrupted") => bail!(CANCELLED),
                    Some("failed") => return Err(provider_error(&turn["error"])),
                    _ => bail!(PROTOCOL_ERROR),
                }
                let items = turn["items"]
                    .as_array()
                    .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
                ensure!(items.len() <= MAX_ITEMS, PROTOCOL_ERROR);
                for item in items {
                    self.complete_item(item, output).await?;
                }
                ensure!(self.text.values().all(|item| item.complete), PROTOCOL_ERROR);
                return Ok(true);
            }
            "error" => {
                self.scope(params)?;
                if params["willRetry"] == true {
                    emit(
                        sender,
                        ProviderEvent::Status(format!(
                            "{} Codex is retrying the same subscription request.",
                            provider_error(&params["error"])
                        )),
                    )
                    .await?;
                } else {
                    return Err(provider_error(&params["error"]));
                }
            }
            "model/rerouted" => bail!(
                "Codex attempted to change the selected model. Vyx stopped the reply instead of accepting a fallback."
            ),
            "thread/status/changed" => self.thread_scope(params)?,
            "item/reasoning/summaryTextDelta"
            | "item/reasoning/summaryPartAdded"
            | "item/reasoning/textDelta"
            | "model/verification"
            | "model/safetyBuffering/updated"
            | "turn/moderationMetadata" => {
                self.scope(params)?;
            }
            _ => background_notice(&notice, sender).await?,
        }
        Ok(false)
    }

    fn scope(&self, params: &Value) -> Result<()> {
        self.thread_scope(params)?;
        ensure!(
            params["turnId"].as_str() == Some(&self.turn),
            PROTOCOL_ERROR
        );
        Ok(())
    }

    fn thread_scope(&self, params: &Value) -> Result<()> {
        ensure!(
            params["threadId"].as_str() == Some(&self.thread),
            PROTOCOL_ERROR
        );
        Ok(())
    }

    async fn complete_item(&mut self, item: &Value, output: &mut Output<'_>) -> Result<()> {
        allowed_item(item)?;
        if item["type"] != "agentMessage" {
            return Ok(());
        }
        let id = identifier(&item["id"])?;
        let final_text = item["text"]
            .as_str()
            .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
        let state = self
            .text
            .get_mut(id)
            .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
        ensure!(
            final_text.starts_with(&state.text) && (!state.complete || final_text == state.text),
            PROTOCOL_ERROR
        );
        let suffix = &final_text[state.text.len()..];
        self.bytes += suffix.len();
        ensure!(
            self.bytes <= MAX_REPLY_BYTES,
            "The Codex reply exceeded Vyx's size limit and was stopped."
        );
        if !suffix.is_empty() {
            state.text.push_str(suffix);
            output.apply(Step::Text(suffix.to_owned())).await?;
        }
        state.complete = true;
        Ok(())
    }
}

fn allowed_item(item: &Value) -> Result<()> {
    ensure!(
        matches!(
            item["type"].as_str(),
            Some("userMessage" | "agentMessage" | "reasoning")
        ),
        BOUNDARY
    );
    ensure!(
        item.get("questions")
            .is_none_or(|value| value.is_null() || value.as_array().is_some_and(Vec::is_empty)),
        BOUNDARY
    );
    Ok(())
}

async fn background_notice(notice: &Notice, sender: &mpsc::Sender<ProviderEvent>) -> Result<()> {
    match notice.method.as_str() {
        "account/updated" => validate_account_notice(&notice.params)?,
        "account/rateLimits/updated" => {}
        "remoteControl/status/changed" => validate_remote_control(&notice.params)?,
        "warning" | "deprecationNotice" => {
            emit(sender, ProviderEvent::Status("Codex reported a runtime warning. Raw helper diagnostics are withheld to protect sign-in credentials.".into())).await?;
        }
        "configWarning" => {
            bail!("Codex reported an invalid runtime configuration. Vyx stopped the operation.")
        }
        _ => bail!(BOUNDARY),
    }
    Ok(())
}

fn validate_account_notice(params: &Value) -> Result<()> {
    ensure!(
        params
            .get("authMode")
            .is_some_and(|mode| mode.is_null() || mode == "chatgpt"),
        BOUNDARY
    );
    Ok(())
}
fn validate_remote_control(params: &Value) -> Result<()> {
    ensure!(
        params["status"] == "disabled" && params["environmentId"].is_null(),
        BOUNDARY
    );
    Ok(())
}

fn provider_error(error: &Value) -> anyhow::Error {
    let info = &error["codexErrorInfo"];
    let text = match info.as_str() {
        Some("unauthorized") => {
            "ChatGPT sign-in expired or was rejected. Sign in again for this Vyx profile."
        }
        Some("usageLimitExceeded" | "sessionBudgetExceeded") => {
            "The ChatGPT Codex entitlement or usage budget is exhausted. No API billing was substituted."
        }
        Some("rateLimitExceeded") => "The ChatGPT Codex request was rate limited. Try again later.",
        Some("contextWindowExceeded") => {
            "The conversation exceeds this Codex model's context window. Reduce the selected context."
        }
        Some("serverOverloaded" | "internalServerError") => {
            "The Codex subscription service is unavailable. Try again later."
        }
        Some("badRequest") => {
            "Codex rejected the selected model, controls, or conversation. Review this profile's settings."
        }
        Some("cyberPolicy" | "misalignmentPolicyViolation") => {
            "The Codex subscription service declined this request under its usage policy."
        }
        _ if info.is_object() => {
            "The Codex subscription connection failed or its response stream was interrupted."
        }
        _ => match error["code"].as_i64() {
            Some(-32601 | -32602) => {
                "The Vyx Codex helper rejected an unsupported protocol method or parameter."
            }
            _ => {
                "The Codex subscription operation failed. Raw helper errors are withheld to protect sign-in credentials."
            }
        },
    };
    anyhow!(text)
}

fn identifier(value: &Value) -> Result<&str> {
    let text = value.as_str().ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
    ensure!(
        !text.is_empty()
            && text.len() <= 512
            && !text.chars().any(|c| c.is_control() || c.is_whitespace()),
        PROTOCOL_ERROR
    );
    Ok(text)
}

async fn emit(sender: &mpsc::Sender<ProviderEvent>, event: ProviderEvent) -> Result<()> {
    sender.send(event).await.map_err(|_| anyhow!(CANCELLED))
}

struct Notice {
    method: String,
    params: Value,
    bytes: usize,
}

enum Frame {
    Response { id: u64, result: Result<Value> },
    Notice(Notice),
}

type CredentialReader = dyn Fn() -> Result<Option<Secret>> + Send + Sync;

/// A single in-flight RPC and a bounded notification queue. No raw protocol value
/// is formatted in an error or implements Debug.
struct Wire<'a, R, W> {
    input: &'a mut W,
    output: &'a mut R,
    next_id: u64,
    pending: VecDeque<Notice>,
    pending_bytes: usize,
    received_bytes: usize,
    received_events: usize,
    login_id: Option<String>,
    active_turn: Option<(String, String)>,
    credential_reader: Option<&'a CredentialReader>,
    last_auth: Option<Secret>,
}

impl<'a, R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin> Wire<'a, R, W> {
    fn new(input: &'a mut W, output: &'a mut R) -> Self {
        Self {
            input,
            output,
            next_id: 1,
            pending: VecDeque::new(),
            pending_bytes: 0,
            received_bytes: 0,
            received_events: 0,
            login_id: None,
            active_turn: None,
            credential_reader: None,
            last_auth: None,
        }
    }

    async fn checkpoint_credentials(
        &mut self,
        sender: &mpsc::Sender<ProviderEvent>,
        signed_in: bool,
    ) -> Result<()> {
        let Some(read) = self.credential_reader else {
            return Ok(());
        };
        let current = read()?;
        if signed_in {
            ensure!(
                current.is_some(),
                "Codex did not retain this Vyx profile's ChatGPT sign-in. Sign in again."
            );
        }
        if let Some(auth) = &current {
            validate_codex_auth(auth)?;
        }
        if self.last_auth != current {
            emit(sender, ProviderEvent::CodexAuth(current.clone())).await?;
            self.last_auth = current;
        }
        Ok(())
    }

    async fn initialize(&mut self) -> Result<()> {
        let response = self.request("initialize", json!({
            "clientInfo": {"name": "vyx", "title": "Vyx AI", "version": env!("CARGO_PKG_VERSION")},
            "capabilities": {"experimentalApi": true, "explicitGatewayOauth": true},
        })).await?;
        let agent = response["userAgent"]
            .as_str()
            .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
        let version = agent
            .split_whitespace()
            .next()
            .and_then(|first| first.rsplit_once('/'))
            .map(|(_, version)| version);
        ensure!(
            version == Some(PROTOCOL_VERSION),
            "The Vyx Codex helper uses an unsupported protocol version. Install the matching optional runtime."
        );
        self.send(&json!({"method": "initialized"})).await
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        timeout(QUERY_TIMEOUT, async {
            let id = self.next_id;
            self.next_id += 1;
            self.send(&json!({"id": id, "method": method, "params": params}))
                .await?;
            loop {
                match self.receive().await? {
                    Frame::Response {
                        id: received,
                        result,
                    } => {
                        ensure!(received == id, PROTOCOL_ERROR);
                        return result;
                    }
                    Frame::Notice(notice) => {
                        self.pending_bytes += notice.bytes;
                        ensure!(
                            self.pending.len() < MAX_PENDING
                                && self.pending_bytes <= MAX_LINE_BYTES,
                            "Codex sent too many notifications before its response."
                        );
                        self.pending.push_back(notice);
                    }
                }
            }
        })
        .await
        .map_err(|_| anyhow!("The Codex helper did not answer in time."))?
    }

    async fn notification(&mut self) -> Result<Notice> {
        if let Some(notice) = self.pending.pop_front() {
            self.pending_bytes -= notice.bytes;
            return Ok(notice);
        }
        match self.receive().await? {
            Frame::Notice(notice) => Ok(notice),
            Frame::Response { .. } => bail!(PROTOCOL_ERROR),
        }
    }

    async fn drain_background(&mut self, sender: &mpsc::Sender<ProviderEvent>) -> Result<()> {
        while let Some(notice) = self.pending.pop_front() {
            self.pending_bytes -= notice.bytes;
            background_notice(&notice, sender).await?;
        }
        Ok(())
    }

    async fn receive(&mut self) -> Result<Frame> {
        let line = timeout(READ_TIMEOUT, read_line(self.output, MAX_LINE_BYTES))
            .await
            .map_err(|_| anyhow!("The Codex helper stopped responding."))??;
        self.received_bytes += line.len();
        self.received_events += 1;
        ensure!(
            self.received_bytes <= MAX_OPERATION_BYTES && self.received_events <= MAX_EVENTS,
            "Codex exceeded the operation's protocol traffic limit."
        );
        let mut value: Value =
            serde_json::from_slice(&line).map_err(|_| anyhow!(PROTOCOL_ERROR))?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
        if let Some(method) = object.remove("method") {
            let method = method.as_str().ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
            ensure!(!method.is_empty() && method.len() <= 128, PROTOCOL_ERROR);
            if let Some(id) = object.remove("id") {
                ensure!(
                    id.as_i64().is_some() || id.as_str().is_some_and(|id| id.len() <= 128),
                    PROTOCOL_ERROR
                );
                self.deny(id, method).await?;
                bail!(BOUNDARY);
            }
            let params = object
                .remove("params")
                .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
            ensure!(
                params.is_object()
                    && !object.contains_key("result")
                    && !object.contains_key("error"),
                PROTOCOL_ERROR
            );
            // Reject tool dispatch notices before waiting for a pending RPC result.
            match method {
                "item/started" | "item/completed" => allowed_item(&params["item"])?,
                "model/rerouted" => {
                    bail!("Codex attempted a model fallback; Vyx stopped the operation.")
                }
                "account/updated" => validate_account_notice(&params)?,
                "remoteControl/status/changed" => validate_remote_control(&params)?,
                "configWarning" => bail!(
                    "Codex reported an invalid runtime configuration. Vyx stopped the operation."
                ),
                "account/login/completed"
                | "account/rateLimits/updated"
                | "thread/started"
                | "thread/status/changed"
                | "turn/started"
                | "turn/completed"
                | "thread/tokenUsage/updated"
                | "item/agentMessage/delta"
                | "item/reasoning/summaryTextDelta"
                | "item/reasoning/summaryPartAdded"
                | "item/reasoning/textDelta"
                | "model/verification"
                | "model/safetyBuffering/updated"
                | "turn/moderationMetadata"
                | "error"
                | "warning"
                | "deprecationNotice" => {}
                _ => bail!(BOUNDARY),
            }
            Ok(Frame::Notice(Notice {
                method: method.to_owned(),
                params,
                bytes: line.len(),
            }))
        } else {
            let id = object
                .remove("id")
                .and_then(|id| id.as_u64())
                .ok_or_else(|| anyhow!(PROTOCOL_ERROR))?;
            let result = match (object.remove("result"), object.remove("error")) {
                (Some(result), None) => Ok(result),
                (None, Some(error)) => Err(provider_error(&error)),
                _ => bail!(PROTOCOL_ERROR),
            };
            Ok(Frame::Response { id, result })
        }
    }

    async fn deny(&mut self, id: Value, method: &str) -> Result<()> {
        let response = match method {
            "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
                json!({"id": id, "result": {"decision": "decline"}})
            }
            "item/permissions/requestApproval" => {
                json!({"id": id, "result": {"permissions": {}, "scope": "turn"}})
            }
            "execCommandApproval" | "applyPatchApproval" => {
                json!({"id": id, "result": {"decision": "denied"}})
            }
            _ => {
                json!({"id": id, "error": {"code": -32601, "message": "Vyx does not provide tools, user-input tools, or credential prompts to this helper."}})
            }
        };
        self.send(&response).await
    }

    async fn send(&mut self, value: &Value) -> Result<()> {
        let mut bytes = BoundedJson {
            bytes: Zeroizing::new(Vec::new()),
        };
        serde_json::to_writer(&mut bytes, value)
            .map_err(|_| anyhow!("The Codex request exceeds the protocol size limit."))?;
        bytes.bytes.push(b'\n');
        self.input
            .write_all(&bytes.bytes)
            .await
            .map_err(|_| anyhow!("The Codex helper connection closed."))?;
        self.input
            .flush()
            .await
            .map_err(|_| anyhow!("The Codex helper connection closed."))
    }

    async fn cancel(&mut self) {
        let request = if let Some(login) = self.login_id.take() {
            Some(("account/login/cancel", json!({"loginId": login})))
        } else {
            self.active_turn.take().map(|(thread, turn)| {
                (
                    "turn/interrupt",
                    json!({"threadId": thread, "turnId": turn}),
                )
            })
        };
        if let Some((method, params)) = request {
            let id = self.next_id;
            let _ = timeout(
                Duration::from_secs(2),
                self.send(&json!({"id": id, "method": method, "params": params})),
            )
            .await;
        }
    }
}

struct BoundedJson {
    bytes: Zeroizing<Vec<u8>>,
}

impl io::Write for BoundedJson {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_LINE_BYTES.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("protocol size limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut line = Zeroizing::new(Vec::new());
    loop {
        let buffer = reader
            .fill_buf()
            .await
            .map_err(|_| anyhow!("The Codex helper connection closed."))?;
        ensure!(
            !buffer.is_empty(),
            "The Codex helper exited before completing the operation."
        );
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(buffer.len());
        ensure!(
            take <= limit.saturating_sub(line.len()),
            "The Codex helper exceeded the protocol line limit."
        );
        line.extend_from_slice(&buffer[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            ensure!(!line.is_empty(), PROTOCOL_ERROR);
            return Ok(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{BufReader, duplex};

    use super::*;
    use crate::ai::providers::Turn;

    fn auth(token: &str) -> Secret {
        Secret::new(
            json!({
                "auth_mode": "chatgpt", "OPENAI_API_KEY": null,
                "tokens": {"id_token": "fixture-id", "access_token": token,
                    "refresh_token": "fixture-refresh", "account_id": "fixture-account"}
            })
            .to_string(),
        )
    }

    fn notice(method: &str, params: Value) -> Notice {
        Notice {
            method: method.into(),
            params,
            bytes: 0,
        }
    }

    fn scoped(extra: Value) -> Value {
        let mut params = json!({"threadId": "thread", "turnId": "turn"});
        params
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        params
    }

    #[tokio::test]
    async fn framing_bounds_bytes_before_newline_and_rejects_truncation() {
        let mut reader = BufReader::with_capacity(1, "é\nnext\n".as_bytes());
        assert_eq!(&*read_line(&mut reader, 2).await.unwrap(), "é".as_bytes());
        assert_eq!(&*read_line(&mut reader, 4).await.unwrap(), b"next");
        for input in ["abc\n", "abc", "\n"] {
            let mut reader = BufReader::with_capacity(1, input.as_bytes());
            assert!(read_line(&mut reader, 2).await.is_err());
        }
        let mut reader = BufReader::new(&b"ok"[..]);
        assert!(
            read_line(&mut reader, 2).await.is_err(),
            "unterminated JSON must never be accepted at EOF"
        );
    }

    #[test]
    fn escaped_json_and_conversation_sizes_are_bounded() {
        let mut buffer = BoundedJson {
            bytes: Zeroizing::new(Vec::new()),
        };
        let escaped = json!("\0".repeat(MAX_LINE_BYTES / 6 + 1));
        assert!(serde_json::to_writer(&mut buffer, &escaped).is_err());
        assert!(buffer.bytes.len() <= MAX_LINE_BYTES);
        let mut conversation = Prepared {
            system: String::new(),
            turns: vec![Turn {
                user: true,
                text: "x".repeat(MAX_MESSAGE_BYTES),
            }],
            omitted: 0,
        };
        validate_conversation(&conversation).unwrap();
        conversation.turns[0].text.push('x');
        assert!(validate_conversation(&conversation).is_err());
        conversation.turns[0].text.clear();
        conversation.turns[0].user = false;
        assert!(validate_conversation(&conversation).is_err());
    }

    #[tokio::test]
    async fn protocol_errors_and_mismatched_responses_never_echo_secrets() {
        for response in [
            json!({"id": 2, "result": {"access_token": "private-fixture"}}),
            json!({"id": 1, "result": {}, "error": {"message": "private-fixture"}}),
            json!({"id": 1, "error": {"code": -32602, "message": "private-fixture", "data": {"token": "private-fixture"}}}),
            json!({"id": 1, "method": "account/chatgptAuthTokens/refresh", "params": {"token": "private-fixture"}}),
        ] {
            let input = format!("{response}\n");
            let mut reader = BufReader::new(input.as_bytes());
            let mut written = Vec::new();
            let mut wire = Wire::new(&mut written, &mut reader);
            let error = wire
                .request("account/read", json!({"refreshToken": false}))
                .await
                .unwrap_err();
            assert!(!format!("{error:#}").contains("private-fixture"));
            assert!(
                !String::from_utf8(written)
                    .unwrap()
                    .contains("private-fixture")
            );
        }
        let error = provider_error(&json!({
            "message": "token private-fixture", "codexErrorInfo": "unauthorized",
            "additionalDetails": {"refresh_token": "private-fixture"},
        }));
        assert!(error.to_string().contains("Sign in again"));
        assert!(!format!("{error:#}").contains("private-fixture"));
    }

    #[tokio::test]
    async fn unexpected_requests_are_denied_not_executed_or_answered_with_fake_data() {
        for method in [
            "item/commandExecution/requestApproval",
            "item/fileChange/requestApproval",
            "item/permissions/requestApproval",
            "item/tool/call",
            "item/tool/requestUserInput",
            "mcpServer/elicitation/request",
            "account/chatgptAuthTokens/refresh",
            "unknown/request",
        ] {
            let input = format!(
                "{}\n",
                json!({"id": "server-request", "method": method, "params": {}})
            );
            let mut reader = BufReader::new(input.as_bytes());
            let mut written = Vec::new();
            let mut wire = Wire::new(&mut written, &mut reader);
            assert!(wire.notification().await.is_err());
            let refusal: Value = serde_json::from_slice(&written).unwrap();
            assert_eq!(refusal["id"], "server-request");
            match method {
                "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
                    assert_eq!(refusal["result"]["decision"], "decline")
                }
                "item/permissions/requestApproval" => {
                    assert_eq!(refusal["result"]["permissions"], json!({}))
                }
                _ => {
                    assert!(refusal.get("result").is_none());
                    assert_eq!(refusal["error"]["code"], -32601);
                }
            }
        }
    }

    #[tokio::test]
    async fn pending_event_flood_and_tool_dispatch_fail_before_rpc_completion() {
        let benign = format!(
            "{}\n",
            json!({"method": "account/updated", "params": {"authMode": null}})
        );
        let input = benign.repeat(MAX_PENDING + 1);
        let mut reader = BufReader::new(input.as_bytes());
        let mut written = Vec::new();
        let mut wire = Wire::new(&mut written, &mut reader);
        assert!(wire.request("account/read", json!({})).await.is_err());
        assert_eq!(wire.pending.len(), MAX_PENDING);

        let input = format!(
            "{}\n{}\n",
            json!({"method": "item/started", "params": {
                "threadId": "thread", "turnId": "turn", "item": {"id": "tool", "type": "fileChange"}
            }}),
            json!({"id": 1, "result": {}})
        );
        let mut reader = BufReader::new(input.as_bytes());
        let mut written = Vec::new();
        let mut wire = Wire::new(&mut written, &mut reader);
        assert!(wire.request("thread/start", json!({})).await.is_err());
        assert!(wire.pending.is_empty());
    }

    #[tokio::test]
    async fn closing_consumer_interrupts_a_silent_turn_and_login_without_waiting_for_reply() {
        for login in [false, true] {
            let (silent_server, client) = duplex(1024);
            let mut reader = BufReader::new(client);
            let mut written = Vec::new();
            let mut wire = Wire::new(&mut written, &mut reader);
            if login {
                wire.login_id = Some("active-login".into());
            } else {
                wire.active_turn = Some(("thread".into(), "turn".into()));
            }
            let (sender, receiver) = mpsc::channel(1);
            let closer = tokio::spawn(async move {
                tokio::task::yield_now().await;
                drop(receiver);
            });
            let result = timeout(
                Duration::from_secs(1),
                cancellable(&sender, wire.notification()),
            )
            .await
            .unwrap();
            assert!(result.is_err());
            wire.cancel().await;
            closer.await.unwrap();
            drop(silent_server);
            let interrupt: Value = serde_json::from_slice(&written).unwrap();
            if login {
                assert_eq!(interrupt["method"], "account/login/cancel");
                assert_eq!(interrupt["params"]["loginId"], "active-login");
            } else {
                assert_eq!(interrupt["method"], "turn/interrupt");
                assert_eq!(
                    interrupt["params"],
                    json!({"threadId": "thread", "turnId": "turn"})
                );
            }
        }
    }

    #[tokio::test]
    async fn authoritative_completion_does_not_duplicate_deltas_or_usage() {
        let (sender, mut receiver) = mpsc::channel(16);
        let mut state = TurnState::new("thread".into(), "turn".into());
        let mut output = Output::new(&sender, false);
        let item = json!({"type": "agentMessage", "id": "answer", "text": "Héllo"});
        let events = [
            notice(
                "item/started",
                scoped(json!({"item": {"type": "agentMessage", "id": "answer", "text": ""}})),
            ),
            notice(
                "item/agentMessage/delta",
                scoped(json!({"itemId": "answer", "delta": "Hé"})),
            ),
            notice("item/completed", scoped(json!({"item": item}))),
            notice(
                "thread/tokenUsage/updated",
                scoped(json!({"tokenUsage": {"total": {"inputTokens": 10, "outputTokens": 3}}})),
            ),
            notice(
                "turn/completed",
                json!({"threadId": "thread", "turn": {"id": "turn", "status": "completed", "items": [item]}}),
            ),
        ];
        for (index, event) in events.into_iter().enumerate() {
            assert_eq!(
                state.apply(event, &mut output, &sender).await.unwrap(),
                index == 4
            );
        }
        output.finish().await.unwrap();
        assert!(matches!(receiver.try_recv(), Ok(ProviderEvent::Delta(text)) if text == "Héllo"));
        assert!(
            matches!(receiver.try_recv(), Ok(ProviderEvent::Usage(usage)) if usage.input_tokens == 10 && usage.output_tokens == 3 && usage.cost_usd.is_none())
        );
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn mismatched_turn_item_and_authoritative_text_cannot_leak_into_reply() {
        for invalid in [
            notice(
                "item/agentMessage/delta",
                json!({"threadId": "other", "turnId": "turn", "itemId": "answer", "delta": "wrong"}),
            ),
            notice(
                "item/agentMessage/delta",
                json!({"threadId": "thread", "turnId": "other", "itemId": "answer", "delta": "wrong"}),
            ),
            notice(
                "item/agentMessage/delta",
                json!({"threadId": "thread", "itemId": "answer", "delta": "wrong"}),
            ),
            notice(
                "item/agentMessage/delta",
                scoped(json!({"itemId": "unstarted", "delta": "wrong"})),
            ),
            notice(
                "item/completed",
                scoped(json!({"item": {"type": "agentMessage", "id": "answer", "text": "wrong"}})),
            ),
            notice(
                "turn/completed",
                json!({"threadId": "thread", "turn": {"id": "other", "status": "completed", "items": []}}),
            ),
        ] {
            let (sender, mut receiver) = mpsc::channel(8);
            let mut output = Output::new(&sender, true);
            let mut state = TurnState::new("thread".into(), "turn".into());
            state.text.insert(
                "answer".into(),
                TextItem {
                    text: "already emitted".into(),
                    complete: false,
                },
            );
            assert!(state.apply(invalid, &mut output, &sender).await.is_err());
            assert!(receiver.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn completed_refresh_is_committed_before_a_silent_turn_can_be_cancelled() {
        let rotated = auth("rotated-before-inference");
        let reader_auth = rotated.clone();
        let credential_reader = move || Ok(Some(reader_auth.clone()));
        let (mut server, client) = duplex(4096);
        server.write_all(b"{\"id\":1,\"result\":{\"requiresOpenaiAuth\":true,\"account\":{\"type\":\"chatgpt\",\"planType\":\"plus\"}}}\n").await.unwrap();
        let mut reader = BufReader::new(client);
        let mut written = Vec::new();
        let mut wire = Wire::new(&mut written, &mut reader);
        wire.last_auth = Some(auth("old-token"));
        wire.credential_reader = Some(&credential_reader);
        let (sender, mut receiver) = mpsc::channel(4);
        assert_eq!(
            read_account(&mut wire, true, &sender).await.unwrap(),
            Some("Plus")
        );
        assert!(
            matches!(receiver.try_recv(), Ok(ProviderEvent::CodexAuth(Some(value))) if value == rotated)
        );
        drop(receiver);
        assert!(cancellable(&sender, wire.notification()).await.is_err());
        assert_eq!(wire.last_auth, Some(rotated));
        drop(server);
    }

    #[tokio::test]
    async fn rotated_credentials_survive_failed_requests_but_not_failed_login() {
        let mut profile = Profile::new(ProviderKind::Codex);
        profile.codex_auth = Some(auth("old-token"));
        let (sender, mut receiver) = mpsc::channel(8);
        let rotated = auth("rotated-token");
        let result = finish_operation(
            profile.codex_auth.as_ref(),
            Operation::Test,
            Err(anyhow!("inference fixture failed")),
            Ok(Some(rotated.clone())),
            &sender,
        )
        .await;
        assert!(result.is_err());
        assert!(
            matches!(receiver.try_recv(), Ok(ProviderEvent::CodexAuth(Some(value))) if value == rotated)
        );

        let result = finish_operation(
            profile.codex_auth.as_ref(),
            Operation::Login(LoginMethod::Browser),
            Err(anyhow!(CANCELLED)),
            Ok(Some(rotated)),
            &sender,
        )
        .await;
        assert!(result.is_err());
        assert!(
            receiver.try_recv().is_err(),
            "cancelled login must not replace the connected account"
        );

        finish_operation(
            profile.codex_auth.as_ref(),
            Operation::Status,
            Ok(Reply::Summary(String::new())),
            Ok(profile.codex_auth.clone()),
            &sender,
        )
        .await
        .ok()
        .unwrap();
        assert!(
            receiver.try_recv().is_err(),
            "unchanged credentials must not rewrite the vault"
        );
        let unsafe_auth =
            Secret::new(r#"{"auth_mode":"apikey","OPENAI_API_KEY":"private-fixture"}"#);
        assert!(
            publish_credentials(None, Some(unsafe_auth), &sender)
                .await
                .is_err()
        );
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn login_completion_must_match_the_active_flow_and_never_expose_failure_details() {
        for completion in [
            json!({"loginId": "different-flow", "success": true, "error": null}),
            json!({"loginId": "active-flow", "success": false, "error": "private-token-fixture"}),
        ] {
            let input = format!(
                "{}\n{}\n",
                json!({"id": 1, "result": {"type": "chatgpt", "loginId": "active-flow", "authUrl": "https://auth.openai.com/oauth/authorize"}}),
                json!({"method": "account/login/completed", "params": completion})
            );
            let mut reader = BufReader::new(input.as_bytes());
            let mut written = Vec::new();
            let mut wire = Wire::new(&mut written, &mut reader);
            let (sender, _receiver) = mpsc::channel(4);
            let error = login_account(&mut wire, LoginMethod::Browser, &sender)
                .await
                .unwrap_err();
            assert!(!format!("{error:#}").contains("private-token-fixture"));
            assert_eq!(
                wire.login_id.as_deref(),
                Some("active-flow"),
                "failure must remain cancellable"
            );
        }
    }

    #[test]
    fn account_billing_model_selection_and_login_links_fail_closed() {
        assert_eq!(
            account_kind(&json!({"requiresOpenaiAuth": true, "account": null})).unwrap(),
            None
        );
        assert!(
            account_kind(&json!({"requiresOpenaiAuth": true, "account": {"type": "apiKey"}}))
                .is_err()
        );
        assert!(
            account_kind(&json!({"requiresOpenaiAuth": false, "account": {"type": "chatgpt"}}))
                .is_err()
        );
        validate_remote_control(&json!({"status": "disabled", "environmentId": null})).unwrap();
        assert!(
            validate_remote_control(&json!({"status": "connected", "environmentId": "remote"}))
                .is_err()
        );
        assert!(validate_account_notice(&json!({"authMode": "apiKey"})).is_err());
        let catalog = vec![Model {
            id: "available".into(),
            default: true,
            efforts: vec!["low".into()],
        }];
        let mut profile = Profile::new(ProviderKind::Codex);
        assert_eq!(select_model(&catalog, &profile).unwrap().id, "available");
        profile.model = "missing".into();
        assert!(select_model(&catalog, &profile).is_err());
        profile.model = "available".into();
        profile.reasoning_effort = Some("high".into());
        assert!(select_model(&catalog, &profile).is_err());
        for url in [
            "http://auth.openai.com/codex/device",
            "https://auth.openai.com.evil.test/",
            "https://user:password@auth.openai.com/",
            "https://127.0.0.1/",
            "https://auth.openai.com:444/",
            "https://auth.openai.com/\u{1b}unsafe",
        ] {
            assert!(login_url(&json!(url)).is_err());
        }
        assert_eq!(
            login_url(&json!("https://auth.openai.com/codex/device")).unwrap(),
            "https://auth.openai.com/codex/device"
        );
    }
}
