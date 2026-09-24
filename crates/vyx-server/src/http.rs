use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{
            AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, IF_MATCH,
            IF_NONE_MATCH, WWW_AUTHENTICATE,
        },
    },
    response::{IntoResponse, Response},
    routing::any,
};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tempfile::Builder;
use tokio::{
    io::AsyncWriteExt,
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
};
use tokio_util::io::ReaderStream;

use crate::{
    auth,
    store::{
        CommitError, CommitSuccess, MAX_VAULT_BYTES, Precondition, ServerStore, StagedUpload,
        UPLOAD_PREFIX, encode_digest,
    },
};

#[cfg(test)]
use crate::store::etag_for_bytes;

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_IN_FLIGHT: usize = 8;

#[derive(Clone)]
pub(crate) struct AppState {
    store: Arc<ServerStore>,
    capacity: Arc<Semaphore>,
    commits: Arc<CommitTracker>,
}

impl AppState {
    pub(crate) fn new(store: Arc<ServerStore>) -> Self {
        Self {
            store,
            capacity: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            commits: Arc::new(CommitTracker::default()),
        }
    }

    pub(crate) async fn drain_commits(&self) {
        self.commits.drain().await;
    }
}

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", any(health))
        .route("/v1/vault", any(vault))
        .fallback(not_found)
        .with_state(state)
}

async fn health(State(state): State<AppState>, request: Request) -> Response {
    if request.method() != Method::GET {
        return error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    if state.store.is_ready() {
        (StatusCode::OK, "ok").into_response()
    } else {
        error_response(StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn vault(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if !authorized(&parts.headers, &state) {
        let mut response = error_response(StatusCode::UNAUTHORIZED, "unauthorized");
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return response;
    }

    let permit = match Arc::clone(&state.capacity).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, "request limit reached");
        }
    };

    match parts.method {
        Method::GET => get_vault(state, parts.headers, permit).await,
        Method::PUT => put_vault(state, parts.headers, body, permit).await,
        _ => error_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    }
}

async fn get_vault(state: AppState, headers: HeaderMap, permit: OwnedSemaphorePermit) -> Response {
    let condition = match get_condition(&headers) {
        Ok(condition) => condition,
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "malformed conditional header"),
    };

    let store = Arc::clone(&state.store);
    let (captured, permit) = match tokio::task::spawn_blocking(move || {
        store.capture().map(|captured| (captured, permit))
    })
    .await
    {
        Ok(Ok(captured)) => captured,
        Ok(Err(_)) | Err(_) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "vault unavailable");
        }
    };
    let Some(captured) = captured else {
        return error_response(StatusCode::NOT_FOUND, "vault not found");
    };

    if condition.matches(&captured.etag) {
        let mut response = vault_response(StatusCode::NOT_MODIFIED, Body::empty());
        insert_etag(&mut response, &captured.etag);
        return response;
    }

    let file = tokio::fs::File::from_std(captured.file);
    let stream = ReaderStream::new(file).map(move |item| {
        let _keep_permit_alive = &permit;
        item
    });
    let mut response = vault_response(StatusCode::OK, Body::from_stream(stream));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    insert_etag(&mut response, &captured.etag);
    response
}

async fn put_vault(
    state: AppState,
    headers: HeaderMap,
    body: Body,
    permit: OwnedSemaphorePermit,
) -> Response {
    match binary_content_type(&headers) {
        Ok(true) => {}
        Ok(false) => {
            return error_response(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported content type",
            );
        }
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "malformed content type"),
    }
    let precondition = match put_precondition(&headers) {
        Ok(precondition) => precondition,
        Err(PreconditionError::Missing) => {
            return error_response(StatusCode::PRECONDITION_REQUIRED, "precondition required");
        }
        Err(PreconditionError::Malformed) => {
            return error_response(StatusCode::BAD_REQUEST, "malformed conditional header");
        }
    };
    match declared_length(&headers) {
        Ok(Some(0)) => return error_response(StatusCode::BAD_REQUEST, "empty vault"),
        Ok(Some(length)) if length > MAX_VAULT_BYTES => {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "vault too large");
        }
        Ok(_) => {}
        Err(()) => return error_response(StatusCode::BAD_REQUEST, "malformed content length"),
    }

    let store = Arc::clone(&state.store);
    let permit =
        match tokio::task::spawn_blocking(move || store.ensure_ready().map(|()| permit)).await {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) | Err(_) => {
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "vault unavailable");
            }
        };

    let data_dir = state.store.data_dir().to_path_buf();
    let staged = match tokio::time::timeout(RECEIVE_TIMEOUT, receive_upload(&data_dir, body)).await
    {
        Ok(Ok(staged)) => staged,
        Ok(Err(ReceiveError::Empty)) => {
            return error_response(StatusCode::BAD_REQUEST, "empty vault");
        }
        Ok(Err(ReceiveError::TooLarge)) => {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, "vault too large");
        }
        Ok(Err(ReceiveError::InvalidBody)) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid request body");
        }
        Ok(Err(ReceiveError::Io)) => {
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "upload staging failed");
        }
        Err(_) => return error_response(StatusCode::REQUEST_TIMEOUT, "upload timed out"),
    };

    let store = Arc::clone(&state.store);
    let commit_guard = state.commits.begin();
    let operation = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _commit_guard = commit_guard;
        store.commit(staged, precondition)
    });

    match operation.await {
        Ok(Ok(CommitSuccess::Created(etag))) => {
            let mut response = vault_response(StatusCode::CREATED, Body::empty());
            insert_etag(&mut response, &etag);
            response
        }
        Ok(Ok(CommitSuccess::Replaced(etag))) => {
            let mut response = vault_response(StatusCode::OK, Body::empty());
            insert_etag(&mut response, &etag);
            response
        }
        Ok(Err(CommitError::PreconditionFailed)) => {
            error_response(StatusCode::PRECONDITION_FAILED, "precondition failed")
        }
        Ok(Err(CommitError::InvalidStage)) => {
            error_response(StatusCode::BAD_REQUEST, "invalid vault")
        }
        Ok(Err(CommitError::Io(error) | CommitError::DurabilityUncertain(error))) => {
            eprintln!("Vault persistence failed: {}", error.kind());
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "vault persistence failed",
            )
        }
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "vault persistence worker failed",
        ),
    }
}

async fn receive_upload(data_dir: &Path, body: Body) -> Result<StagedUpload, ReceiveError> {
    let data_dir = data_dir.to_path_buf();
    let temporary = tokio::task::spawn_blocking(move || {
        use std::os::unix::fs::PermissionsExt;

        let temporary = Builder::new().prefix(UPLOAD_PREFIX).tempfile_in(data_dir)?;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok::<_, std::io::Error>(temporary)
    })
    .await
    .map_err(|_| ReceiveError::Io)?
    .map_err(|_| ReceiveError::Io)?;

    let (file, path) = temporary.into_parts();
    let mut file = tokio::fs::File::from_std(file);
    let mut stream = body.into_data_stream();
    let mut hasher = Sha256::new();
    let mut length = 0_u64;

    while let Some(item) = stream.next().await {
        let bytes = item.map_err(|_| ReceiveError::InvalidBody)?;
        let chunk_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        length = length
            .checked_add(chunk_length)
            .ok_or(ReceiveError::TooLarge)?;
        if length > MAX_VAULT_BYTES {
            return Err(ReceiveError::TooLarge);
        }
        file.write_all(&bytes).await.map_err(|_| ReceiveError::Io)?;
        hasher.update(&bytes);
    }

    if length == 0 {
        return Err(ReceiveError::Empty);
    }
    let file = file.into_std().await;
    let etag = encode_digest(hasher.finalize().into());
    Ok(StagedUpload {
        file,
        path,
        etag,
        length,
    })
}

fn authorized(headers: &HeaderMap, state: &AppState) -> bool {
    let Ok(Some(value)) = single_header(headers, &AUTHORIZATION) else {
        return false;
    };
    auth::authenticate(Some(value.as_bytes()), &state.store.auth_digest())
}

fn binary_content_type(headers: &HeaderMap) -> Result<bool, ()> {
    Ok(matches!(
        single_header(headers, &CONTENT_TYPE)?,
        Some(value) if value.as_bytes() == b"application/octet-stream"
    ))
}

fn declared_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    let Some(value) = single_header(headers, &CONTENT_LENGTH)? else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    value.parse().map(Some).map_err(|_| ())
}

fn single_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a HeaderValue>, ()> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(());
    }
    Ok(first)
}

#[derive(Clone, Debug)]
enum GetCondition {
    None,
    Any,
    Exact(String),
}

impl GetCondition {
    fn matches(&self, current: &str) -> bool {
        match self {
            Self::None => false,
            Self::Any => true,
            Self::Exact(expected) => expected == current,
        }
    }
}

fn get_condition(headers: &HeaderMap) -> Result<GetCondition, ()> {
    if headers.contains_key(IF_MATCH) {
        return Err(());
    }
    let Some(value) = single_header(headers, &IF_NONE_MATCH)? else {
        return Ok(GetCondition::None);
    };
    if value.as_bytes() == b"*" {
        return Ok(GetCondition::Any);
    }
    parse_strong_etag(value).map(GetCondition::Exact).ok_or(())
}

#[derive(Clone, Copy, Debug)]
enum PreconditionError {
    Missing,
    Malformed,
}

fn put_precondition(headers: &HeaderMap) -> Result<Precondition, PreconditionError> {
    let if_match = single_header(headers, &IF_MATCH).map_err(|_| PreconditionError::Malformed)?;
    let if_none_match =
        single_header(headers, &IF_NONE_MATCH).map_err(|_| PreconditionError::Malformed)?;
    match (if_match, if_none_match) {
        (None, None) => Err(PreconditionError::Missing),
        (Some(_), Some(_)) => Err(PreconditionError::Malformed),
        (None, Some(value)) if value.as_bytes() == b"*" => Ok(Precondition::NoneMatchAny),
        (None, Some(_)) => Err(PreconditionError::Malformed),
        (Some(value), None) if value.as_bytes() == b"*" => Ok(Precondition::Match("*".to_owned())),
        (Some(value), None) => parse_strong_etag(value)
            .map(Precondition::Match)
            .ok_or(PreconditionError::Malformed),
    }
}

fn parse_strong_etag(value: &HeaderValue) -> Option<String> {
    let value = value.as_bytes();
    if value.len() != 66 || value[0] != b'"' || value[65] != b'"' {
        return None;
    }
    let digest = &value[1..65];
    if !digest
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    String::from_utf8(digest.to_vec()).ok()
}

fn insert_etag(response: &mut Response, etag: &str) {
    let quoted = format!("\"{etag}\"");
    if let Ok(value) = HeaderValue::from_str(&quoted) {
        response.headers_mut().insert(ETAG, value);
    }
}

fn vault_response(status: StatusCode, body: Body) -> Response {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error_response(status: StatusCode, message: &'static str) -> Response {
    let mut response = (status, message).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn not_found() -> Response {
    error_response(StatusCode::NOT_FOUND, "not found")
}

#[derive(Clone, Copy, Debug)]
enum ReceiveError {
    Empty,
    TooLarge,
    InvalidBody,
    Io,
}

#[derive(Default)]
struct CommitTracker {
    active: AtomicUsize,
    notify: Notify,
}

impl CommitTracker {
    fn begin(self: &Arc<Self>) -> CommitGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        CommitGuard {
            tracker: Arc::clone(self),
        }
    }

    async fn drain(&self) {
        loop {
            let notified = self.notify.notified();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }
}

struct CommitGuard {
    tracker: Arc<CommitTracker>,
}

impl Drop for CommitGuard {
    fn drop(&mut self) {
        if self.tracker.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.tracker.notify.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request as HttpRequest;
    use std::{fs, sync::mpsc};

    fn setup() -> (tempfile::TempDir, String, AppState) {
        let temporary = tempfile::tempdir().unwrap();
        let token = auth::initialize(temporary.path()).unwrap();
        let store = ServerStore::open(temporary.path()).unwrap();
        (temporary, token, AppState::new(store))
    }

    fn request(
        method: Method,
        token: Option<&str>,
        condition_name: HeaderName,
        condition: &str,
        bytes: Vec<u8>,
    ) -> Request {
        let mut builder = HttpRequest::builder()
            .method(method)
            .uri("/v1/vault")
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(condition_name, condition);
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(Body::from(bytes)).unwrap()
    }

    async fn dispatch(state: AppState, request: Request) -> Response {
        vault(State(state), request).await
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unauthorized_oversized_and_stale_puts_preserve_the_blob() {
        let (temporary, token, state) = setup();
        let initial = b"opaque-one".to_vec();
        let response = dispatch(
            state.clone(),
            request(
                Method::PUT,
                Some(&token),
                IF_NONE_MATCH,
                "*",
                initial.clone(),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let stored_path = temporary.path().join("vault.vyx");
        assert_eq!(fs::read(&stored_path).unwrap(), initial);

        let unauthorized = dispatch(
            state.clone(),
            request(
                Method::PUT,
                None,
                IF_MATCH,
                &format!("\"{}\"", etag_for_bytes(b"opaque-one")),
                b"attacker".to_vec(),
            ),
        )
        .await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(fs::read(&stored_path).unwrap(), b"opaque-one");

        let oversized = dispatch(
            state.clone(),
            request(
                Method::PUT,
                Some(&token),
                IF_MATCH,
                &format!("\"{}\"", etag_for_bytes(b"opaque-one")),
                vec![7_u8; MAX_VAULT_BYTES as usize + 1],
            ),
        )
        .await;
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(fs::read(&stored_path).unwrap(), b"opaque-one");

        let stale = dispatch(
            state,
            request(
                Method::PUT,
                Some(&token),
                IF_MATCH,
                &format!("\"{}\"", "0".repeat(64)),
                b"stale".to_vec(),
            ),
        )
        .await;
        assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
        assert_eq!(fs::read(stored_path).unwrap(), b"opaque-one");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn post_rename_uncertainty_blocks_health_until_incoming_retry() {
        let (_temporary, token, state) = setup();
        state.store.fail_next_directory_sync();
        let response = dispatch(
            state.clone(),
            request(
                Method::PUT,
                Some(&token),
                IF_NONE_MATCH,
                "*",
                b"opaque".to_vec(),
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!state.store.is_ready());

        let health_response = health(
            State(state.clone()),
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(health_response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let get = HttpRequest::builder()
            .method(Method::GET)
            .uri("/v1/vault")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let response = dispatch(state.clone(), get).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.store.is_ready());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_commit_survives_request_cancellation() {
        let (temporary, token, state) = setup();
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = mpsc::sync_channel(0);
        state.store.pause_next_before_rename(entered_tx, resume_rx);

        let handler = tokio::spawn(dispatch(
            state.clone(),
            request(
                Method::PUT,
                Some(&token),
                IF_NONE_MATCH,
                "*",
                b"committed after cancellation".to_vec(),
            ),
        ));
        tokio::task::spawn_blocking(move || entered_rx.recv().unwrap())
            .await
            .unwrap();
        handler.abort();
        let _ = handler.await;
        resume_tx.send(()).unwrap();
        state.drain_commits().await;

        assert_eq!(
            fs::read(temporary.path().join("vault.vyx")).unwrap(),
            b"committed after cancellation"
        );
    }
}
