use super::*;

pub(super) const ABSOLUTE_AUTH_LIMIT: Duration = Duration::from_secs(30 * 60);
const BANNER_BYTES: usize = 4096;
const TOTAL_BYTES: usize = 16 * 1024;
const MESSAGE_LIMIT: usize = 8;

/// Plain server text from a verified keyless SSH authentication attempt.
/// Links are text only: the host never opens or fetches them.
#[derive(Clone, Debug)]
pub struct AuthNotice {
    pub text: String,
}

#[derive(Clone)]
pub(super) struct AuthCheck(Arc<CheckInner>);

struct CheckInner {
    state: Mutex<CheckState>,
    view: Arc<Mutex<SessionView>>,
    dirty: Arc<Notify>,
    pause: PromptPause,
    cancel: watch::Receiver<bool>,
}

struct CheckState {
    active: bool,
    messages: usize,
    bytes: usize,
    summary: String,
    pause: Option<PromptPauseGuard>,
}

impl AuthCheck {
    pub(super) fn new(
        enabled: bool,
        view: Arc<Mutex<SessionView>>,
        dirty: Arc<Notify>,
        pause: PromptPause,
        cancel: watch::Receiver<bool>,
    ) -> Self {
        Self(Arc::new(CheckInner {
            state: Mutex::new(CheckState {
                active: enabled, messages: 0, bytes: 0,
                summary: String::new(), pause: None,
            }),
            view, dirty, pause, cancel,
        }))
    }
    pub(super) fn is_keyless(&self) -> bool {
        self.0.state.lock().active
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn authenticate(
        &self,
        session_id: Uuid,
        credential: &Login,
        handle: &mut client::Handle<ClientHandler>,
        budget: &mut NetworkBudget,
        cancel: &mut watch::Receiver<bool>,
        prompts: &mpsc::Sender<PromptRequest>,
        pause: &PromptPause,
        handler_failure: &Mutex<Option<String>>,
    ) -> std::result::Result<(), OperationError> {
        if matches!(credential.auth, LoginMode::TailscaleNone) {
            budget.auth_deadline = Some(Instant::now() + ABSOLUTE_AUTH_LIMIT);
        }
        let result = super::authenticate(
            session_id, credential, handle, budget, cancel, prompts, pause,
        ).await;
        budget.auth_deadline = None;
        self.finish(result, handler_failure.lock().take())
    }


    // Called synchronously by auth_banner; no user response can stall protocol progress.
    pub(super) fn banner(&self, banner: &str) -> Result<(), &'static str> {
        let mut state = self.0.state.lock();
        if !state.active { return Ok(()); }
        if banner.len() > BANNER_BYTES || state.messages == MESSAGE_LIMIT
            || banner.len() > TOTAL_BYTES.saturating_sub(state.bytes)
        {
            return Err("Tailscale SSH server exceeded authentication banner limits (4 KiB/message, 16 KiB total, 8 messages)");
        }
        let mut view = self.0.view.lock();
        if *self.0.cancel.borrow() { return Ok(()); }
        state.messages += 1;
        state.bytes += banner.len();
        let text = sanitize_text(banner, BANNER_BYTES);
        let summary = redact_urls(&text);
        if state.summary.len() < BANNER_BYTES {
            if !state.summary.is_empty() { state.summary.push('\n'); }
            let remaining = BANNER_BYTES.saturating_sub(state.summary.len());
            state.summary.push_str(&sanitize_text(&summary, remaining));
        }
        let notice = view.auth_notice.get_or_insert_with(|| AuthNotice { text: String::new() });
        if !notice.text.is_empty() { notice.text.push('\n'); }
        notice.text.push_str(&text);
        if state.pause.is_none() { state.pause = Some(self.0.pause.enter()); }
        self.0.dirty.notify_one();
        Ok(())
    }

    pub(super) fn finish(
        &self,
        result: std::result::Result<(), OperationError>,
        handler_failure: Option<String>,
    ) -> std::result::Result<(), OperationError> {
        let mut state = self.0.state.lock();
        let was_active = state.active;
        state.active = false;
        state.pause.take();
        self.0.view.lock().auth_notice = None;
        self.0.dirty.notify_one();
        let summary = std::mem::take(&mut state.summary);
        match result {
            Err(OperationError::Failed(message)) if was_active => {
                let mut message = handler_failure.unwrap_or(message);
                if !summary.is_empty() {
                    message.push_str("\nServer message (links removed): ");
                    message.push_str(&summary);
                }
                Err(OperationError::failed(sanitize_text(&message, BANNER_BYTES)))
            }
            other => other,
        }
    }
}

impl Drop for CheckInner {
    fn drop(&mut self) {
        self.state.get_mut().pause.take();
        if self.view.lock().auth_notice.take().is_some() { self.dirty.notify_one(); }
    }
}

pub(super) fn sanitize_text(text: &str, limit: usize) -> String {
    let mut output = String::with_capacity(text.len().min(limit));
    for character in text.chars() {
        if (character.is_control() && character != '\n' && character != '\t')
            || matches!(character, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        { continue; }
        if output.len() + character.len_utf8() > limit { break; }
        output.push(character);
    }
    output
}

fn redact_urls(text: &str) -> String {
    // Redact whole tokens, including punctuation around URLs, rather than retaining
    // bearer-bearing query/path fragments in a lasting session error.
    let mut output = String::with_capacity(text.len());
    for token in text.split_inclusive(char::is_whitespace) {
        if token.contains("://") || token.as_bytes().windows(4).any(|part| part.eq_ignore_ascii_case(b"www.")) {
            output.push_str("[link removed]");
            output.push_str(&token[token.trim_end_matches(char::is_whitespace).len()..]);
        } else { output.push_str(token); }
    }
    output
}
