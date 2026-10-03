use super::*;
use russh::{server, keys::ssh_key::private::Ed25519Keypair};

fn key(seed: u8) -> PrivateKey {
    PrivateKey::new(Ed25519Keypair::from_seed(&[seed; 32]).into(), "local fixture").unwrap()
}

struct Server {
    banner: Option<String>,
    decision: oneshot::Receiver<bool>,
    methods: Arc<Mutex<Vec<String>>>,
}

impl server::Handler for Server {
    type Error = anyhow::Error;

    async fn authentication_banner(&mut self) -> Result<Option<String>> {
        Ok(self.banner.take())
    }

    async fn auth_none(&mut self, user: &str) -> Result<server::Auth> {
        self.methods.lock().push(format!("none:{user}"));
        Ok(if (&mut self.decision).await.unwrap_or(false) {
            server::Auth::Accept
        } else { server::Auth::reject() })
    }

    async fn auth_password(&mut self, user: &str, _: &str) -> Result<server::Auth> {
        self.methods.lock().push(format!("password:{user}"));
        Ok(if (&mut self.decision).await.unwrap_or(false) {
            server::Auth::Accept
        } else { server::Auth::reject() })
    }

    async fn auth_publickey_offered(&mut self, _: &str, _: &PublicKey) -> Result<server::Auth> {
        self.methods.lock().push("publickey".into());
        Ok(server::Auth::reject())
    }

    async fn auth_keyboard_interactive<'a>(
        &'a mut self, _: &str, _: &str, _: Option<server::Response<'a>>,
    ) -> Result<server::Auth> {
        self.methods.lock().push("keyboard-interactive".into());
        Ok(server::Auth::reject())
    }
}

struct Attempt {
    task: tokio::task::JoinHandle<(std::result::Result<(), OperationError>, client::Handle<ClientHandler>, Duration)>,
    server: tokio::task::JoinHandle<()>,
    decision: Option<oneshot::Sender<bool>>,
    methods: Arc<Mutex<Vec<String>>>,
    view: Arc<Mutex<SessionView>>,
    dirty: Arc<Notify>,
    pause: PromptPause,
    cancel: watch::Sender<bool>,
    prompts: mpsc::Receiver<PromptRequest>,
    store: Store,
    expected_pins: usize,
    _directory: tempfile::TempDir,
}

fn view() -> Arc<Mutex<SessionView>> {
    Arc::new(Mutex::new(SessionView {
        terminal: TerminalState::new(24, 80), phase: SessionPhase::Authenticating,
        output_ended: false, auth_notice: None,
    }))
}

async fn store() -> (tempfile::TempDir, Store) {
    let temporary = tempfile::tempdir().unwrap();
    let directory = crate::vault::Directory::open(temporary.path().join("vault")).unwrap();
    let store = directory.create(Secret::new("fixture passphrase")).await.unwrap();
    (temporary, store)
}

impl Attempt {
    async fn start(banner: Option<String>, keyless: bool) -> Self {
        let (directory, store) = store().await;
        let key = key(7);
        if !keyless {
            let encoded = key.public_key().to_openssh().unwrap();
            store.commit(true, move |state| {
                state.vault.known_hosts.push(KnownHost {
                    hostname: "fixture.invalid".into(), port: 22, public_key_openssh: encoded,
                });
                Ok(())
            }).await.unwrap();
        }
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let (decision, receive_decision) = oneshot::channel();
        let methods = Arc::new(Mutex::new(Vec::new()));
        let server_config = Arc::new(server::Config {
            keys: vec![key.clone()], auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO), inactivity_timeout: None,
            ..Default::default()
        });
        let fixture = Server { banner, decision: receive_decision, methods: methods.clone() };
        let server = tokio::spawn(async move {
            if let Ok(running) = server::run_stream(server_config, server_stream, fixture).await {
                let _ = running.await;
            }
        });
        let view = view();
        let dirty = Arc::new(Notify::new());
        let (pause_tx, pause_rx) = watch::channel(false);
        let pause = PromptPause(pause_tx);
        let (cancel, mut cancelled) = watch::channel(false);
        let (prompts_tx, prompts) = mpsc::channel(8);
        let check = AuthCheck::new(keyless, view.clone(), dirty.clone(), pause.clone(), cancelled.clone());
        let failure = Arc::new(Mutex::new(None));
        let id = Uuid::new_v4();
        let handler = ClientHandler {
            session_id: id, hostname: "fixture.invalid".into(), port: 22,
            store: store.clone(), prompts: prompts_tx.clone(), cancel: cancelled.clone(),
            pause: pause.clone(), failure: failure.clone(),
            tailscale_keys: keyless.then(|| vec![key.public_key().clone()]),
            verified_tailscale_key: false, check: check.clone(),
        };
        let mut handle = client::connect_stream(Arc::new(client::Config::default()), client_stream, handler).await.unwrap();
        let task_pause = pause.clone();
        let task = tokio::spawn(async move {
            let login = Login {
                username: "fixture-user".into(),
                auth: if keyless { LoginMode::TailscaleNone } else {
                    LoginMode::Standard(Auth::Password { password: Secret::new("fixture-only") })
                },
            };
            let mut budget = NetworkBudget::new(pause_rx);
            let result = check.authenticate(id, &login, &mut handle, &mut budget, &mut cancelled, &prompts_tx, &task_pause, &failure).await;
            (result, handle, budget.remaining)
        });
        Self { task, server, decision: Some(decision), methods, view, dirty, pause, cancel, prompts, store, expected_pins: usize::from(!keyless), _directory: directory }
    }

    async fn notice(&self) -> String {
        loop {
            let notified = self.dirty.notified();
            if let Some(notice) = &self.view.lock().auth_notice { return notice.text.clone(); }
            assert!(!self.task.is_finished(), "authentication ended before showing a notice");
            notified.await;
        }
    }

    fn decide(&mut self, accept: bool) {
        self.decision.take().unwrap().send(accept).unwrap();
    }

    async fn finish(mut self) -> (std::result::Result<(), OperationError>, Duration, Vec<String>) {
        // Release a stalled server callback before joining its protocol task.
        self.decision.take();
        let (result, handle, remaining) = self.task.await.unwrap();
        assert!(self.view.lock().auth_notice.is_none(), "URLs must not outlive authentication");
        assert!(!*self.pause.0.borrow(), "authentication must release its pause");
        assert!(self.prompts.try_recv().is_err(), "keyless checks must not create an interactive prompt");
        assert_eq!(self.store.snapshot().vault.known_hosts.len(), self.expected_pins,
            "distributed keys must never become ordinary host-key pins");
        let _ = handle.disconnect(russh::Disconnect::ByApplication, "fixture done", "en").await;
        let _ = handle.await;
        self.server.await.unwrap();
        self.store.shutdown().await.unwrap();
        let methods = self.methods.lock().clone();
        (result, remaining, methods)
    }
}

#[tokio::test]
async fn verified_none_succeeds_and_banners_never_require_dismissal() {
    let mut attempt = Attempt::start(Some("Check access manually: https://example.invalid/secret\n\u{1b}[31m\u{202e}server".into()), true).await;
    let notice = attempt.notice().await;
    assert!(notice.contains("https://example.invalid/secret"));
    assert!(!notice.contains('\u{1b}') && !notice.contains('\u{202e}'));
    assert!(*attempt.pause.0.borrow());
    attempt.decide(true);
    let (result, _, methods) = attempt.finish().await;
    result.unwrap();
    assert_eq!(methods, ["none:fixture-user"]);
}

#[tokio::test]
async fn immediate_denial_retains_redacted_reason_and_never_falls_back() {
    let mut attempt = Attempt::start(Some("Policy denied. Reauthenticate HTTPS://example.invalid/bearer?token=secret \u{202e}\u{1b}".into()), true).await;
    attempt.decide(false);
    let (result, _, methods) = attempt.finish().await;
    let Err(OperationError::Failed(message)) = result else { panic!("expected denial") };
    assert!(message.contains("Policy denied."));
    assert!(message.contains("[link removed]"));
    assert!(!message.contains("secret") && !message.contains("example.invalid"));
    assert!(!message.contains('\u{1b}') && !message.contains('\u{202e}'));
    assert!(message.len() <= 4096);
    assert_eq!(methods, ["none:fixture-user"]);
}

#[tokio::test]
async fn verified_banner_pauses_budget_but_absolute_cap_expires() {
    let attempt = Attempt::start(Some("Complete the check https://example.invalid/private".into()), true).await;
    attempt.notice().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(60)).await;
    assert!(!attempt.task.is_finished(), "a verified check pauses the ordinary 15 seconds");
    tokio::time::advance(check::ABSOLUTE_AUTH_LIMIT).await;
    // Await timeout before releasing the fixture's decision gate.
    while !attempt.task.is_finished() { tokio::task::yield_now().await; }
    let (result, remaining, _) = attempt.finish().await;
    assert!(matches!(result, Err(OperationError::TimedOut)));
    assert!(remaining > Duration::ZERO);
}

#[tokio::test]
async fn cancel_clears_check_without_waiting_for_server_approval() {
    let attempt = Attempt::start(Some("Check https://example.invalid/private".into()), true).await;
    attempt.notice().await;
    attempt.cancel.send_replace(true);
    while !attempt.task.is_finished() { tokio::task::yield_now().await; }
    let (result, _, _) = attempt.finish().await;
    assert!(matches!(result, Err(OperationError::Cancelled)));
}

#[tokio::test]
async fn ordinary_banner_is_ignored_and_never_extends_authentication() {
    let attempt = Attempt::start(Some("https://example.invalid/not-a-tailscale-check".into()), false).await;
    // Wait until the server actually receives the password; its banner precedes this.
    while attempt.methods.lock().is_empty() { tokio::task::yield_now().await; }
    assert!(attempt.view.lock().auth_notice.is_none());
    assert!(!*attempt.pause.0.borrow());
    tokio::time::pause();
    tokio::time::advance(NETWORK_DEADLINE + Duration::from_secs(1)).await;
    while !attempt.task.is_finished() { tokio::task::yield_now().await; }
    let (result, _, methods) = attempt.finish().await;
    assert!(matches!(result, Err(OperationError::TimedOut)));
    assert_eq!(methods, ["password:fixture-user"]);
}

#[tokio::test]
async fn keyless_without_a_check_still_uses_the_ordinary_deadline() {
    let attempt = Attempt::start(None, true).await;
    while attempt.methods.lock().is_empty() { tokio::task::yield_now().await; }
    tokio::time::pause();
    tokio::time::advance(NETWORK_DEADLINE + Duration::from_secs(1)).await;
    while !attempt.task.is_finished() { tokio::task::yield_now().await; }
    let (result, remaining, methods) = attempt.finish().await;
    assert!(matches!(result, Err(OperationError::TimedOut)));
    assert_eq!(remaining, Duration::ZERO);
    assert_eq!(methods, ["none:fixture-user"]);
}

#[tokio::test(start_paused = true)]
async fn resuming_after_a_notice_preserves_only_unspent_network_time() {
    let (pause, paused) = watch::channel(false);
    let (_cancel, mut cancelled) = watch::channel(false);
    let (complete, completed) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut budget = NetworkBudget::new(paused);
        tokio::pin!(completed);
        budget.wait(completed.as_mut(), &mut cancelled).await.unwrap().unwrap();
        budget.remaining
    });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    pause.send_replace(true);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(50)).await;
    pause.send_replace(false);
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    complete.send(()).unwrap();
    assert_eq!(task.await.unwrap(), Duration::from_secs(9));
}

#[tokio::test]
async fn oversized_server_banner_reports_abuse_not_generic_authentication_failure() {
    let attempt = Attempt::start(Some("x".repeat(4097)), true).await;
    while !attempt.task.is_finished() { tokio::task::yield_now().await; }
    let (result, _, _) = attempt.finish().await;
    let Err(OperationError::Failed(message)) = result else { panic!("expected banner rejection") };
    assert!(message.contains("exceeded authentication banner limits"));
}

#[tokio::test]
async fn missing_and_mismatched_distributed_keys_fail_before_authentication_or_tofu() {
    let (_directory, store) = store().await;
    for keys in [None, Some(vec![]), Some(vec![key(9).public_key().clone()])] {
        let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
        let (decision, receive_decision) = oneshot::channel();
        let methods = Arc::new(Mutex::new(Vec::new()));
        let fixture = Server { banner: None, decision: receive_decision, methods: methods.clone() };
        let server = tokio::spawn(async move {
            if let Ok(running) = server::run_stream(Arc::new(server::Config { keys: vec![key(7)], ..Default::default() }), server_stream, fixture).await {
                let _ = running.await;
            }
        });
        let (pause, _) = watch::channel(false);
        let pause = PromptPause(pause);
        let (_cancel, cancelled) = watch::channel(false);
        let (prompts, mut received) = mpsc::channel(1);
        let failure = Arc::new(Mutex::new(None));
        let handler = ClientHandler {
            session_id: Uuid::new_v4(), hostname: "fixture.invalid".into(), port: 22,
            store: store.clone(), prompts, cancel: cancelled.clone(), pause: pause.clone(),
            failure: failure.clone(), tailscale_keys: keys, verified_tailscale_key: false,
            check: AuthCheck::new(true, view(), Arc::new(Notify::new()), pause, cancelled),
        };
        let connected = client::connect_stream(Arc::new(client::Config::default()), client_stream, handler).await;
        assert!(connected.is_err());
        assert!(failure.lock().as_ref().unwrap().contains("no trust override"));
        assert!(received.try_recv().is_err());
        assert!(methods.lock().is_empty());
        assert!(store.snapshot().vault.known_hosts.is_empty());
        drop(decision);
        server.await.unwrap();
    }
    store.shutdown().await.unwrap();
}

#[test]
fn cumulative_banner_limits_and_utf8_error_bounds() {
    for (banner, allowed) in [("x".repeat(4096), 4), ("small message".into(), 8)] {
        let view = view();
        let (pause, _) = watch::channel(false);
        let pause = PromptPause(pause);
        let (_cancel, cancelled) = watch::channel(false);
        let check = AuthCheck::new(true, view.clone(), Arc::new(Notify::new()), pause.clone(), cancelled);
        for _ in 0..allowed { check.banner(&banner).unwrap(); }
        assert!(check.banner(&banner).is_err());
        check.finish(Err(OperationError::Cancelled), None).unwrap_err();
        assert!(view.lock().auth_notice.is_none());
        assert!(!*pause.0.borrow());
        check.banner("late https://example.invalid/secret").unwrap();
        assert!(view.lock().auth_notice.is_none());
    }
    let text = check::sanitize_text(&"é".repeat(4096), 4095);
    assert_eq!(text.len(), 4094);
}
