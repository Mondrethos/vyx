//! Compiled into the pinned upstream app-server, not into Vyx core.
#![recursion_limit = "256"]

use codex_app_server::{
    AppServerRuntimeOptions, AppServerTransport, AppServerWebsocketAuthSettings,
    PluginStartupTasks, RemoteControlStartupMode, run_main_with_transport_options,
};
use codex_arg0::Arg0DispatchPaths;
use codex_config::LoaderOverrides;
use codex_protocol::protocol::SessionSource;
use codex_utils_cli::CliConfigOverrides;

const CAPABILITIES: &str = r#"{"protocolVersion":1,"helper":"vyx-codex","sourceRevision":"36650394c5b38c2990ccf2a3457165ca3e9d9726","toolPolicy":"deny-all","configuration":"vyx-fixed-v1"}"#;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let operation = args.next().unwrap_or_default();
    anyhow::ensure!(args.next().is_none(), "Vyx helper does not accept configuration arguments");
    if operation == "--vyx-capabilities" {
        use codex_extension_api::{ToolName, ToolPolicy};
        let tool = ToolName::plain("apply_patch");
        let mut policy = ToolPolicy { allowed_tools: None, ..Default::default() };
        anyhow::ensure!(!policy.allows(&tool), "unrestricted tool policy in Vyx build");
        policy.allowed_tools = Some(vec![tool.clone()]);
        anyhow::ensure!(!policy.allows(&tool), "caller tool-policy override in Vyx build");
        println!("{CAPABILITIES}");
        return Ok(());
    }
    anyhow::ensure!(operation == "app-server", "use the Vyx managed launcher");
    anyhow::ensure!(
        std::env::var("VYX_CODEX_SANDBOX").as_deref() == Ok("1")
            && std::env::var("CODEX_HOME").as_deref() == Ok("/state")
            && std::env::var("HOME").as_deref() == Ok("/home")
            && std::env::current_exe()? == std::path::Path::new("/vyx-codex"),
        "Vyx helper requires its isolated filesystem"
    );
    deny_subprocesses()?;
    let mut overrides: Vec<String> = [
        "model_provider=\"openai\"",
        "forced_login_method=\"chatgpt\"",
        "chatgpt_base_url=\"https://chatgpt.com/backend-api\"",
        "cli_auth_credentials_store=\"file\"",
        "approval_policy=\"never\"",
        "sandbox_mode=\"read-only\"",
        "analytics.enabled=false",
        "feedback.enabled=false",
        "check_for_update_on_startup=false",
        "history.persistence=\"none\"",
        "otel.exporter=\"none\"",
        "otel.trace_exporter=\"none\"",
        "otel.metrics_exporter=\"none\"",
        "otel.log_user_prompt=false",
        "web_search=\"disabled\"",
        "project_doc_max_bytes=0",
        "include_apps_instructions=false",
        "include_environment_context=false",
        "include_permissions_instructions=false",
        "include_collaboration_mode_instructions=false",
        "mcp_servers={}",
        "plugins={}",
        "notify=[]",
        "cloud.skills.enabled=false",
    ].into_iter().map(str::to_owned).collect();
    // No experimental/ambient feature is inherited from upstream defaults.
    overrides.extend(codex_features::FEATURES.iter().map(|feature| format!("features.{}=false", feature.key)));
    let loader = LoaderOverrides {
        ignore_user_config: true,
        ignore_project_config: true,
        ignore_user_and_project_exec_policy_rules: true,
        ignore_managed_requirements: true,
        managed_config_path: Some("/nonexistent/managed.toml".into()),
        system_config_path: Some("/nonexistent/config.toml".into()),
        system_requirements_path: Some("/nonexistent/requirements.toml".into()),
        ..Default::default()
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_stack_size(8 * 1024 * 1024)
        .enable_all()
        .build()?;
    runtime.block_on(run_main_with_transport_options(
        Arg0DispatchPaths {
            codex_self_exe: Some("/vyx-codex".into()),
            ..Default::default()
        },
        CliConfigOverrides { raw_overrides: overrides },
        loader,
        true,
        false,
        AppServerTransport::Stdio,
        SessionSource::VSCode,
        AppServerWebsocketAuthSettings::default(),
        AppServerRuntimeOptions {
            plugin_startup_tasks: PluginStartupTasks::Skip,
            remote_control_startup_mode: RemoteControlStartupMode::DisabledEphemeral,
            ..Default::default()
        },
    ))?;
    // Upstream may retain blocking I/O tasks; the owner always controls lifetime.
    std::process::exit(0);
}

/// Complement the tool ceiling: no fork/exec aliases or host shell can run.
/// This is not a sandbox for malicious native code, nor a network egress policy.
fn deny_subprocesses() -> std::io::Result<()> {
    use libc::{sock_filter, sock_fprog};
    const LD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    const ALLOW: u32 = 0x7fff0000;
    const ERRNO: u32 = 0x00050000;
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc00000b7;
    let stmt = |code, k| sock_filter { code, jt: 0, jf: 0, k };
    let jump = |code, k, jt, jf| sock_filter { code, jt, jf, k };
    let mut filter = vec![
        stmt(LD, 4),
        jump(JEQ, ARCH, 1, 0),
        stmt(RET, 0x80000000),
        stmt(LD, 0),
    ];
    let mut denied = vec![
        libc::SYS_execve, libc::SYS_execveat, libc::SYS_ptrace,
        libc::SYS_process_vm_readv, libc::SYS_process_vm_writev,
        libc::SYS_keyctl, libc::SYS_add_key, libc::SYS_request_key,
    ];
    #[cfg(target_arch = "x86_64")]
    denied.extend([libc::SYS_fork, libc::SYS_vfork]);
    for syscall in denied {
        filter.push(jump(JEQ, syscall as u32, 0, 1));
        filter.push(stmt(RET, ERRNO | libc::EPERM as u32));
    }
    filter.extend([
        jump(JEQ, libc::SYS_clone3 as u32, 0, 1),
        stmt(RET, ERRNO | libc::ENOSYS as u32),
        jump(JEQ, libc::SYS_clone as u32, 0, 4),
        stmt(LD, 16),
        jump((libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16, libc::CLONE_THREAD as u32, 1, 0),
        stmt(RET, ERRNO | libc::EPERM as u32),
        stmt(RET, ALLOW),
        stmt(RET, ALLOW),
    ]);
    let program = sock_fprog { len: filter.len() as u16, filter: filter.as_mut_ptr() };
    // SAFETY: single-threaded startup; the kernel copies the live BPF program.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            || libc::prctl(libc::PR_SET_SECCOMP, 2, &program) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
