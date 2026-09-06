//! SPEC-077 TEST-008's private native command adapter. See the host protocol
//! and evidence in docs/spec077-native-host.md. This module is test-only.
//!
//! The ignored host runs alone: keyring and network configuration are global.
//! No production App setup, wallet directory, or publication command is used.

use super::*;
use crate::{cbcl_v2_completion as completion, custody::Custody, session::Session};
use serde::Deserialize;
use serde_json::{json, value::RawValue, Value};
use std::io::{BufRead, Read, Write};
use std::sync::Mutex;
use tauri::{
    test::{mock_builder, mock_context, noop_assets, MockRuntime},
    Manager,
};

#[path = "scan_integration_native_host_jobs.rs"]
mod jobs;

const MAX_LINE: u64 = 65_536;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request<'a> {
    id: u64,
    op: Op,
    #[serde(borrow)]
    args: &'a RawValue,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Op {
    Initialize,
    BeginHandoff,
    BeginManual,
    Contact,
    UnlockPreview,
    PreviewRendered,
    Link,
    ContinueLink,
    StartContinueLink,
    PollContinueLink,
    FinishLink,
    CancelLink,
    RecogniseHandoff,
    RecogniseLegacy,
    RelayDecide,
    PreliminaryDecide,
    Compare,
    FinalDecide,
    Finish,
    PendingRecoveries,
    PendingLinks,
    Recover,
    InstalledLinks,
    Metrics,
    Cancel,
    Shutdown,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Initialize {
    mnemonic: Zeroizing<String>,
    passcode: Zeroizing<String>,
    root_pem: String,
    proxy_url: String,
    relay_address: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handoff {
    handoff: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyEntry {
    invitation: Zeroizing<String>,
    presence_code: Zeroizing<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayDecision {
    approve: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    approve: bool,
    passcode: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Presence {
    passcode: Option<Zeroizing<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Recovery {
    application_id: String,
    passcode: Zeroizing<String>,
    approve_rotation: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

fn args<'a, T: Deserialize<'a>>(raw: &'a RawValue) -> Result<T> {
    serde_json::from_str(raw.get()).map_err(|_| UiError::from("HostRequestRefused"))
}

fn view(value: impl Serialize) -> Result<Value> {
    serde_json::to_value(value).map_err(|_| UiError::from("HostInternal"))
}

struct Host {
    app: tauri::App<MockRuntime>,
    initialized: bool,
    jobs: jobs::NativeHostJobs,
}

impl Host {
    fn new() -> Self {
        // FIRST: no application setup or custody code can run before this.
        completion::shared_memkeyring::install();
        let app = mock_builder()
            .manage(AppSession(Mutex::new(Session::default())))
            .build(mock_context(noop_assets()))
            .expect("native host mock application");
        Self {
            app,
            initialized: false,
            jobs: jobs::NativeHostJobs::default(),
        }
    }

    fn initialize(&mut self, args: Initialize) -> Result<Value> {
        if self.initialized {
            return Err(UiError::from("HostAlreadyInitialized"));
        }
        completion::shared_memkeyring::assert_active();
        let http = selfsame_app_identity_net::test_support::HostConfig::new(
            args.root_pem.as_bytes(),
            &args.proxy_url,
        )
        .map_err(|error| match error {
            selfsame_app_identity_net::test_support::ConfigError::Root => {
                UiError::from("HostRootRefused")
            }
            selfsame_app_identity_net::test_support::ConfigError::Proxy => {
                UiError::from("HostProxyRefused")
            }
            selfsame_app_identity_net::test_support::ConfigError::AlreadyConfigured => {
                UiError::from("HostAlreadyConfigured")
            }
        })?;
        let relay = cbcl_transport::HostConfig::new(args.root_pem.as_bytes(), &args.relay_address)
            .map_err(UiError::from)?;
        // Recognise custody input before either once-only configuration changes.
        selfsame_core::derive::parse_mnemonic(&args.mnemonic)
            .map_err(|_| UiError::from("HostMnemonicRefused"))?;
        if args.passcode.chars().count() < crate::custody::MIN_PASSCODE_CHARS {
            return Err(UiError::from("HostPasscodeRefused"));
        }
        crate::store::assert_durable().map_err(|_| UiError::from("HostCustodyRefused"))?;
        if Custody::exists()? || !completion::installed_links()?.is_empty() {
            return Err(UiError::from("HostCustodyRefused"));
        }
        selfsame_app_identity_net::test_support::install(http)
            .map_err(|_| UiError::from("HostAlreadyConfigured"))?;
        cbcl_transport::install_host_config(relay).map_err(UiError::from)?;
        // The custody primitive has no publication/fetch effect. Its restore
        // path checks the mnemonic and seals both roots in the memory backend.
        Custody::restore(&args.mnemonic, &args.passcode)?;
        let _root = Custody::unlock_hierarchy_root(&args.passcode)?;
        if !Custody::exists()? || !Custody::backup_confirmed()? {
            return Err(UiError::from("HostCustodyRefused"));
        }
        self.initialized = true;
        Ok(
            json!({ "outcome": "initialized", "custody": "memory", "backupConfirmed": true,
            "installedLinks": completion::installed_links()? }),
        )
    }

    async fn installed(&self) -> Result<Vec<Value>> {
        // Call the actual command, then load each actual recognised slot. A
        // pending slot can never be projected as installed by this adapter.
        let rows = cbcl_v2_installed_links().await?;
        let generation = completion::root_generation(&Custody::root_public_key()?);
        rows.into_iter()
            .map(|row| {
                let installed = completion::load_installed(&row.application_id)?;
                installed.require_root_generation(generation)?;
                Ok(installed.host_evidence())
            })
            .collect()
    }

    fn recognise_occupied_request(&self, request: &Request<'_>) -> Result<()> {
        match request.op {
            Op::BeginHandoff => {
                let _: single_link::BeginHandoffRequest = args(request.args)?;
            }
            Op::BeginManual => {
                let _: single_link::BeginManualRequest = args(request.args)?;
            }
            Op::Contact
            | Op::PreviewRendered
            | Op::Link
            | Op::ContinueLink
            | Op::StartContinueLink
            | Op::FinishLink
            | Op::CancelLink => {
                let _: single_link::TaggedRequest = args(request.args)?;
            }
            Op::UnlockPreview => {
                let _: single_link::UnlockPreviewRequest = args(request.args)?;
            }
            Op::PollContinueLink => {
                let _: jobs::PollContinueLink = args(request.args)?;
            }
            Op::RecogniseHandoff => {
                let _: Handoff = args(request.args)?;
            }
            Op::RecogniseLegacy => {
                let _: LegacyEntry = args(request.args)?;
            }
            Op::RelayDecide => {
                let _: RelayDecision = args(request.args)?;
            }
            Op::PreliminaryDecide | Op::FinalDecide => {
                let _: Decision = args(request.args)?;
            }
            Op::Compare
            | Op::PendingRecoveries
            | Op::PendingLinks
            | Op::InstalledLinks
            | Op::Metrics => {
                let _: Empty = args(request.args)?;
            }
            Op::Finish => {
                let _: Presence = args(request.args)?;
            }
            Op::Recover => {
                let _: Recovery = args(request.args)?;
            }
            Op::Initialize | Op::Cancel | Op::Shutdown => unreachable!("handled before guard"),
        }
        Ok(())
    }

    async fn dispatch(&mut self, request: &Request<'_>) -> Result<Value> {
        if matches!(request.op, Op::Initialize) {
            let initialize = args(request.args)?;
            if self.jobs.occupied() {
                return Err(UiError::from("HostJobOccupied"));
            }
            return self.initialize(initialize);
        }
        if matches!(request.op, Op::Shutdown) {
            let _: Empty = args(request.args)?;
            self.jobs.teardown(self.app.handle()).await?;
            return Ok(Value::Null);
        }
        if matches!(request.op, Op::Cancel) {
            let _: Empty = args(request.args)?;
            if self.jobs.occupied() {
                return Err(UiError::from("HostJobOccupied"));
            }
            self.app
                .state::<AppSession>()
                .0
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .revoke_cbcl_v2();
            return Ok(Value::Null);
        }
        if !self.initialized {
            return Err(UiError::from("HostNotInitialized"));
        }
        completion::shared_memkeyring::assert_active();
        if self.jobs.occupied() {
            self.recognise_occupied_request(request)?;
            match request.op {
                Op::PollContinueLink
                | Op::InstalledLinks
                | Op::PendingRecoveries
                | Op::PendingLinks
                | Op::Metrics => {}
                Op::CancelLink => {
                    let binding: jobs::StartContinueLink = args(request.args)?;
                    if !self.jobs.matches_attempt(&binding.attempt_tag) {
                        return Err(UiError::from("HostJobRefused"));
                    }
                }
                _ => return Err(UiError::from("HostJobOccupied")),
            }
        }
        match request.op {
            Op::BeginHandoff => view(
                single_link::cbcl_v2_begin_handoff(args(request.args)?, self.app.state()).await?,
            ),
            Op::BeginManual => view(
                single_link::cbcl_v2_begin_manual(args(request.args)?, self.app.state()).await?,
            ),
            Op::Contact => {
                view(single_link::cbcl_v2_contact(args(request.args)?, self.app.state()).await?)
            }
            Op::UnlockPreview => view(
                single_link::cbcl_v2_unlock_preview(args(request.args)?, self.app.state()).await?,
            ),
            Op::PreviewRendered => view(
                single_link::cbcl_v2_preview_rendered(args(request.args)?, self.app.state())
                    .await?,
            ),
            Op::Link => {
                view(single_link::cbcl_v2_link(args(request.args)?, self.app.state()).await?)
            }
            Op::ContinueLink => view(
                single_link::cbcl_v2_continue_link(args(request.args)?, self.app.state()).await?,
            ),
            Op::StartContinueLink => {
                let binding: jobs::StartContinueLink = args(request.args)?;
                let tagged = args(request.args)?;
                self.app
                    .state::<AppSession>()
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .cbcl_v2_attempts
                    .tagged(&binding.attempt_tag)?
                    .check()?;
                let app = self.app.handle().clone();
                self.jobs.start(binding.attempt_tag, async move {
                    view(single_link::cbcl_v2_continue_link(tagged, app.state()).await?)
                })
            }
            Op::PollContinueLink => {
                let request: jobs::PollContinueLink = args(request.args)?;
                self.jobs.require_poll(&request)?;
                let work_active = self
                    .app
                    .state::<AppSession>()
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .cbcl_v2_attempts
                    .tagged_worker_active(&request.attempt_tag)?;
                self.jobs.poll(request, work_active)
            }
            Op::CancelLink => {
                let binding: jobs::StartContinueLink = args(request.args)?;
                single_link::cbcl_v2_cancel_link(args(request.args)?, self.app.state()).await?;
                if self.jobs.occupied() {
                    self.jobs.mark_cancelled(&binding.attempt_tag)?;
                }
                view(())
            }
            Op::FinishLink => {
                let application = self
                    .app
                    .state::<AppSession>()
                    .0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .pending_cbcl_v2
                    .as_ref()
                    .map(|p| p.claimant.profile().application_id.as_str().to_owned())
                    .ok_or_else(|| UiError::from("PairingNotStarted"))?;
                let result =
                    single_link::cbcl_v2_finish_link(args(request.args)?, self.app.state()).await?;
                let installed = self.installed().await?;
                if result.outcome != "installed"
                    || !installed
                        .iter()
                        .any(|row| row["applicationId"] == application)
                {
                    return Err(UiError::from("HostInstalledRecordMissing"));
                }
                Ok(json!({"outcome": result.outcome, "installedLinks": installed}))
            }
            Op::RecogniseHandoff => {
                let args: Handoff = args(request.args)?;
                view(cbcl_v2_recognise_handoff(args.handoff.to_string(), self.app.state()).await?)
            }
            Op::RecogniseLegacy => {
                let args: LegacyEntry = args(request.args)?;
                view(
                    cbcl_v2_recognise(
                        args.invitation.to_string(),
                        args.presence_code.to_string(),
                        self.app.state(),
                    )
                    .await?,
                )
            }
            Op::RelayDecide => {
                let args: RelayDecision = args(request.args)?;
                view(cbcl_v2_relay_decide(args.approve, self.app.state()).await?)
            }
            Op::PreliminaryDecide => {
                let args: Decision = args(request.args)?;
                view(
                    cbcl_v2_preliminary_decide(
                        args.approve,
                        args.passcode.as_deref().cloned(),
                        self.app.state(),
                    )
                    .await?,
                )
            }
            Op::Compare => {
                let _: Empty = args(request.args)?;
                view(cbcl_v2_compare(self.app.state()).await?)
            }
            Op::FinalDecide => {
                let args: Decision = args(request.args)?;
                view(
                    cbcl_v2_final_decide(
                        args.approve,
                        args.passcode.as_deref().cloned(),
                        self.app.state(),
                    )
                    .await?,
                )
            }
            Op::Finish => {
                let args: Presence = args(request.args)?;
                let application = self
                    .app
                    .state::<AppSession>()
                    .0
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .pending_cbcl_v2
                    .as_ref()
                    .map(|pending| {
                        pending
                            .claimant
                            .profile()
                            .application_id
                            .as_str()
                            .to_owned()
                    })
                    .ok_or_else(|| UiError::from("PairingNotStarted"))?;
                let result =
                    cbcl_v2_finish(args.passcode.as_deref().cloned(), self.app.state()).await?;
                let installed = self.installed().await?;
                if result.outcome != "installed"
                    || !installed
                        .iter()
                        .any(|row| row["applicationId"] == application)
                {
                    return Err(UiError::from("HostInstalledRecordMissing"));
                }
                Ok(json!({"outcome": result.outcome, "installedLinks": installed}))
            }
            Op::PendingRecoveries => {
                let _: Empty = args(request.args)?;
                view(cbcl_v2_pending_recoveries().await?)
            }
            Op::PendingLinks => {
                let _: Empty = args(request.args)?;
                view(cbcl_v2_pending_links().await?)
            }
            Op::Recover => {
                let args: Recovery = args(request.args)?;
                let result = cbcl_v2_recover(
                    args.application_id,
                    args.passcode.to_string(),
                    args.approve_rotation,
                )
                .await?;
                Ok(json!({"recovery":result, "installedLinks":self.installed().await?}))
            }
            Op::InstalledLinks => {
                let _: Empty = args(request.args)?;
                view(self.installed().await?)
            }
            Op::Metrics => {
                let _: Empty = args(request.args)?;
                Ok(json!({
                    "identityEffects":completion::identity_effect_count(),
                    "custodyWrites":completion::shared_memkeyring::write_count(),
                    "policyOperations":completion::shared_memkeyring::policy_operations()
                }))
            }
            Op::Initialize | Op::Cancel | Op::Shutdown => unreachable!(),
        }
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        // An undrained job may still own a spawn_blocking operation. Process
        // exit erases memory; never clear the test keyring underneath live work.
        if !self.jobs.occupied() {
            completion::shared_memkeyring::clear();
        }
    }
}

// UiError also supports human/backend messages elsewhere. Never print those:
// this allowlist is closed even if a future command adds dynamic error text.
fn error_category(error: &UiError) -> &'static str {
    match error.to_string().as_str() {
        "PairingWrongMode" => "PairingWrongMode",
        "PairingStaleAttempt" => "PairingStaleAttempt",
        "PairingExpired" => "PairingExpired",
        "PairingClockUnavailable" => "PairingClockUnavailable",
        "PairingCancelled" => "PairingCancelled",
        "HostRequestRefused" => "HostRequestRefused",
        "HostNotInitialized" => "HostNotInitialized",
        "HostAlreadyInitialized" => "HostAlreadyInitialized",
        "HostAlreadyConfigured" => "HostAlreadyConfigured",
        "HostRootRefused" => "HostRootRefused",
        "HostProxyRefused" => "HostProxyRefused",
        "HostRelayAddressRefused" => "HostRelayAddressRefused",
        "HostMnemonicRefused" => "HostMnemonicRefused",
        "HostPasscodeRefused" => "HostPasscodeRefused",
        "HostCustodyRefused" => "HostCustodyRefused",
        "HostInstalledRecordMissing" => "HostInstalledRecordMissing",
        "HostJobOccupied" => "HostJobOccupied",
        "HostJobMissing" => "HostJobMissing",
        "HostJobRefused" => "HostJobRefused",
        "HostJobDrainFailed" => "HostJobDrainFailed",
        "PairingAllocatorKeyRequired" => "PairingAllocatorKeyRequired",
        "PairingAlreadyActive" => "PairingAlreadyActive",
        "PairingApplicationAlreadyLinked" => "PairingApplicationAlreadyLinked",
        "PairingApplicationNotLinked" => "PairingApplicationNotLinked",
        "PairingAuthorityRefused" => "PairingAuthorityRefused",
        "PairingCheckpointRefused" => "PairingCheckpointRefused",
        "PairingCheckpointUnavailable" => "PairingCheckpointUnavailable",
        "PairingFailed" => "PairingFailed",
        "PairingIdentityUnavailable" => "PairingIdentityUnavailable",
        "PairingInvitationExpired" => "PairingInvitationExpired",
        "PairingNotStarted" => "PairingNotStarted",
        "PairingOfferExpired" => "PairingOfferExpired",
        "PairingPolicyUnavailable" => "PairingPolicyUnavailable",
        "PairingPresenceRefused" => "PairingPresenceRefused",
        "PairingPreviewChanged" => "PairingPreviewChanged",
        "PairingProfileUnavailable" => "PairingProfileUnavailable",
        "PairingProvisioningRefused" => "PairingProvisioningRefused",
        "PairingReceiptRefused" => "PairingReceiptRefused",
        "PairingRecoveryRefused" => "PairingRecoveryRefused",
        "PairingRelayRefused" => "PairingRelayRefused",
        "PairingRelayTimedOut" => "PairingRelayTimedOut",
        "PairingRelayTlsRefused" => "PairingRelayTlsRefused",
        "PairingRelayUnavailable" => "PairingRelayUnavailable",
        "PairingResolverRefused" => "PairingResolverRefused",
        "PairingResolverUnavailable" => "PairingResolverUnavailable",
        "PairingRootChanged" => "PairingRootChanged",
        "PairingVersionUnsupported" => "PairingVersionUnsupported",
        "PairingWrongPhase" => "PairingWrongPhase",
        "PresenceRequired" => "PresenceRequired",
        "RecognitionFailed" => "RecognitionFailed",
        _ => "HostCommandRefused",
    }
}

fn reply(output: &mut impl Write, value: Value) -> std::io::Result<()> {
    write!(output, "SPEC077_HOST ")?;
    serde_json::to_writer(&mut *output, &value)?;
    writeln!(output)?;
    output.flush()
}

fn run(input: &mut impl BufRead, output: &mut impl Write) -> std::io::Result<()> {
    let mut host = Host::new();
    let result = (|| {
        loop {
            let mut line = Zeroizing::new(Vec::new());
            let count = input.take(MAX_LINE + 1).read_until(b'\n', &mut line)?;
            if count == 0 {
                break;
            }
            if count as u64 > MAX_LINE {
                reply(
                    output,
                    json!({"id": null, "ok": false, "error": "HostRequestOversize"}),
                )?;
                break;
            }
            let request: Request<'_> = match serde_json::from_slice(&line) {
                Ok(request) => request,
                Err(_) => {
                    reply(
                        output,
                        json!({"id": null, "ok": false, "error": "HostRequestRefused"}),
                    )?;
                    continue;
                }
            };
            let result = tauri::async_runtime::block_on(host.dispatch(&request));
            let shutdown = matches!(request.op, Op::Shutdown) && result.is_ok();
            let response = match result {
                Ok(result) => json!({"id": request.id, "ok": true, "result": result}),
                Err(error) => {
                    json!({"id": request.id, "ok": false, "error": error_category(&error)})
                }
            };
            reply(output, response)?;
            if shutdown {
                break;
            }
        }
        Ok(())
    })();
    let teardown = tauri::async_runtime::block_on(host.jobs.teardown(host.app.handle()));
    match (result, teardown) {
        (Err(error), _) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(_)) => Err(std::io::Error::other("HostJobDrainFailed")),
    }
}

#[test]
#[ignore = "private stdin host; installs global memory custody and loopback routing; run alone"]
fn scan_integration_native_host() {
    // No input, output or command values appear in panic diagnostics.
    // libtest writes an unterminated test-name diagnostic before calling us.
    // Terminate it so even the first response starts with the protocol prefix.
    let mut output = std::io::stdout().lock();
    writeln!(output).expect("host output unavailable");
    assert!(
        run(&mut std::io::stdin().lock(), &mut output).is_ok(),
        "host I/O failed"
    );
}

#[test]
fn native_host_request_grammar_and_error_redaction() {
    for line in [
        r#"{"id":1,"op":"compare","args":{},"extra":1}"#,
        r#"{"id":1,"op":"recognise","args":{}}"#,
        r#"{"id":1,"id":2,"op":"cancel","args":{}}"#,
    ] {
        assert!(serde_json::from_str::<Request<'_>>(line).is_err());
    }
    let raw = RawValue::from_string(r#"{"approve":true,"unexpected":1}"#.into()).unwrap();
    assert!(args::<Decision>(&raw).is_err());
    assert!(serde_json::from_str::<jobs::StartContinueLink>(r#"{"attemptTag":"A"}"#).is_err());
    assert!(serde_json::from_str::<jobs::PollContinueLink>(
        r#"{"attemptTag":"00000000000000000000000000000000","jobId":"A"}"#
    )
    .is_err());
    assert!(serde_json::from_str::<Recovery>(
        r#"{"applicationId":"https://photos.example/selfsame/v2","passcode":"test-only-913","approveRotation":false,"extra":1}"#
    )
    .is_err());
    assert_eq!(
        error_category(&UiError::from("not a closed category")),
        "HostCommandRefused"
    );
}

#[test]
#[ignore = "installs global memory custody/configuration; run alone"]
fn native_host_memory_init_cancel_shutdown_regression() {
    // Private synthetic fixture construction. No secret is printed or stored.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mnemonic = bip39::Mnemonic::from_entropy(&[19; 16]).unwrap();
    let input = Zeroizing::new(format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        json!({"id":1,"op":"initialize","args":{"mnemonic":mnemonic.to_string(),"passcode":"test-only-913","rootPem":cert.cert.pem(),"proxyUrl":"http://127.0.0.1:1","relayAddress":"127.0.0.1:1"}}),
        json!({"id":2,"op":"installed-links","args":{}}),
        json!({"id":3,"op":"pending-recoveries","args":{}}),
        json!({"id":4,"op":"pending-links","args":{}}),
        json!({"id":5,"op":"recover","args":{"applicationId":"https://photos.example/selfsame/v2","passcode":"test-only-913","approveRotation":false}}),
        json!({"id":6,"op":"begin-handoff","args":{"handoff":"SSPAIR2:invalid"}}),
        json!({"id":7,"op":"final-decide","args":{"approve":true,"passcode":"test-only-913"}}),
        json!({"id":8,"op":"cancel","args":{}}),
        json!({"id":9,"op":"installed-links","args":{}}),
        json!({"id":10,"op":"shutdown","args":{}}),
    ));
    let mut output = Vec::new();
    run(&mut std::io::Cursor::new(input.as_bytes()), &mut output).unwrap();
    let text = String::from_utf8(output).unwrap();
    assert!(
        !text.contains("test-only-913")
            && !text.contains(&mnemonic.to_string())
            && !text.contains("SSPAIR2:invalid")
    );
    let responses: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line.strip_prefix("SPEC077_HOST ").unwrap()).unwrap())
        .collect();
    assert_eq!(responses.len(), 10);
    assert_eq!(responses[0]["result"]["custody"], "memory");
    assert_eq!(responses[0]["result"]["backupConfirmed"], true);
    assert_eq!(responses[1]["result"], json!([]));
    assert_eq!(responses[2]["result"], json!([]));
    assert_eq!(responses[3]["result"], json!([]));
    assert_eq!(responses[4]["error"], "PairingCheckpointRefused");
    assert_eq!(responses[5]["error"], "PairingVersionUnsupported");
    assert_eq!(responses[6]["error"], "PairingNotStarted");
    assert_eq!(responses[7]["ok"], true);
    assert_eq!(responses[8]["result"], json!([]));
    assert_eq!(responses[9]["ok"], true);
    completion::shared_memkeyring::assert_active();
    assert!(!Custody::exists().unwrap());
}

#[tokio::test]
#[ignore = "installs global memory custody/configuration; run alone"]
async fn native_host_single_link_reserves_before_contact_and_refuses_profile_failure() {
    native_host_reservation_contact_failure(false).await;
}

#[tokio::test]
#[ignore = "installs global memory custody/configuration; run alone"]
async fn native_host_manual_reserves_before_contact_and_refuses_profile_failure() {
    native_host_reservation_contact_failure(true).await;
}

async fn native_host_reservation_contact_failure(manual: bool) {
    use cbcl_pairing::credential_v2::*;
    use std::net::TcpListener;
    async fn call(host: &mut Host, op: &str, args: Value) -> Result<Value> {
        let line = Zeroizing::new(json!({"id":1,"op":op,"args":args}).to_string());
        let request: Request<'_> = serde_json::from_str(&line).unwrap();
        host.dispatch(&request).await
    }
    let mut host = Host::new();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mnemonic = bip39::Mnemonic::from_entropy(&[19; 16]).unwrap();
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    relay.set_nonblocking(true).unwrap();
    call(
        &mut host,
        "initialize",
        json!({"mnemonic":mnemonic.to_string(),"passcode":"test-only-913",
        "rootPem":cert.cert.pem(),"proxyUrl":format!("http://{}",proxy.local_addr().unwrap()),
        "relayAddress":relay.local_addr().unwrap().to_string()}),
    )
    .await
    .unwrap();
    let now = crate::commands::now();
    let carrier = CredentialV2Carrier::new(CredentialV2CarrierInput {
        application_context: "https://photos.example/selfsame/v2".into(),
        relay_origin: "https://relay.example:9443".into(),
        mailbox_id: [1; 32],
        carrier_ceremony_id: [2; 32],
        carrier_nonce: [3; 32],
        claim_commitment: cbcl_pairing::wire::claim_commitment(
            [1; 32],
            &cbcl_pairing::wire::ClaimToken::new([4; 16]),
        ),
        relay_expires_at: now + 300,
        expected_allocator_key: Some(
            ed25519_dalek::SigningKey::from_bytes(&[6; 32])
                .verifying_key()
                .to_bytes(),
        ),
    })
    .unwrap();
    let manual_bootstrap = CredentialV2ManualBootstrap::new(carrier.clone(), [4; 16], now)
        .unwrap()
        .encode()
        .unwrap();
    let manual_words = CredentialV2ManualWords::from_csprng([5; 4]).encode();
    let handoff =
        CredentialV2Handoff::new(carrier, CredentialV2PresenceCode::new([5; 16], [4; 16]))
            .unwrap()
            .encode()
            .unwrap();
    let writes = completion::shared_memkeyring::write_count();
    let policy = completion::shared_memkeyring::policy_operations();
    let identity_effects = completion::identity_effect_count();
    let reserved = call(
        &mut host,
        if manual {
            "begin-manual"
        } else {
            "begin-handoff"
        },
        if manual {
            json!({"bootstrap":manual_bootstrap.as_str(),"words":manual_words.as_str()})
        } else {
            json!({"handoff":handoff.as_str()})
        },
    )
    .await
    .unwrap();
    assert_eq!(reserved["phase"], "reserved");
    let attempt_tag = reserved["attemptTag"].as_str().unwrap();
    {
        let state = host.app.state::<AppSession>();
        let mut session = state
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(!session
            .cbcl_v2_attempts
            .tagged_worker_active(attempt_tag)
            .unwrap());
        let work = session.cbcl_v2_attempts.start_work().unwrap();
        assert!(session
            .cbcl_v2_attempts
            .tagged_worker_active(attempt_tag)
            .unwrap());
        work.retain();
        assert!(!session
            .cbcl_v2_attempts
            .tagged_worker_active(attempt_tag)
            .unwrap());
    }
    let started = call(
        &mut host,
        "start-continue-link",
        json!({"attemptTag":attempt_tag}),
    )
    .await
    .unwrap();
    assert_eq!(started["state"], "started");
    let job_id = started["jobId"].as_str().unwrap();
    assert_eq!(job_id.len(), 32);
    assert_eq!(
        call(
            &mut host,
            "begin-handoff",
            json!({"handoff":handoff.as_str()})
        )
        .await
        .unwrap_err()
        .to_string(),
        "HostJobOccupied"
    );
    assert_eq!(
        call(
            &mut host,
            "begin-manual",
            json!({"bootstrap":manual_bootstrap.as_str(),"words":manual_words.as_str()})
        )
        .await
        .unwrap_err()
        .to_string(),
        "HostJobOccupied"
    );
    assert_eq!(
        call(
            &mut host,
            "begin-manual",
            json!({"bootstrap":manual_bootstrap.as_str(),"words":manual_words.as_str(),"extra":true})
        )
        .await
        .unwrap_err()
        .to_string(),
        "HostRequestRefused"
    );
    assert_eq!(
        call(&mut host, "installed-links", json!({})).await.unwrap(),
        json!([])
    );
    assert_eq!(
        call(&mut host, "metrics", json!({})).await.unwrap(),
        json!({"identityEffects":identity_effects,"custodyWrites":writes,"policyOperations":policy})
    );
    assert_eq!(
        call(&mut host, "metrics", json!({"extra":true}))
            .await
            .unwrap_err()
            .to_string(),
        "HostRequestRefused"
    );
    let wrong_job = match job_id.split_at(1) {
        ("0", rest) => format!("1{rest}"),
        (_, rest) => format!("0{rest}"),
    };
    assert_eq!(
        call(
            &mut host,
            "poll-continue-link",
            json!({"attemptTag":attempt_tag,"jobId":wrong_job})
        )
        .await
        .unwrap_err()
        .to_string(),
        "HostJobRefused"
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let polled = call(
            &mut host,
            "poll-continue-link",
            json!({"attemptTag":attempt_tag,"jobId":job_id}),
        )
        .await
        .unwrap();
        if polled["state"] == "finished" {
            assert_eq!(polled["ok"], false);
            assert_eq!(polled["error"], "PairingWrongPhase");
            break;
        }
        assert!(std::time::Instant::now() < deadline);
        tokio::task::yield_now().await;
    }
    assert_eq!(
        proxy.accept().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        relay.accept().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(completion::shared_memkeyring::write_count(), writes);
    let tagged = json!({"attemptTag":reserved["attemptTag"]});
    for op in ["preview-rendered", "link", "continue-link", "finish-link"] {
        assert!(call(&mut host, op, tagged.clone()).await.is_err());
    }
    assert_eq!(
        call(
            &mut host,
            "unlock-preview",
            json!({"attemptTag":reserved["attemptTag"],"passcode":false})
        )
        .await
        .err()
        .unwrap()
        .to_string(),
        "HostRequestRefused"
    );
    // This explicit local proxy accepts then closes before TLS/profile success.
    // No request can reach the canonical public origin or selected relay.
    proxy.set_nonblocking(false).unwrap();
    let peer = std::thread::spawn(move || {
        let (stream, _) = proxy.accept().unwrap();
        drop(stream);
    });
    assert_eq!(
        call(&mut host, "contact", tagged.clone())
            .await
            .err()
            .unwrap()
            .to_string(),
        "PairingProfileUnavailable"
    );
    peer.join().unwrap();
    assert_eq!(
        relay.accept().err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(completion::shared_memkeyring::write_count(), writes);
    assert_eq!(completion::shared_memkeyring::policy_operations(), policy);
    assert!(call(&mut host, "cancel-link", tagged).await.is_ok());
    assert!(call(&mut host, "shutdown", json!({})).await.is_ok());
}
