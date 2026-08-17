//! Selfsame application composition for the reusable `cbcl-pairing` protocol.
//!
//! This crate is a Tier-1 prototype. It is not production-approved.
//!
//! A raw pairing effect cannot be promoted into an accepted Selfsame
//! credential by downstream code. The intermediate authority type is private:
//!
//! ```compile_fail
//! use selfsame_pairing::{accept_transferred_credential, ApprovedCredential};
//! ```

#![forbid(unsafe_code)]

/// Dependency evidence exposed to conformance tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DependencyBaseline {
    /// Reviewed sibling Git revision.
    pub revision: &'static str,
    /// Published bootstrap dialect source hash.
    pub bootstrap_source_sha256: &'static str,
    /// Published session dialect source hash.
    pub session_source_sha256: &'static str,
}

/// Return the compiled dependency baseline.
#[must_use]
pub const fn dependency_baseline() -> DependencyBaseline {
    DependencyBaseline {
        revision: "197d4cb3d1560ab5328df28fc984269799c510f9",
        bootstrap_source_sha256: cbcl_pairing::BOOTSTRAP_SOURCE_SHA256,
        session_source_sha256: cbcl_pairing::SESSION_SOURCE_SHA256,
    }
}

use cbcl_pairing::{
    cbcl_protocol::{
        build_bootstrap_control, BootstrapMonitor, BootstrapPerformative, CeremonySigningKey,
    },
    channel::PendingChannel,
    context::PairingContext,
    cpace,
    endpoint::{EndpointEffect, EndpointReducer, InvitationRecord},
    limiter::{LimiterConfig, OperationPolicy},
    observability::CapacityCaps,
    profile::{
        CredentialGrant, CredentialIntentClaims, CredentialProfile, DisplayIntent, GrantVerifier,
        ProfileError, RecognisedPayload, CREDENTIAL_ACTION, CREDENTIAL_APPLICATION,
        CREDENTIAL_PAYLOAD,
    },
    relay::{ConnectionId, RelayConfig, RelayRandomness, RelayService, RoutedMessage},
    wire::{
        decode_channel_frame, decode_client_message, decode_invitation, decode_server_message,
        encode_channel_frame, encode_client_message, encode_cpace_message, encode_invitation,
        encode_server_message, ApplicationPayload, ChannelFrame, ClientMessage, CloseReason,
        Decision, Invitation, Locator, PairingIntent, ServerMessage, Side,
    },
};
use cbcl_pairing_core::message::CausedBy;
use selfsame_app_identity::{
    accept::{
        self, AcceptError, Acceptance, Evidence, Expectation, Freshness, IssuerState, Projection,
    },
    alias::{AcctUri, Jrd},
    ceremony,
    profile::ApplicationProfile,
    proof::Challenge,
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use zeroize::{Zeroize, Zeroizing};

const RELAY_ORIGIN: &str = "https://relay.demo.invalid";

/// Explicit shell-supplied entropy for one deterministic ceremony.
pub struct CeremonyEntropy {
    /// Direct mailbox identifier.
    pub mailbox_id: [u8; 32],
    /// Sixteen-octet invitation secret.
    pub invitation_secret: [u8; 16],
    /// Allocator CPace scalar input.
    pub allocator_cpace: [u8; 32],
    /// Claimant CPace scalar input.
    pub claimant_cpace: [u8; 32],
    /// Allocator ceremony signing seed.
    pub allocator_signing: [u8; 32],
    /// Claimant ceremony signing seed.
    pub claimant_signing: [u8; 32],
    /// Relay limiter HMAC key.
    pub relay_operator_key: [u8; 32],
    /// Allocator relay membership token.
    pub allocator_membership: [u8; 32],
    /// Claimant relay membership token.
    pub claimant_membership: [u8; 32],
    /// Intent nonce.
    pub intent_nonce: [u8; 32],
}

impl Drop for CeremonyEntropy {
    fn drop(&mut self) {
        self.mailbox_id.zeroize();
        self.invitation_secret.zeroize();
        self.allocator_cpace.zeroize();
        self.claimant_cpace.zeroize();
        self.allocator_signing.zeroize();
        self.claimant_signing.zeroize();
        self.relay_operator_key.zeroize();
        self.allocator_membership.zeroize();
        self.claimant_membership.zeroize();
        self.intent_nonce.zeroize();
    }
}

/// Application fields and the exact PROTO-004 bundle to transfer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialTransfer {
    /// Canonical Selfsame application identifier.
    pub application_id: String,
    /// Canonical HTTPS application origin.
    pub origin: String,
    /// Requested account scope.
    pub scope: String,
    /// Intended recipient.
    pub recipient: String,
    /// Complete PROTO-004 grant bundle.
    pub bundle: Vec<u8>,
}

/// Closed verifier failure at the Selfsame boundary.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VerificationFailure {
    /// The transferred value is not a complete PROTO-004 bundle.
    #[error("bundle recognition failed")]
    Bundle,
    /// The thirteen-step Selfsame predicate refused the credential.
    #[error("Selfsame acceptance failed at step {0}")]
    Selfsame(u8),
}

impl From<AcceptError> for VerificationFailure {
    fn from(value: AcceptError) -> Self {
        Self::Selfsame(value.step as u8)
    }
}

/// An owned proof resolved by the Selfsame shell for one verifier session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfsameProof {
    /// The consumed proof challenge.
    pub challenge: Challenge,
    /// Device signature over the challenge.
    pub signature: [u8; 64],
    /// Opaque verifier session that issued the challenge.
    pub verifier_session: String,
}

/// Owned shell evidence for Selfsame's complete thirteen-step predicate.
///
/// This context supplies facts the pure verifier cannot resolve itself. It does
/// not supply an acceptance result: the adapter always invokes
/// [`selfsame_app_identity::accept::accept_grant`] directly after pairing
/// releases the exact approved bundle.
#[derive(Clone, Debug)]
pub struct SelfsameVerificationContext {
    /// Authenticated application profile.
    pub profile: ApplicationProfile,
    /// Expected account in the authenticated context.
    pub account: AcctUri,
    /// Device key offered by this context.
    pub device_public_key: [u8; 32],
    /// Permissions required by the operation.
    pub operation_permissions: Vec<String>,
    /// Current Unix time supplied by the shell.
    pub now: i64,
    /// Explicit application clock-skew bound.
    pub clock_skew_seconds: i64,
    /// Freshness tier for this verification.
    pub freshness: Freshness,
    /// Verified issuer closure, when resolved.
    pub issuer: Option<IssuerState>,
    /// Reciprocal WebFinger record, when resolved.
    pub jrd: Option<Jrd>,
    /// Optional revocation projection observation.
    pub projection: Option<Projection>,
    /// Consumed device proof for this verifier session.
    pub proof: Option<SelfsameProof>,
}

/// Closed integration failure.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IntegrationError {
    /// Input failed complete closed-language recognition or exact matching.
    #[error("input recognition failed")]
    Recognition,
    /// A pairing protocol gate refused the ceremony.
    #[error("pairing protocol refused the ceremony")]
    Pairing,
    /// Pairing profile claims or credential semantics did not match exactly.
    #[error("pairing profile refused the transfer")]
    Profile,
    /// The authoritative Selfsame predicate refused the approved transfer.
    #[error(transparent)]
    Selfsame(VerificationFailure),
    /// The requested lifecycle transition was not available.
    #[error("ceremony state refused the transition")]
    State,
    /// The shell encountered an input/output failure.
    #[error("shell input/output failed")]
    Io,
}

impl From<VerificationFailure> for IntegrationError {
    fn from(value: VerificationFailure) -> Self {
        match value {
            VerificationFailure::Bundle => Self::Recognition,
            value @ VerificationFailure::Selfsame(_) => Self::Selfsame(value),
        }
    }
}

impl From<std::io::Error> for IntegrationError {
    fn from(_value: std::io::Error) -> Self {
        Self::Io
    }
}

/// One invitation awaiting the claimant's out-of-band carrier.
pub struct PendingTransfer {
    carrier: Zeroizing<Vec<u8>>,
    transfer: CredentialTransfer,
    verification: SelfsameVerificationContext,
    entropy: CeremonyEntropy,
}

impl PendingTransfer {
    /// Allocate one prototype invitation without starting online processing.
    pub fn new(
        transfer: CredentialTransfer,
        verification: SelfsameVerificationContext,
        entropy: CeremonyEntropy,
    ) -> Result<Self, IntegrationError> {
        recognise_transfer_claims(&transfer, &verification)?;
        let invitation = Invitation {
            application: CREDENTIAL_APPLICATION.into(),
            relay_origin: RELAY_ORIGIN.into(),
            locator: Locator::Direct(entropy.mailbox_id),
            secret: entropy.invitation_secret.to_vec(),
            expected_allocator_key: None,
            expected_claimant_key: None,
        };
        let carrier = encode_invitation(&invitation).map_err(|_| IntegrationError::Recognition)?;
        Ok(Self {
            carrier: Zeroizing::new(carrier),
            transfer,
            verification,
            entropy,
        })
    }

    /// Return the complete invitation carrier.
    #[must_use]
    pub fn carrier(&self) -> &[u8] {
        &self.carrier
    }

    /// Consume the invitation and establish both authenticated endpoints.
    pub fn begin(self, presented_carrier: &[u8]) -> Result<DemoCeremony, IntegrationError> {
        if presented_carrier != self.carrier.as_slice() {
            return Err(IntegrationError::Recognition);
        }
        let invitation_value =
            decode_invitation(presented_carrier).map_err(|_| IntegrationError::Recognition)?;
        establish(self, invitation_value)
    }
}

fn recognise_transfer_claims(
    transfer: &CredentialTransfer,
    verification: &SelfsameVerificationContext,
) -> Result<(), IntegrationError> {
    let bundle =
        ceremony::recognise_bundle(&transfer.bundle).map_err(|_| IntegrationError::Recognition)?;
    let compact = selfsame_app_identity::jws::recognise(
        &bundle.grant,
        selfsame_app_identity::grant::GRANT_JWS,
        &[],
    )
    .map_err(|_| IntegrationError::Recognition)?;
    let grant = selfsame_app_identity::grant::recognise(&compact.payload)
        .map_err(|_| IntegrationError::Profile)?;
    let permissions = [transfer.scope.as_str()];
    if transfer.application_id != grant.application
        || transfer.application_id != verification.profile.application_id.as_str()
        || transfer.origin != verification.profile.application_id.origin()
        || transfer.recipient != grant.device_did
        || grant.device_public_key != verification.device_public_key
        || grant.account != verification.account
        || grant
            .permissions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != permissions
        || verification
            .operation_permissions
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != permissions
    {
        return Err(IntegrationError::Profile);
    }
    Ok(())
}

/// An established ceremony awaiting one explicit wallet decision.
pub struct DemoCeremony {
    allocator: EndpointReducer,
    claimant: EndpointReducer,
    transfer: CredentialTransfer,
    expected_grant_body: Vec<u8>,
    verification: SelfsameVerificationContext,
    pairing_verifier_calls: Arc<AtomicUsize>,
    selfsame_verifier_calls: usize,
    display_intent: DisplayIntent,
    relay: BlindRelay,
    terminal: bool,
}

impl DemoCeremony {
    /// Commit approval, transfer one bundle, and apply Selfsame acceptance.
    pub fn approve(&mut self) -> Result<CeremonyOutcome, IntegrationError> {
        if self.terminal {
            return Err(IntegrationError::State);
        }
        self.terminal = true;
        let result = self.approve_inner();
        if result.is_err() {
            self.erase_after_failure();
        }
        result
    }

    fn approve_inner(&mut self) -> Result<CeremonyOutcome, IntegrationError> {
        let decision_frame = one_frame(self.claimant.decide(Decision::Approve))?;
        let decision_frame = self.relay.transmit(Side::Claimant, &decision_frame)?;
        self.allocator
            .receive_frame(&decision_frame)
            .map_err(|_| IntegrationError::Pairing)?;

        let intent_digest = self
            .allocator
            .intent_digest()
            .ok_or(IntegrationError::Pairing)?;
        let payload = ApplicationPayload {
            intent_digest,
            payload_type: CREDENTIAL_PAYLOAD.into(),
            body: self.expected_grant_body.clone(),
        };
        let payload_frame = self
            .allocator
            .send_payload(&payload)
            .map_err(|_| IntegrationError::Pairing)?;
        let payload_frame = self.relay.transmit(Side::Allocator, &payload_frame)?;
        let grant = one_grant(self.claimant.receive_frame(&payload_frame))?;
        if grant.application != CREDENTIAL_APPLICATION
            || grant.payload_type != CREDENTIAL_PAYLOAD
            || grant.body != self.expected_grant_body
        {
            return Err(IntegrationError::Pairing);
        }

        let approved = ApprovedCredential {
            bundle: self.transfer.bundle.clone(),
        };
        self.selfsame_verifier_calls += 1;
        let verification = accept_transferred_credential(&self.verification, approved);
        self.relay.close(Side::Allocator)?;
        close_after_success(&mut self.allocator)?;
        close_after_success(&mut self.claimant)?;
        let acceptance = verification?;
        Ok(CeremonyOutcome::Accepted(Box::new(AcceptedCredential {
            acceptance,
        })))
    }

    /// Commit decline and close without releasing a bundle.
    pub fn decline(&mut self) -> Result<CeremonyOutcome, IntegrationError> {
        if self.terminal {
            return Err(IntegrationError::State);
        }
        self.terminal = true;
        let result = self.decline_inner();
        if result.is_err() {
            self.erase_after_failure();
        }
        result
    }

    fn decline_inner(&mut self) -> Result<CeremonyOutcome, IntegrationError> {
        let decision_frame = one_frame(self.claimant.decide(Decision::Decline))?;
        let decision_frame = self.relay.transmit(Side::Claimant, &decision_frame)?;
        self.allocator
            .receive_frame(&decision_frame)
            .map_err(|_| IntegrationError::Pairing)?;
        self.relay.close(Side::Claimant)?;
        Ok(CeremonyOutcome::Declined)
    }

    /// Cancel both endpoints and erase their secret-bearing state.
    pub fn cancel(&mut self) -> Result<(), IntegrationError> {
        if self.terminal {
            return Err(IntegrationError::State);
        }
        self.terminal = true;
        let allocator = self
            .allocator
            .cancel()
            .map_err(|_| IntegrationError::Pairing);
        let claimant = self
            .claimant
            .cancel()
            .map_err(|_| IntegrationError::Pairing);
        let relay = self.relay.close(Side::Allocator);
        allocator.and(claimant).and(relay)
    }

    /// Apply the relay's authenticated expiry event to both endpoints.
    pub fn expire(&mut self) -> Result<(), IntegrationError> {
        if self.terminal {
            return Err(IntegrationError::State);
        }
        self.terminal = true;
        let relay = self.relay.expire();
        let allocator = self
            .allocator
            .relay_closed(CloseReason::Expired)
            .map(|_| ())
            .map_err(|_| IntegrationError::Pairing);
        let claimant = self
            .claimant
            .relay_closed(CloseReason::Expired)
            .map(|_| ())
            .map_err(|_| IntegrationError::Pairing);
        relay.and(allocator).and(claimant)
    }

    /// Return the fully recognised intent presented to the wallet.
    #[must_use]
    pub const fn display_intent(&self) -> &DisplayIntent {
        &self.display_intent
    }

    /// Return privacy-safe state counters.
    #[must_use]
    pub fn snapshot(&self) -> CeremonySnapshot {
        CeremonySnapshot {
            delivered_payloads: self.claimant.delivered_payloads(),
            pairing_verifier_calls: self.pairing_verifier_calls.load(Ordering::Relaxed),
            selfsame_verifier_calls: self.selfsame_verifier_calls,
            allocator_secrets_erased: self.allocator.secrets_erased(),
            claimant_secrets_erased: self.claimant.secrets_erased(),
            relay_frames: self.relay.frames,
            relay_bytes: self.relay.bytes,
            relay_mailboxes: self.relay.service.mailbox_count(),
        }
    }

    /// Return the relay's privacy-safe debug representation.
    #[must_use]
    pub fn relay_debug(&self) -> String {
        format!("{:?}", self.relay.service)
    }

    fn erase_after_failure(&mut self) {
        let _ = self.allocator.cancel();
        let _ = self.claimant.cancel();
        let _ = self.relay.close(Side::Allocator);
    }
}

/// Pairing-approved bundle that cannot be constructed outside this module.
struct ApprovedCredential {
    bundle: Vec<u8>,
}

fn accept_transferred_credential(
    verification: &SelfsameVerificationContext,
    approved: ApprovedCredential,
) -> Result<Acceptance, VerificationFailure> {
    let recognised =
        ceremony::recognise_bundle(&approved.bundle).map_err(|_| VerificationFailure::Bundle)?;
    let permissions: Vec<&str> = verification
        .operation_permissions
        .iter()
        .map(String::as_str)
        .collect();
    let expectation = Expectation {
        profile: &verification.profile,
        account: &verification.account,
        device_public_key: &verification.device_public_key,
        operation_permissions: &permissions,
        now: verification.now,
        clock_skew_seconds: verification.clock_skew_seconds,
        freshness: verification.freshness,
    };
    let proof = verification.proof.as_ref().map(|proof| {
        (
            &proof.challenge,
            &proof.signature,
            proof.verifier_session.as_str(),
        )
    });
    let evidence = Evidence {
        issuer: verification.issuer.as_ref(),
        jrd: verification.jrd.as_ref(),
        projection: verification.projection,
        proof,
    };
    accept::accept_grant(recognised.grant.as_bytes(), &expectation, &evidence).map_err(Into::into)
}

/// Terminal ceremony outcome.
#[derive(Debug)]
pub enum CeremonyOutcome {
    /// One credential passed pairing and Selfsame authorization.
    Accepted(Box<AcceptedCredential>),
    /// The person declined and no payload was released.
    Declined,
}

/// Opaque accepted credential constructed only after both authorization layers.
#[derive(Debug)]
pub struct AcceptedCredential {
    acceptance: Acceptance,
}

impl AcceptedCredential {
    /// Borrow the authoritative Selfsame acceptance result.
    #[must_use]
    pub const fn acceptance(&self) -> &Acceptance {
        &self.acceptance
    }
}

/// Privacy-safe ceremony counters and erasure evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CeremonySnapshot {
    /// Payloads delivered by the claimant reducer.
    pub delivered_payloads: usize,
    /// Calls made by the pairing profile.
    pub pairing_verifier_calls: usize,
    /// Calls made to the authoritative Selfsame verifier.
    pub selfsame_verifier_calls: usize,
    /// Whether allocator secret-bearing state is erased.
    pub allocator_secrets_erased: bool,
    /// Whether claimant secret-bearing state is erased.
    pub claimant_secrets_erased: bool,
    /// Opaque protocol frames transported by the relay.
    pub relay_frames: usize,
    /// Aggregate encoded frame bytes transported by the relay.
    pub relay_bytes: usize,
    /// Mailboxes retained by the relay.
    pub relay_mailboxes: usize,
}

struct BlindRelay {
    service: RelayService,
    next_sequence: [u8; 2],
    now: u64,
    frames: usize,
    bytes: usize,
}

impl BlindRelay {
    fn new(entropy: &CeremonyEntropy) -> Result<Self, IntegrationError> {
        let limiter_entries = 128;
        let mut value = Self {
            service: RelayService::new(RelayConfig {
                operator_key: entropy.relay_operator_key,
                limiter: LimiterConfig::new(
                    OperationPolicy {
                        limit: 1_000,
                        window_seconds: 60,
                    },
                    limiter_entries,
                    30,
                ),
                capacity: CapacityCaps {
                    open_mailboxes: 4,
                    queue_bytes: 4 * 69_632,
                    limiter_entries: limiter_entries as u64,
                },
                allocation_enabled: true,
            })
            .map_err(|_| IntegrationError::Pairing)?,
            next_sequence: [0, 0],
            now: 1_000,
            frames: 0,
            bytes: 0,
        };
        value.expect_one(
            ConnectionId(1),
            ClientMessage::Bind,
            RelayRandomness {
                mailbox_id: [0; 32],
                membership_token: [0; 32],
                nameplate: 0,
            },
            |message| matches!(message, ServerMessage::Welcome),
        )?;
        value.expect_one(
            ConnectionId(1),
            ClientMessage::Allocate {
                locator_mode: 0,
                ttl_seconds: Some(600),
            },
            RelayRandomness {
                mailbox_id: entropy.mailbox_id,
                membership_token: entropy.allocator_membership,
                nameplate: 0,
            },
            |message| {
                matches!(
                    message,
                    ServerMessage::Allocated {
                        mailbox_id,
                        membership_token,
                        nameplate: None,
                        ..
                    } if *mailbox_id == entropy.mailbox_id
                        && *membership_token == entropy.allocator_membership
                )
            },
        )?;
        value.expect_one(
            ConnectionId(2),
            ClientMessage::Bind,
            RelayRandomness {
                mailbox_id: [0; 32],
                membership_token: [0; 32],
                nameplate: 0,
            },
            |message| matches!(message, ServerMessage::Welcome),
        )?;
        value.expect_one(
            ConnectionId(2),
            ClientMessage::Claim(Locator::Direct(entropy.mailbox_id)),
            RelayRandomness {
                mailbox_id: [0; 32],
                membership_token: entropy.claimant_membership,
                nameplate: 0,
            },
            |message| {
                matches!(
                    message,
                    ServerMessage::Claimed {
                        mailbox_id,
                        membership_token,
                        ..
                    } if *mailbox_id == entropy.mailbox_id
                        && *membership_token == entropy.claimant_membership
                )
            },
        )?;
        Ok(value)
    }

    fn transmit(
        &mut self,
        side: Side,
        frame: &ChannelFrame,
    ) -> Result<ChannelFrame, IntegrationError> {
        let body = encode_channel_frame(frame).map_err(|_| IntegrationError::Pairing)?;
        let (source, destination, sequence_index) = match side {
            Side::Allocator => (ConnectionId(1), ConnectionId(2), 0),
            Side::Claimant => (ConnectionId(2), ConnectionId(1), 1),
        };
        let seq = self.next_sequence[sequence_index];
        self.next_sequence[sequence_index] = seq.checked_add(1).ok_or(IntegrationError::Pairing)?;
        let routed = self.handle(
            source,
            ClientMessage::Put {
                seq,
                body: body.clone(),
            },
            RelayRandomness {
                mailbox_id: [0; 32],
                membership_token: [0; 32],
                nameplate: 0,
            },
        )?;
        let (peer_seq, delivered) = routed
            .into_iter()
            .find_map(|item| match item {
                RoutedMessage {
                    connection,
                    message: ServerMessage::Frame { peer_seq, body },
                } if connection == destination => Some((peer_seq, body)),
                _ => None,
            })
            .ok_or(IntegrationError::Pairing)?;
        self.handle(
            destination,
            ClientMessage::Ack { peer_seq },
            RelayRandomness {
                mailbox_id: [0; 32],
                membership_token: [0; 32],
                nameplate: 0,
            },
        )?;
        self.frames += 1;
        self.bytes += delivered.len();
        decode_channel_frame(&delivered).map_err(|_| IntegrationError::Pairing)
    }

    fn close(&mut self, side: Side) -> Result<(), IntegrationError> {
        let connection = match side {
            Side::Allocator => ConnectionId(1),
            Side::Claimant => ConnectionId(2),
        };
        self.handle(
            connection,
            ClientMessage::Close,
            RelayRandomness {
                mailbox_id: [0; 32],
                membership_token: [0; 32],
                nameplate: 0,
            },
        )?;
        self.service
            .sweep(2_000)
            .map_err(|_| IntegrationError::Pairing)?;
        Ok(())
    }

    fn expire(&mut self) -> Result<(), IntegrationError> {
        self.service
            .sweep(2_000)
            .map_err(|_| IntegrationError::Pairing)?;
        Ok(())
    }

    fn expect_one(
        &mut self,
        connection: ConnectionId,
        message: ClientMessage,
        randomness: RelayRandomness,
        predicate: impl FnOnce(&ServerMessage) -> bool,
    ) -> Result<(), IntegrationError> {
        let routed = self.handle(connection, message, randomness)?;
        if routed.len() == 1 && predicate(&routed[0].message) {
            Ok(())
        } else {
            Err(IntegrationError::Pairing)
        }
    }

    fn handle(
        &mut self,
        connection: ConnectionId,
        message: ClientMessage,
        randomness: RelayRandomness,
    ) -> Result<Vec<RoutedMessage>, IntegrationError> {
        let encoded = encode_client_message(&message).map_err(|_| IntegrationError::Pairing)?;
        let recognised = decode_client_message(&encoded).map_err(|_| IntegrationError::Pairing)?;
        let peer = if connection == ConnectionId(1) {
            b"127.0.0.1:application".as_slice()
        } else {
            b"127.0.0.1:wallet".as_slice()
        };
        let routed = self
            .service
            .handle(connection, peer, self.now, randomness, recognised)
            .map_err(|_| IntegrationError::Pairing)?;
        self.now += 1;
        routed
            .into_iter()
            .map(|item| {
                let encoded =
                    encode_server_message(&item.message).map_err(|_| IntegrationError::Pairing)?;
                let message =
                    decode_server_message(&encoded).map_err(|_| IntegrationError::Pairing)?;
                Ok(RoutedMessage {
                    connection: item.connection,
                    message,
                })
            })
            .collect()
    }
}

#[derive(Debug)]
struct PairingGrantGate {
    calls: Arc<AtomicUsize>,
}

impl GrantVerifier for PairingGrantGate {
    fn verify(&mut self, _payload: &RecognisedPayload) -> Result<(), ProfileError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn establish(
    pending: PendingTransfer,
    invitation_value: Invitation,
) -> Result<DemoCeremony, IntegrationError> {
    let invitation = pending.carrier;
    let entropy = pending.entropy;
    let mut relay = BlindRelay::new(&entropy)?;
    let ceremony = cbcl_pairing::cbcl_protocol::ceremony_id(&invitation);
    let allocator_key = CeremonySigningKey::from_secret(entropy.allocator_signing)
        .map_err(|_| IntegrationError::Pairing)?;
    let claimant_key = CeremonySigningKey::from_secret(entropy.claimant_signing)
        .map_err(|_| IntegrationError::Pairing)?;

    let (allocator_state, allocator_message) = cpace::start_pairing(
        Side::Allocator,
        &invitation_value,
        entropy.mailbox_id,
        entropy.allocator_cpace,
    )
    .map_err(|_| IntegrationError::Pairing)?;
    let (claimant_state, claimant_message) = cpace::start_pairing(
        Side::Claimant,
        &invitation_value,
        entropy.mailbox_id,
        entropy.claimant_cpace,
    )
    .map_err(|_| IntegrationError::Pairing)?;
    let allocator_isk =
        cpace::finish(allocator_state, &claimant_message).map_err(|_| IntegrationError::Pairing)?;
    let claimant_isk =
        cpace::finish(claimant_state, &allocator_message).map_err(|_| IntegrationError::Pairing)?;

    let allocator_body =
        encode_cpace_message(&allocator_message).map_err(|_| IntegrationError::Pairing)?;
    let claimant_body =
        encode_cpace_message(&claimant_message).map_err(|_| IntegrationError::Pairing)?;
    let allocator_control = build_bootstrap_control(
        &allocator_key,
        BootstrapPerformative::CpaceA,
        &ceremony,
        &allocator_body,
        CausedBy::Begin,
    )
    .map_err(|_| IntegrationError::Pairing)?;
    let claimant_control = build_bootstrap_control(
        &claimant_key,
        BootstrapPerformative::CpaceB,
        &ceremony,
        &claimant_body,
        CausedBy::Begin,
    )
    .map_err(|_| IntegrationError::Pairing)?;
    let allocator_cpace = ChannelFrame::Cpace {
        side: Side::Allocator,
        control: allocator_control.clone(),
        message: allocator_body.clone(),
    };
    let claimant_cpace = ChannelFrame::Cpace {
        side: Side::Claimant,
        control: claimant_control.clone(),
        message: claimant_body.clone(),
    };
    let allocator_cpace = relay.transmit(Side::Allocator, &allocator_cpace)?;
    let claimant_cpace = relay.transmit(Side::Claimant, &claimant_cpace)?;
    let allocator_frame_bytes =
        encode_channel_frame(&allocator_cpace).map_err(|_| IntegrationError::Pairing)?;
    let claimant_frame_bytes =
        encode_channel_frame(&claimant_cpace).map_err(|_| IntegrationError::Pairing)?;

    let mut allocator_monitor =
        BootstrapMonitor::new(&invitation).map_err(|_| IntegrationError::Pairing)?;
    let mut claimant_monitor =
        BootstrapMonitor::new(&invitation).map_err(|_| IntegrationError::Pairing)?;
    let allocator_hash = allocator_monitor
        .admit(
            BootstrapPerformative::CpaceA,
            &allocator_control,
            &allocator_body,
        )
        .map_err(|_| IntegrationError::Pairing)?
        .content_hash()
        .to_owned();
    let claimant_hash = allocator_monitor
        .admit(
            BootstrapPerformative::CpaceB,
            &claimant_control,
            &claimant_body,
        )
        .map_err(|_| IntegrationError::Pairing)?
        .content_hash()
        .to_owned();
    claimant_monitor
        .admit(
            BootstrapPerformative::CpaceA,
            &allocator_control,
            &allocator_body,
        )
        .map_err(|_| IntegrationError::Pairing)?;
    claimant_monitor
        .admit(
            BootstrapPerformative::CpaceB,
            &claimant_control,
            &claimant_body,
        )
        .map_err(|_| IntegrationError::Pairing)?;

    let allocator_pending = PendingChannel::new_pairing(
        Side::Allocator,
        allocator_isk,
        &invitation_value,
        entropy.mailbox_id,
        &allocator_frame_bytes,
        &claimant_frame_bytes,
    )
    .map_err(|_| IntegrationError::Pairing)?;
    let claimant_pending = PendingChannel::new_pairing(
        Side::Claimant,
        claimant_isk,
        &invitation_value,
        entropy.mailbox_id,
        &allocator_frame_bytes,
        &claimant_frame_bytes,
    )
    .map_err(|_| IntegrationError::Pairing)?;
    let allocator_record = bound_record(
        &invitation,
        &invitation_value,
        entropy.mailbox_id,
        &claimant_frame_bytes,
    )?;
    let claimant_record = bound_record(
        &invitation,
        &invitation_value,
        entropy.mailbox_id,
        &allocator_frame_bytes,
    )?;
    let pairing_verifier_calls = Arc::new(AtomicUsize::new(0));
    let mut allocator = EndpointReducer::new(
        Side::Allocator,
        &invitation,
        allocator_record,
        allocator_key,
        allocator_monitor,
        allocator_pending,
        allocator_hash.clone(),
        claimant_hash.clone(),
        Box::new(CredentialProfile::new(Box::new(PairingGrantGate {
            calls: pairing_verifier_calls.clone(),
        }))),
    )
    .map_err(|_| IntegrationError::Pairing)?;
    let mut claimant = EndpointReducer::new(
        Side::Claimant,
        &invitation,
        claimant_record,
        claimant_key,
        claimant_monitor,
        claimant_pending,
        allocator_hash,
        claimant_hash,
        Box::new(CredentialProfile::new(Box::new(PairingGrantGate {
            calls: pairing_verifier_calls.clone(),
        }))),
    )
    .map_err(|_| IntegrationError::Pairing)?;

    let allocator_finished = allocator
        .local_finished_frame()
        .map_err(|_| IntegrationError::Pairing)?
        .ok_or(IntegrationError::Pairing)?;
    let allocator_finished = relay.transmit(Side::Allocator, &allocator_finished)?;
    let claimant_finished = claimant
        .local_finished_frame()
        .map_err(|_| IntegrationError::Pairing)?
        .ok_or(IntegrationError::Pairing)?;
    let claimant_finished = relay.transmit(Side::Claimant, &claimant_finished)?;
    claimant
        .receive_frame(&allocator_finished)
        .map_err(|_| IntegrationError::Pairing)?;
    let opener = one_frame(allocator.receive_frame(&claimant_finished))?;
    let opener = relay.transmit(Side::Allocator, &opener)?;
    claimant
        .receive_frame(&opener)
        .map_err(|_| IntegrationError::Pairing)?;
    if !allocator.session_ready() || !claimant.session_ready() {
        return Err(IntegrationError::Pairing);
    }

    let claims = CredentialIntentClaims {
        application_id: pending.transfer.application_id.clone(),
        origin: pending.transfer.origin.clone(),
        scope: pending.transfer.scope.clone(),
        recipient: pending.transfer.recipient.clone(),
    };
    let (allocator_claim, claimant_claim) =
        claims.encode().map_err(|_| IntegrationError::Profile)?;
    let intent = PairingIntent {
        application: CREDENTIAL_APPLICATION.into(),
        action: CREDENTIAL_ACTION.into(),
        allocator_claim,
        claimant_claim,
        authority_summary: "Transfer one Selfsame device grant".into(),
        intent_nonce: entropy.intent_nonce,
    };
    let intent_frame = allocator
        .send_intent(&intent)
        .map_err(|_| IntegrationError::Pairing)?;
    let intent_frame = relay.transmit(Side::Allocator, &intent_frame)?;
    let display_intent = one_display(claimant.receive_frame(&intent_frame))?;
    let expected_grant_body = CredentialGrant {
        application_id: pending.transfer.application_id.clone(),
        origin: pending.transfer.origin.clone(),
        scope: pending.transfer.scope.clone(),
        recipient: pending.transfer.recipient.clone(),
        credential: pending.transfer.bundle.clone(),
    }
    .encode()
    .map_err(|_| IntegrationError::Profile)?;

    Ok(DemoCeremony {
        allocator,
        claimant,
        transfer: pending.transfer,
        expected_grant_body,
        verification: pending.verification,
        pairing_verifier_calls,
        selfsame_verifier_calls: 0,
        display_intent,
        relay,
        terminal: false,
    })
}

fn bound_record(
    invitation: &[u8],
    invitation_value: &Invitation,
    mailbox_id: [u8; 32],
    peer_frame: &[u8],
) -> Result<InvitationRecord, IntegrationError> {
    let context = PairingContext::derive(invitation_value, mailbox_id)
        .map_err(|_| IntegrationError::Pairing)?;
    let mut record = InvitationRecord::new(invitation);
    record
        .bind(mailbox_id, peer_frame, context.channel_context())
        .map_err(|_| IntegrationError::Pairing)?;
    Ok(record)
}

fn one_frame(
    result: Result<Vec<EndpointEffect>, cbcl_pairing::endpoint::ReducerError>,
) -> Result<ChannelFrame, IntegrationError> {
    result
        .map_err(|_| IntegrationError::Pairing)?
        .into_iter()
        .find_map(|effect| match effect {
            EndpointEffect::SendFrame(frame) => Some(frame),
            _ => None,
        })
        .ok_or(IntegrationError::Pairing)
}

fn one_display(
    result: Result<Vec<EndpointEffect>, cbcl_pairing::endpoint::ReducerError>,
) -> Result<DisplayIntent, IntegrationError> {
    result
        .map_err(|_| IntegrationError::Pairing)?
        .into_iter()
        .find_map(|effect| match effect {
            EndpointEffect::DisplayIntent(display) => Some(display),
            _ => None,
        })
        .ok_or(IntegrationError::Pairing)
}

fn one_grant(
    result: Result<Vec<EndpointEffect>, cbcl_pairing::endpoint::ReducerError>,
) -> Result<cbcl_pairing::profile::AuthorisedGrant, IntegrationError> {
    result
        .map_err(|_| IntegrationError::Pairing)?
        .into_iter()
        .find_map(|effect| match effect {
            EndpointEffect::DeliverGrant(grant) => Some(grant),
            _ => None,
        })
        .ok_or(IntegrationError::Pairing)
}

fn close_after_success(endpoint: &mut EndpointReducer) -> Result<(), IntegrationError> {
    endpoint
        .relay_closed(CloseReason::Closed)
        .map_err(|_| IntegrationError::Pairing)?;
    Ok(())
}
