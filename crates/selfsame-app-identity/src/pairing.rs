//! The pairing ceremony's obligations — `CON-213`, `CON-216`, `CON-217`,
//! `CON-218`, `REQ-226`, `REQ-228`, `REQ-229`.
//!
//! These four contracts are one capability: **what an adopting application owes
//! around the [[PROTO-003]] pairing ceremony**. Routing itself is PROTO-003's;
//! the descriptor binding, the preconditions before a code may be shown, the
//! ordering of what may happen after confirmation, and the closure when anything
//! goes wrong are all here.
//!
//! # What is injected, and why that is not a gap
//!
//! PROTO-003 owns SPAKE2 — the password mapping, the two messages, the
//! confirmation MACs, and the derivation of `mailbox_secret_16` from the PAKE
//! key. None of that is implemented here, and none of it needs to be for these
//! four contracts to hold, because **every obligation they state is about
//! ordering, binding, and closure rather than about the primitive**.
//!
//! So a confirmation arrives as an opaque [`Confirmation`] carrying the role it
//! was made for and the `binding_hash` it covers. That is enough to decide every
//! question these contracts ask: whether consent may be shown, whether a mailbox
//! slot may be derived, whether an offer may be sent, and whether the ceremony
//! is burned. Swapping in a real SPAKE2 changes what produces a `Confirmation`,
//! not what may be done once one exists.
//!
//! # `CON-217`: confirmation is necessary and never sufficient
//!
//! The sentence that governs the ordering:
//!
//! > Neither may display consent, derive an application branch, request a
//! > mailbox slot, or send an offer/grant before the confirmation required for
//! > **its role** succeeds.
//!
//! and the one that stops it being read as an authorization:
//!
//! > A valid PAKE confirmation is necessary transport authentication but is
//! > **never sufficient** application authentication or authorization.
//!
//! [`Ceremony::may`] enforces both. Confirmation opens the gate on transport
//! actions; showing consent additionally requires `CON-214` evidence to have
//! verified, because a confirmed channel to an unauthenticated application is
//! exactly the case `REQ-222` refuses.
//!
//! # `CON-218`: burned is terminal, and retry is a new ceremony
//!
//! > A burned ceremony accepts no new frame, confirmation, profile, provider,
//! > carrier, callback, mailbox record, or application evidence.
//!
//! > The only retry transition is `burned -> new ceremony`, with every value
//! > listed in `REQ-229` regenerated.
//!
//! [`Ceremony::burn`] is one-way and [`Ceremony::may`] refuses everything
//! afterwards. [`CeremonyValues`] makes the second half checkable rather than
//! asserted: it fingerprints the thirteen values `REQ-229` names, so
//! [`CeremonyValues::shared_with`] answers "did the retry reuse anything?" with
//! a list rather than a promise.
//!
//! [[PROTO-003]]: ../../../../specs/PROTO-003-selfsame-pairing-v1.md

use crate::json::{self, Json};
use crate::profile::{ApplicationProfile, RendezvousDescriptor};

/// The thirteen values `REQ-229` requires a retry to regenerate.
///
/// Written as a list so a test can iterate it, because "every value listed in
/// REQ-229" is otherwise an obligation a reviewer has to hold in their head
/// while reading a diff.
pub const REGENERATED_VALUES: &[&str] = &[
    "code",
    "meetingPointAddress",
    "providerSession",
    "roleTokens",
    "spake2Ephemerals",
    "mailboxSecret",
    "offer",
    "slots",
    "ciphertext",
    "requestId",
    "ceremonyId",
    "enrollmentEvidence",
    "providerHint",
];

/// Which PROTO-003 role a party plays (`CON-217`).
///
/// Fixed, not negotiated: "The application is PROTO-003 role A and Selfsame is
/// role B." A negotiable role would let a peer choose to be the one whose
/// confirmation is checked first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The adopting application. Always the one that selects the provider,
    /// publishes the record, and writes `pA`.
    Application,
    /// The Selfsame wallet.
    Wallet,
}

impl Role {
    /// The peer role.
    pub fn peer(self) -> Self {
        match self {
            Role::Application => Role::Wallet,
            Role::Wallet => Role::Application,
        }
    }
}

/// A PROTO-003 confirmation, as this crate sees it.
///
/// Opaque by design: what matters to `CON-217` is which role it was made for and
/// which binding it covers, not how the MAC was computed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Confirmation {
    /// The role whose confirmation this is.
    pub role: Role,
    /// The PROTO-003 `binding_hash` the confirmation covers.
    pub binding_hash: [u8; 32],
}

/// A version-1 downgrade, refused rather than accommodated (`CON-218`).
///
/// Each of these is a way to arrive at something that looks like a working
/// pairing while removing the property that made it safe. They are named
/// individually so a corpus case can say which one fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PairingDowngrade {
    /// Deriving an AEAD or mailbox secret directly from `C`, `wib`, or any
    /// rendering of the human code, bypassing SPAKE2.
    ///
    /// The one that matters most, and the negative form of `REQ-226`: "No
    /// client SHALL treat the short code as a bearer key, feed it to the former
    /// direct-secret HKDF, omit SPAKE2, or accept a provider-generated peer
    /// confirmation." A 128-bit code used directly as a key is a key an
    /// eavesdropper can grind offline.
    #[error("secret derived from the human code, bypassing SPAKE2")]
    SecretFromCode,
    /// Carrying a route, nameplate, provider, or application identifier inside
    /// the human code, or asking a person to convey an application identity.
    #[error("routing information carried inside the human code")]
    RoutingInCode,
    /// Transporting the word rendering through a machine carrier instead of `C`.
    #[error("word rendering sent through a machine carrier")]
    WordsOnMachineCarrier,
    /// Omitting either confirmation MAC.
    #[error("a confirmation MAC was omitted")]
    MissingConfirmation,
    /// Making the provider a SPAKE2 responder or password-verifier holder.
    ///
    /// The negative form of `REQ-228`: "The application and wallet SHALL be the
    /// two SPAKE2 endpoints", and the selected provider "SHALL receive no word,
    /// word index, password-equivalent verifier, PAKE key, mailbox key,
    /// offer/grant plaintext, DID, account scope, or authorization decision."
    #[error("the provider was made a SPAKE2 endpoint")]
    ProviderAsPakeEndpoint,
    /// Using Hark or cbcl-bus transcript labels without Selfsame binding.
    #[error("foreign transcript labels without Selfsame binding")]
    ForeignTranscriptLabels,
    /// Treating the QR as an authoritative browser or custom-scheme URL.
    #[error("the QR was treated as an authoritative URL")]
    QrAsUrl,
    /// Accepting a code by searching providers rather than resolving its
    /// `CON-409` record.
    #[error("a code was accepted by searching providers")]
    ProviderSearch,
    /// Changing provider or carrier while retaining any ceremony value.
    #[error("provider or carrier changed while ceremony values were retained")]
    ChangeWithRetainedValues,
}

/// Why the pairing surface refused something.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PairingError {
    /// One of the nine version-1 downgrades.
    #[error("PairingDowngrade: {0}")]
    PairingDowngrade(PairingDowngrade),
    /// The ceremony is in the terminal burned state.
    #[error("the ceremony is burned")]
    Burned,
    /// The wallet received a PAKE frame before the person approved the claimed
    /// pairing target required by PROTO-003 CON-409.
    #[error("the claimed pairing target was not approved before PAKE")]
    PairingTargetUnapproved,
    /// An approval was requested before the resolved pairing target had been
    /// disclosed to the person.
    #[error("the claimed pairing target was not disclosed before approval")]
    PairingTargetUndisclosed,
    /// `CON-216`: the five preconditions are not all met.
    #[error("the pairing bootstrap preconditions are not met")]
    PreconditionsUnmet,
    /// `CON-217`: this role's confirmation has not succeeded.
    #[error("this role's confirmation has not succeeded")]
    Unconfirmed,
    /// `CON-217`: confirmed, but the application is not yet authenticated.
    #[error("confirmation is not application authentication")]
    ApplicationUnauthenticated,
    /// `CON-213`: the response is not one the transport policy admits.
    #[error("the transport response is not admissible")]
    TransportRefused,
    /// `CON-213`/`CON-216`: the origin is not the selected descriptor's.
    #[error("the origin is not the one the selected descriptor names")]
    OriginMismatch,
    /// `CON-216`: a `providerId` matching zero or several descriptors.
    #[error("the record names a provider the profile does not resolve uniquely")]
    ProviderNotUnique,
    /// `CON-216`: the record's digest, descriptor, nameplate, or protocol
    /// changed.
    #[error("the record does not match the authenticated profile")]
    RecordMismatch,
}

// ── CON-216: obligations before a code may be displayed ────────────────────

/// The five steps `CON-216` requires **before the code may be displayed by
/// either party**.
///
/// Ordered and all required. The reason they are a struct of booleans rather
/// than a sequence of calls is that the wallet-generated path runs them *after*
/// the person carries `C` to the application (`ADR-408`), so the order in time
/// varies while the set does not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BootstrapPreconditions {
    /// 1. One descriptor selected under `CON-208`, both probes passing.
    pub descriptor_selected: bool,
    /// 2. That provider's nameplate obtained.
    pub nameplate_obtained: bool,
    /// 3. The complete PROTO-003 binding constructed from the authenticated
    ///    profile and the selected descriptor.
    pub binding_constructed: bool,
    /// 4. Acknowledgement of the immutable `pA` write obtained.
    pub initiator_frame_acknowledged: bool,
    /// 5. The `CON-409` record published, naming the canonical `applicationId`,
    ///    profile digest, `providerId`, and nameplate.
    pub record_published: bool,
}

impl BootstrapPreconditions {
    /// All five, which is the only condition under which a code may be shown.
    pub fn complete(&self) -> bool {
        self.descriptor_selected
            && self.nameplate_obtained
            && self.binding_constructed
            && self.initiator_frame_acknowledged
            && self.record_published
    }

    /// The steps still outstanding, for a diagnostic that names them.
    pub fn outstanding(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.descriptor_selected {
            out.push("descriptor selected under CON-208");
        }
        if !self.nameplate_obtained {
            out.push("provider nameplate obtained");
        }
        if !self.binding_constructed {
            out.push("PROTO-003 binding constructed");
        }
        if !self.initiator_frame_acknowledged {
            out.push("immutable pA write acknowledged");
        }
        if !self.record_published {
            out.push("CON-409 record published");
        }
        out
    }
}

/// What a party may put in front of a person (`CON-216`).
///
/// > The application SHALL NOT render, or ask a person to convey, a pairing URL,
/// > a mailbox URL, a route, a nameplate, or **any value other than the
/// > twelve-word rendering of `C`**.
///
/// An allowlist rather than a denylist, because the obligation is stated as one:
/// the twelve words are the only conveyable value, so anything not on this list
/// is refused without needing to be enumerated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Conveyable {
    /// The twelve-word rendering of `C`. The only value a person conveys.
    TwelveWords,
    /// The application's own authenticated origin, shown as context.
    ///
    /// "That display is a courtesy to the reader, never a protocol input, and
    /// the resolving party ignores it."
    OwnOriginAsContext,
    /// The application's origin, typed by the person under `CON-409` tier 3.
    ///
    /// The single exception, and a last resort rather than a mode. Permitted
    /// only once every other transport tier has failed.
    OriginUnderTierThree,
}

/// Whether a value may be conveyed, given how far the transport ladder has got.
///
/// `TEST-232`'s grammar half. Its routing half — "require a twelve-word code to
/// resolve exactly one CON-409 record" — needs a live record transport and is
/// not covered here.
///
/// `CON-216`: a party "SHALL attempt tiers 1 and 2 first and SHALL NOT offer
/// origin entry as an alternative to resolution, a shortcut past it, or a
/// default."
pub fn may_convey(value: Conveyable, earlier_tiers_exhausted: bool) -> Result<(), PairingError> {
    match value {
        Conveyable::TwelveWords | Conveyable::OwnOriginAsContext => Ok(()),
        Conveyable::OriginUnderTierThree if earlier_tiers_exhausted => Ok(()),
        Conveyable::OriginUnderTierThree => {
            Err(PairingError::PairingDowngrade(PairingDowngrade::RoutingInCode))
        }
    }
}

/// A resolved `CON-409` record, as `CON-216` requires a resolving party to
/// check it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordClaim {
    /// The canonical application identifier the record names.
    pub application_id: String,
    /// The profile digest the record pins, base64url.
    pub profile_digest: String,
    /// The provider the record names.
    pub provider_id: String,
    /// The nameplate the record names.
    pub nameplate: String,
}

/// The target a resolving wallet must disclose before it may begin PAKE.
///
/// This value is constructed only by [`resolve_pairing_target`], after the
/// pure-core profile/digest/provider checks. It deliberately does **not** claim
/// that the record signature or profile digest authenticates the application:
/// signed-record recognition, expiry, and transport remain PROTO-003 work
/// outside this policy prototype.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingTarget {
    application_id: String,
    origin: String,
    provider_id: String,
    nameplate: String,
}

impl PairingTarget {
    /// The record-named canonical application identifier shown to the person.
    pub fn application_id(&self) -> &str {
        &self.application_id
    }

    /// The HTTPS origin shown beside the claimed application identifier.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The selected provider identifier, retained for audit/UI binding.
    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    /// The provider-local nameplate, retained as ceremony context and never
    /// shown as an endpoint-selection affordance.
    pub fn nameplate(&self) -> &str {
        &self.nameplate
    }
}

/// `CON-216`'s "on resolution" checks against the authenticated profile.
///
/// > A `providerId` matching zero or several descriptors, an unresolvable
/// > address, a changed profile digest, descriptor, nameplate, or protocol, and
/// > a record that fails signature or expiry each return a fresh-ceremony
/// > failure. The resolving party never repairs, guesses, broadcasts, or falls
/// > back, and **never searches for a matching nameplate**.
pub fn resolve_record<'a>(
    record: &RecordClaim,
    profile: &'a ApplicationProfile,
) -> Result<&'a RendezvousDescriptor, PairingError> {
    if record.application_id != profile.application_id.as_str() {
        return Err(PairingError::RecordMismatch);
    }
    if record.profile_digest != crate::codec::b64url(profile.digest()) {
        return Err(PairingError::RecordMismatch);
    }
    // "matching zero or several descriptors" — `CON-201` already forbids
    // duplicate provider ids, so several is unreachable through a recognised
    // profile. It is checked anyway: this is the point where a profile that
    // reached here by another route would otherwise silently pick the first.
    let mut found = profile.rendezvous.iter().filter(|d| d.id == record.provider_id);
    let descriptor = found.next().ok_or(PairingError::ProviderNotUnique)?;
    if found.next().is_some() {
        return Err(PairingError::ProviderNotUnique);
    }
    Ok(descriptor)
}

/// Resolve the policy-level target that must be disclosed to a wallet user.
///
/// This is intentionally narrower than a conforming CON-409 resolver: the
/// shell must first authenticate the record's bytes, signature, expiry, and
/// transport response. The pure core then checks the record/profile relation
/// and returns exactly the claimed values the wallet must disclose.
pub fn resolve_pairing_target(
    record: &RecordClaim,
    profile: &ApplicationProfile,
) -> Result<PairingTarget, PairingError> {
    resolve_record(record, profile)?;
    Ok(PairingTarget {
        application_id: profile.application_id.as_str().to_owned(),
        origin: profile.application_id.origin().to_owned(),
        provider_id: record.provider_id.clone(),
        nameplate: record.nameplate.clone(),
    })
}

// ── CON-213: the transport policy and the origin binding ───────────────────

/// What the shell observed on a pairing or mailbox request (`CON-213`).
#[derive(Clone, Copy, Debug)]
pub struct TransportResponse<'a> {
    /// Whether any redirect occurred.
    pub redirected: bool,
    /// Whether the request or response carried credentials.
    pub carried_credentials: bool,
    /// Whether the response set or expected cookies.
    pub carried_cookies: bool,
    /// The `Content-Encoding`, when one was present.
    pub content_encoding: Option<&'a str>,
    /// The response size in octets.
    pub octets: usize,
    /// The HTTP status.
    pub status: u16,
    /// Whether reading consumed the record (destructive-read semantics).
    pub destructive_read: bool,
    /// An endpoint or protocol the server tried to nominate.
    pub server_nominated_endpoint: Option<&'a str>,
}

/// `CON-213`'s response policy.
///
/// > They reject redirects, credentials, cookies, content encoding, oversized
/// > responses, unrecognized statuses, destructive-read semantics, and any
/// > attempt by the server to choose another endpoint or protocol.
///
/// The last is the load-bearing one: a provider that could nominate an endpoint
/// would be choosing where the ceremony happens, and `CON-209`'s authenticated
/// hint exists precisely so "a joiner never accepts a health response or
/// redirect as a provider substitution".
pub fn recognise_transport_response(
    response: &TransportResponse<'_>,
    max_octets: usize,
    recognised_statuses: &[u16],
) -> Result<(), PairingError> {
    if response.redirected
        || response.carried_credentials
        || response.carried_cookies
        || response.destructive_read
        || response.server_nominated_endpoint.is_some()
        || response.octets > max_octets
        || !recognised_statuses.contains(&response.status)
    {
        return Err(PairingError::TransportRefused);
    }
    if response.content_encoding.is_some_and(|e| !e.eq_ignore_ascii_case("identity")) {
        return Err(PairingError::TransportRefused);
    }
    Ok(())
}

/// The two origins a ceremony is bound to (`CON-213`).
///
/// > The selected descriptor's exact `pairingUrl` is the only PAKE relay origin
/// > and its exact `url` is the only mailbox origin for that ceremony.
///
/// They may differ, and may be operated by different organisations — `NFR-206`
/// requires that no wire identifier assume otherwise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundOrigins {
    /// The only PAKE relay origin for this ceremony.
    pub pairing: String,
    /// The only mailbox origin for this ceremony.
    pub mailbox: String,
}

impl BoundOrigins {
    /// Bind to a selected descriptor.
    pub fn of(descriptor: &RendezvousDescriptor) -> Self {
        Self { pairing: descriptor.pairing_url.clone(), mailbox: descriptor.url.clone() }
    }

    /// Whether a PAKE relay request may go to this origin.
    pub fn permits_pairing(&self, origin: &str) -> Result<(), PairingError> {
        if origin == self.pairing {
            Ok(())
        } else {
            Err(PairingError::OriginMismatch)
        }
    }

    /// Whether a mailbox request may go to this origin.
    pub fn permits_mailbox(&self, origin: &str) -> Result<(), PairingError> {
        if origin == self.mailbox {
            Ok(())
        } else {
            Err(PairingError::OriginMismatch)
        }
    }
}

/// `CON-213` and `REQ-228`: "A pairing/rendezvous descriptor supplies no
/// DID-state, account-authority, or status-projection endpoint."
///
/// `REQ-228` states the same boundary from the operator's side: "A provider may
/// operate both pairing and PROTO-002 services, but co-location confers no
/// application, account, DID-state, credential, or PAKE authority."
///
/// Those roles require their own profile descriptors and protocols **even when
/// one operator or DNS origin implements several roles**. Co-location is the
/// trap: a state resolver deployed beside the selected rendezvous must not
/// become an implicit resolver, and `TEST-226` tests exactly that arrangement.
pub const ROLES_A_DESCRIPTOR_DOES_NOT_SUPPLY: &[&str] =
    &["did-crdt-state", "account-authority", "status-projection"];

// ── CON-217 and CON-218: the ceremony ──────────────────────────────────────

/// An action gated by `CON-217`'s ordering rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GatedAction {
    /// Show the code to a person. Gated by `CON-216`'s five preconditions.
    DisplayCode,
    /// Claim the record-selected nameplate, after the wallet's target approval.
    ClaimNameplate,
    /// Send or accept `pA`, `pB`, `cA`, or `cB`. This policy core does not
    /// implement the frames or SPAKE2.
    PakeFrame,
    /// Derive or select an application-account branch.
    DeriveApplicationBranch,
    /// Request a PROTO-002 mailbox slot.
    RequestMailboxSlot,
    /// Seal and write the offer payload.
    SendOffer,
    /// Show the consent screen to a person.
    DisplayConsent,
    /// Seal and write the grant bundle.
    SendGrantBundle,
}

/// The terminal state and everything that leads to it.
#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Live,
    Burned,
}

/// One pairing and grant ceremony, with `CON-217`'s ordering and `CON-218`'s
/// closure.
#[derive(Clone, Debug)]
pub struct Ceremony {
    role: Role,
    binding_hash: [u8; 32],
    preconditions: BootstrapPreconditions,
    /// This party validated the **peer's** confirmation — `cB` for the
    /// application, `cA` for the wallet. This is the one that gates action.
    confirmed: bool,
    /// This party's own confirmation came back through the relay: evidence the
    /// peer holds it, and half of `CON-217`'s mutual confirmation.
    peer_confirmed: bool,
    /// The wallet has disclosed the record-named claimed target and the person
    /// has explicitly approved pairing with it. This is deliberately not
    /// CON-214 application authentication or application-account consent.
    pairing_target_approved: bool,
    /// The exact target that was disclosed before a wallet may record approval.
    disclosed_pairing_target: Option<PairingTarget>,
    application_authenticated: bool,
    initiator_confirmations_seen: u32,
    state: State,
    values: CeremonyValues,
}

impl Ceremony {
    /// Mint a fresh ceremony.
    pub fn new(role: Role, binding_hash: [u8; 32], values: CeremonyValues) -> Self {
        Self {
            role,
            binding_hash,
            preconditions: BootstrapPreconditions::default(),
            confirmed: false,
            peer_confirmed: false,
            pairing_target_approved: false,
            disclosed_pairing_target: None,
            application_authenticated: false,
            initiator_confirmations_seen: 0,
            state: State::Live,
            values,
        }
    }

    /// This party's role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The values `REQ-229` requires a retry to regenerate.
    pub fn values(&self) -> &CeremonyValues {
        &self.values
    }

    /// Whether the ceremony has reached the terminal burned state.
    pub fn is_burned(&self) -> bool {
        self.state == State::Burned
    }

    /// Record progress through `CON-216`'s five preconditions.
    pub fn record_precondition(
        &mut self,
        set: impl FnOnce(&mut BootstrapPreconditions),
    ) -> Result<(), PairingError> {
        self.require_live()?;
        set(&mut self.preconditions);
        Ok(())
    }

    /// Record the claimed target that the wallet disclosed to the person.
    ///
    /// Callers obtain this value from [`resolve_pairing_target`]; keeping the
    /// constructor private means an approval cannot be associated with an
    /// arbitrary caller-created application/origin tuple.
    pub fn record_pairing_target_disclosure(
        &mut self,
        target: PairingTarget,
    ) -> Result<(), PairingError> {
        self.require_live()?;
        self.disclosed_pairing_target = Some(target);
        Ok(())
    }

    /// Record the wallet's explicit approval of the disclosed pairing target.
    ///
    /// This is the CON-409 / TEST-234 boundary for a bearer code: it permits
    /// PAKE traffic only after the person has seen the *claimed* target. It
    /// does not authenticate the application and cannot authorize a grant;
    /// [`record_application_authenticated`](Self::record_application_authenticated)
    /// remains a distinct later transition.
    pub fn record_pairing_target_approval(&mut self) -> Result<(), PairingError> {
        self.require_live()?;
        if self.disclosed_pairing_target.is_none() {
            return Err(PairingError::PairingTargetUndisclosed);
        }
        self.pairing_target_approved = true;
        Ok(())
    }

    /// Record that the person declined the disclosed target.
    ///
    /// Decline has no retry transition inside this ceremony: it burns before a
    /// nameplate claim, PAKE frame, mailbox action, or grant can occur.
    pub fn decline_pairing_target(&mut self) -> Result<(), PairingError> {
        self.require_live()?;
        if self.disclosed_pairing_target.is_none() {
            return Err(PairingError::PairingTargetUndisclosed);
        }
        self.burn();
        Ok(())
    }

    /// Accept a PROTO-003 confirmation.
    ///
    /// A burned ceremony "accepts no new frame, **confirmation**, profile,
    /// provider, carrier, callback, mailbox record, or application evidence",
    /// so this refuses outright afterwards.
    ///
    /// `REQ-229`: "The wallet SHALL evaluate at most one initiator confirmation
    /// per minted ceremony." A second one burns the ceremony rather than being
    /// ignored — an attacker who can retry confirmations against one minted
    /// ceremony is an attacker with more than one guess at the code.
    ///
    /// # Which confirmation opens the gate
    ///
    /// [`Confirmation::role`] names the party that **produced** the MAC, and a
    /// party is never authenticated by its own. PROTO-003 CON-405 states the
    /// obligation from each side:
    ///
    /// > Role B SHALL NOT \[accept\] application data before validating `cA`.
    /// > Role A SHALL NOT accept the PAKE or mailbox output before validating
    /// > `cB`.
    ///
    /// and its state machine says the same thing twice:
    ///
    /// ```text
    /// A: allocate -> pA stored -> pB locked -> cA stored -> cB verified -> confirmed
    /// B: claim    -> pA locked -> pB stored -> cA verified -> cB stored -> confirmed
    /// ```
    ///
    /// Each role reaches `confirmed` by **verifying the peer's** value, not by
    /// storing its own. So the peer-produced confirmation is what sets
    /// [`confirmed`](Self::mutually_confirmed) and opens [`may`](Self::may);
    /// this party's own MAC, relayed back, is only evidence the peer received
    /// it. Reading it the other way round lets a party unlock the ceremony by
    /// processing its own outbound frame — no peer required.
    pub fn accept_confirmation(
        &mut self,
        confirmation: Confirmation,
    ) -> Result<(), PairingError> {
        self.require_live()?;
        if self.role == Role::Wallet && !self.pairing_target_approved {
            // A frame before disclosure/approval violates the one permitted
            // ordering. Burn rather than leave an attacker an opportunity to
            // replay the same frame after the person acts.
            self.burn();
            return Err(PairingError::PairingTargetUnapproved);
        }
        if confirmation.binding_hash != self.binding_hash {
            self.burn();
            return Err(PairingError::PairingDowngrade(
                PairingDowngrade::ForeignTranscriptLabels,
            ));
        }
        if confirmation.role == self.role {
            // This party's own MAC. It confirms nothing to this party.
            self.peer_confirmed = true;
            return Ok(());
        }
        // The peer's MAC: the one this role is required to validate. For the
        // wallet that is the application's `cA`, and REQ-229 allows exactly one
        // per minted ceremony — the counter is what bounds active guessing.
        if self.role == Role::Wallet {
            self.initiator_confirmations_seen += 1;
            if self.initiator_confirmations_seen > 1 {
                self.burn();
                return Err(PairingError::Burned);
            }
        }
        self.confirmed = true;
        Ok(())
    }

    /// Record that `CON-214` evidence verified for this ceremony.
    ///
    /// The wallet may reach this later authorization stage only after it has
    /// disclosed and obtained approval for the claimed target, then accepted
    /// the application's PAKE confirmation. This does not prove that a real
    /// mailbox exchange occurred — that requires the still-unimplemented
    /// PROTO-003/PROTO-002 transport — but prevents this pure policy model from
    /// representing CON-214 as an earlier substitute for either boundary.
    pub fn record_application_authenticated(&mut self) -> Result<(), PairingError> {
        self.require_live()?;
        if self.role == Role::Wallet && !self.pairing_target_approved {
            return Err(PairingError::PairingTargetUnapproved);
        }
        if !self.confirmed {
            return Err(PairingError::Unconfirmed);
        }
        self.application_authenticated = true;
        Ok(())
    }

    /// Whether both sides have confirmed, which is what `CON-217` calls mutual
    /// confirmation.
    pub fn mutually_confirmed(&self) -> bool {
        self.confirmed && self.peer_confirmed
    }

    /// `CON-217`'s ordering rule, plus `CON-216`'s display precondition.
    pub fn may(&self, action: GatedAction) -> Result<(), PairingError> {
        self.require_live()?;
        match action {
            // CON-216: the five steps come before any code is shown, and they
            // are the only thing that gates it — a code is displayed *before*
            // any confirmation exists.
            GatedAction::DisplayCode => {
                if self.preconditions.complete() {
                    Ok(())
                } else {
                    Err(PairingError::PreconditionsUnmet)
                }
            }
            // The application prepares `pA` before a wallet resolves the
            // record; the wallet may claim or exchange any PAKE frame only
            // after target disclosure and explicit approval.
            GatedAction::ClaimNameplate | GatedAction::PakeFrame => {
                if self.role == Role::Wallet && !self.pairing_target_approved {
                    Err(PairingError::PairingTargetUnapproved)
                } else {
                    Ok(())
                }
            }
            // CON-217: "Neither may … derive an application branch, request a
            // mailbox slot, or send an offer/grant before the confirmation
            // required for its role succeeds."
            GatedAction::RequestMailboxSlot | GatedAction::SendOffer => {
                if self.confirmed {
                    Ok(())
                } else {
                    Err(PairingError::Unconfirmed)
                }
            }
            // The same confirmation gate, plus REQ-222 where the wallet is the
            // party acting. These two are Selfsame's own operations, and
            // REQ-222 names them among the things it "SHALL NOT" do "unless the
            // enrollment evidence in CON-214 authenticates the application
            // origin":
            //
            // > Selfsame SHALL NOT disclose whether an application branch
            // > exists, derive or select an existing application-account home,
            // > sign or publish an authorization delta, issue a device grant,
            // > or write a grant bundle …
            //
            // A confirmed PAKE says only that the channel has two ends. CON-217
            // is explicit that it "is never sufficient application
            // authentication or authorization", and the prohibition here starts
            // at *disclosing that a branch exists* — so a hostile application
            // must not be able to reach a branch derivation by completing a
            // pairing it was always able to complete.
            GatedAction::DeriveApplicationBranch | GatedAction::SendGrantBundle => {
                if !self.confirmed {
                    return Err(PairingError::Unconfirmed);
                }
                if self.role == Role::Wallet && !self.application_authenticated {
                    return Err(PairingError::ApplicationUnauthenticated);
                }
                Ok(())
            }
            // Consent needs both halves. A confirmed channel to an
            // unauthenticated application is exactly what REQ-222 refuses, and
            // CON-217 says a valid confirmation "is never sufficient
            // application authentication or authorization".
            GatedAction::DisplayConsent => {
                if !self.confirmed {
                    return Err(PairingError::Unconfirmed);
                }
                if !self.application_authenticated {
                    return Err(PairingError::ApplicationUnauthenticated);
                }
                Ok(())
            }
        }
    }

    /// Move to the terminal burned state.
    ///
    /// One-way. `CON-218`: "The only retry transition is `burned -> new
    /// ceremony`", which is why there is no `unburn` and no `reset`.
    pub fn burn(&mut self) {
        self.state = State::Burned;
    }

    /// Burn on one of the nine version-1 downgrades.
    pub fn burn_on_downgrade(&mut self, mode: PairingDowngrade) -> PairingError {
        self.burn();
        PairingError::PairingDowngrade(mode)
    }

    fn require_live(&self) -> Result<(), PairingError> {
        if self.state == State::Burned {
            return Err(PairingError::Burned);
        }
        Ok(())
    }
}

/// Fingerprints of the thirteen values `REQ-229` names.
///
/// Not the values themselves: this exists so a test — and an implementation's
/// own audit — can answer "did the retry reuse anything?" without holding
/// secrets. `TEST-226` and `TEST-230` both require that no abandoned value is
/// reused, and that is otherwise an obligation nothing checks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CeremonyValues {
    entries: Vec<(String, [u8; 32])>,
}

impl CeremonyValues {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one value's fingerprint under a `REGENERATED_VALUES` name.
    pub fn record(&mut self, name: &str, value: &[u8]) {
        use sha2::Digest as _;
        let digest: [u8; 32] = sha2::Sha256::digest(value).into();
        self.entries.retain(|(n, _)| n != name);
        self.entries.push((name.to_string(), digest));
    }

    /// The `REGENERATED_VALUES` names not yet recorded.
    pub fn missing(&self) -> Vec<&'static str> {
        REGENERATED_VALUES
            .iter()
            .filter(|name| !self.entries.iter().any(|(n, _)| n == *name))
            .copied()
            .collect()
    }

    /// Names this set shares a fingerprint with another under.
    ///
    /// Empty is the only conforming answer when comparing a retry against the
    /// ceremony it replaced.
    pub fn shared_with(&self, other: &Self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(name, digest)| {
                other.entries.iter().any(|(n, d)| n == name && d == digest)
            })
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// Check `REQ-229`'s retry obligation: a fresh ceremony reuses nothing.
///
/// > A retry SHALL generate a new code `C`, meeting-point address, provider
/// > session, role tokens, SPAKE2 ephemerals, derived mailbox secret, offer,
/// > slots, ciphertext, request ID, ceremony ID, enrollment evidence, and
/// > provider hint.
pub fn retry_is_fresh(
    abandoned: &CeremonyValues,
    retry: &CeremonyValues,
) -> Result<(), PairingError> {
    if !retry.missing().is_empty() {
        return Err(PairingError::PreconditionsUnmet);
    }
    if retry.shared_with(abandoned).is_empty() {
        Ok(())
    } else {
        Err(PairingError::PairingDowngrade(PairingDowngrade::ChangeWithRetainedValues))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BINDING: [u8; 32] = [7u8; 32];

    fn values(salt: u8) -> CeremonyValues {
        let mut v = CeremonyValues::new();
        for (i, name) in REGENERATED_VALUES.iter().enumerate() {
            v.record(name, &[salt, i as u8]);
        }
        v
    }

    fn live(role: Role) -> Ceremony {
        Ceremony::new(role, BINDING, values(1))
    }

    fn ready(role: Role) -> Ceremony {
        let mut c = live(role);
        c.record_precondition(|p| {
            p.descriptor_selected = true;
            p.nameplate_obtained = true;
            p.binding_constructed = true;
            p.initiator_frame_acknowledged = true;
            p.record_published = true;
        })
        .unwrap();
        c
    }

    fn disclosed_target() -> PairingTarget {
        PairingTarget {
            application_id: "https://photos.example/selfsame/application".into(),
            origin: "https://photos.example".into(),
            provider_id: "au-primary".into(),
            nameplate: "482715".into(),
        }
    }

    fn approve_disclosed_target(ceremony: &mut Ceremony) {
        ceremony.record_pairing_target_disclosure(disclosed_target()).unwrap();
        ceremony.record_pairing_target_approval().unwrap();
    }

    // ── CON-216 ────────────────────────────────────────────────────────────

    #[test]
    fn a_code_may_not_be_displayed_until_all_five_preconditions_are_met() {
        let mut c = live(Role::Application);
        assert_eq!(c.may(GatedAction::DisplayCode), Err(PairingError::PreconditionsUnmet));
        assert_eq!(c.values().missing().len(), 0);

        // One at a time; only the fifth opens the gate.
        let steps: [fn(&mut BootstrapPreconditions); 5] = [
            |p| p.descriptor_selected = true,
            |p| p.nameplate_obtained = true,
            |p| p.binding_constructed = true,
            |p| p.initiator_frame_acknowledged = true,
            |p| p.record_published = true,
        ];
        for (i, step) in steps.iter().enumerate() {
            c.record_precondition(step).unwrap();
            let expected_outstanding = 5 - (i + 1);
            assert_eq!(c.preconditions.outstanding().len(), expected_outstanding);
            if expected_outstanding > 0 {
                assert_eq!(
                    c.may(GatedAction::DisplayCode),
                    Err(PairingError::PreconditionsUnmet),
                    "after step {}", i + 1
                );
            }
        }
        assert!(c.may(GatedAction::DisplayCode).is_ok());
    }

    #[test]
    fn the_only_conveyable_value_is_the_twelve_words_and_the_tier_three_origin() {
        assert!(may_convey(Conveyable::TwelveWords, false).is_ok());
        assert!(may_convey(Conveyable::OwnOriginAsContext, false).is_ok());
        // "SHALL NOT offer origin entry as an alternative to resolution, a
        // shortcut past it, or a default."
        assert_eq!(
            may_convey(Conveyable::OriginUnderTierThree, false),
            Err(PairingError::PairingDowngrade(PairingDowngrade::RoutingInCode))
        );
        assert!(may_convey(Conveyable::OriginUnderTierThree, true).is_ok());
    }

    // ── CON-218 ────────────────────────────────────────────────────────────

    #[test]
    fn a_burned_ceremony_accepts_nothing_further() {
        // "A burned ceremony accepts no new frame, confirmation, profile,
        // provider, carrier, callback, mailbox record, or application
        // evidence."
        let mut c = ready(Role::Wallet);
        c.burn();
        assert!(c.is_burned());

        assert_eq!(
            c.accept_confirmation(Confirmation { role: Role::Wallet, binding_hash: BINDING }),
            Err(PairingError::Burned)
        );
        assert_eq!(c.record_application_authenticated(), Err(PairingError::Burned));
        assert_eq!(c.record_precondition(|p| p.record_published = true), Err(PairingError::Burned));
        for action in [
            GatedAction::DisplayCode,
            GatedAction::DeriveApplicationBranch,
            GatedAction::RequestMailboxSlot,
            GatedAction::SendOffer,
            GatedAction::DisplayConsent,
            GatedAction::SendGrantBundle,
        ] {
            assert_eq!(c.may(action), Err(PairingError::Burned), "{action:?}");
        }
    }

    #[test]
    fn burning_is_one_way() {
        // The only retry transition is `burned -> new ceremony`, which is why
        // there is no API that clears the state.
        let mut c = ready(Role::Application);
        c.burn();
        c.burn();
        assert!(c.is_burned());
    }

    #[test]
    fn all_nine_version_one_downgrades_are_named_and_burn_the_ceremony() {
        let modes = [
            PairingDowngrade::SecretFromCode,
            PairingDowngrade::RoutingInCode,
            PairingDowngrade::WordsOnMachineCarrier,
            PairingDowngrade::MissingConfirmation,
            PairingDowngrade::ProviderAsPakeEndpoint,
            PairingDowngrade::ForeignTranscriptLabels,
            PairingDowngrade::QrAsUrl,
            PairingDowngrade::ProviderSearch,
            PairingDowngrade::ChangeWithRetainedValues,
        ];
        assert_eq!(modes.len(), 9, "CON-218 lists exactly nine");
        for mode in modes {
            let mut c = ready(Role::Application);
            let err = c.burn_on_downgrade(mode);
            assert_eq!(err, PairingError::PairingDowngrade(mode));
            assert!(c.is_burned(), "{mode:?} must burn the ceremony");
        }
    }

    // ── REQ-229 ────────────────────────────────────────────────────────────

    #[test]
    fn a_retry_that_reuses_any_value_is_refused() {
        let abandoned = values(1);
        let fresh = values(2);
        assert!(retry_is_fresh(&abandoned, &fresh).is_ok());

        // Reuse exactly one value out of thirteen.
        let mut partial = values(2);
        partial.record("mailboxSecret", &[1u8, 5]);
        assert_eq!(
            retry_is_fresh(&abandoned, &partial),
            Err(PairingError::PairingDowngrade(PairingDowngrade::ChangeWithRetainedValues))
        );
        assert_eq!(partial.shared_with(&abandoned), vec!["mailboxSecret".to_string()]);
    }

    #[test]
    fn a_retry_missing_any_of_the_thirteen_values_is_refused() {
        let abandoned = values(1);
        let mut incomplete = CeremonyValues::new();
        for name in &REGENERATED_VALUES[..12] {
            incomplete.record(name, &[2u8]);
        }
        assert_eq!(incomplete.missing(), vec!["providerHint"]);
        assert_eq!(
            retry_is_fresh(&abandoned, &incomplete),
            Err(PairingError::PreconditionsUnmet)
        );
    }

    #[test]
    fn the_thirteen_regenerated_values_match_req_229() {
        assert_eq!(REGENERATED_VALUES.len(), 13);
        for expected in ["code", "spake2Ephemerals", "mailboxSecret", "ceremonyId", "providerHint"] {
            assert!(REGENERATED_VALUES.contains(&expected), "{expected}");
        }
    }

    // ── CON-217 ────────────────────────────────────────────────────────────

    #[test]
    fn nothing_transport_bearing_happens_before_this_roles_confirmation() {
        let mut c = ready(Role::Application);
        for action in [GatedAction::RequestMailboxSlot, GatedAction::SendOffer] {
            assert_eq!(c.may(action), Err(PairingError::Unconfirmed), "{action:?}");
        }
        // Role A is confirmed by verifying role B's `cB`, not by storing its own
        // `cA`. Its own MAC coming back changes nothing about what it may do.
        c.accept_confirmation(Confirmation { role: Role::Application, binding_hash: BINDING })
            .unwrap();
        for action in [GatedAction::RequestMailboxSlot, GatedAction::SendOffer] {
            assert_eq!(
                c.may(action),
                Err(PairingError::Unconfirmed),
                "{action:?} unlocked on this party's own outbound MAC"
            );
        }
        c.accept_confirmation(Confirmation { role: Role::Wallet, binding_hash: BINDING })
            .unwrap();
        for action in [GatedAction::RequestMailboxSlot, GatedAction::SendOffer] {
            assert!(c.may(action).is_ok(), "{action:?}");
        }
        assert!(c.mutually_confirmed());
    }

    #[test]
    fn wallet_requires_pairing_target_approval_before_accepting_a_pake_frame() {
        // PROTO-003 CON-409 / SPEC-004 TEST-234: `C` is a bearer capability,
        // not intended-application authentication. The wallet must disclose
        // the claimed target and receive this separate approval before it
        // claims a nameplate or accepts an application PAKE frame.
        let mut c = ready(Role::Wallet);
        assert_eq!(
            c.accept_confirmation(Confirmation { role: Role::Application, binding_hash: BINDING }),
            Err(PairingError::PairingTargetUnapproved),
        );
        assert!(c.is_burned(), "an early PAKE frame must not be retryable");

        let mut approved = ready(Role::Wallet);
        assert_eq!(
            approved.record_pairing_target_approval(),
            Err(PairingError::PairingTargetUndisclosed),
        );
        approve_disclosed_target(&mut approved);
        approved
            .accept_confirmation(Confirmation { role: Role::Application, binding_hash: BINDING })
            .unwrap();
        assert_eq!(
            approved.may(GatedAction::DisplayConsent),
            Err(PairingError::ApplicationUnauthenticated),
            "pairing-target approval must not become CON-214 authentication",
        );
        assert_eq!(
            approved.may(GatedAction::SendGrantBundle),
            Err(PairingError::ApplicationUnauthenticated),
            "pairing-target approval must not authorize a grant",
        );

        let mut before_approval = ready(Role::Wallet);
        for action in [GatedAction::ClaimNameplate, GatedAction::PakeFrame] {
            assert_eq!(
                before_approval.may(action),
                Err(PairingError::PairingTargetUnapproved),
                "{action:?} bypassed target approval",
            );
        }
        approve_disclosed_target(&mut before_approval);
        for action in [GatedAction::ClaimNameplate, GatedAction::PakeFrame] {
            assert!(before_approval.may(action).is_ok(), "{action:?} remained closed after approval");
        }
    }

    #[test]
    fn declining_a_disclosed_pairing_target_burns_the_ceremony() {
        let mut c = ready(Role::Wallet);
        c.record_pairing_target_disclosure(disclosed_target()).unwrap();
        c.decline_pairing_target().unwrap();
        assert!(c.is_burned());
        assert_eq!(
            c.accept_confirmation(Confirmation { role: Role::Application, binding_hash: BINDING }),
            Err(PairingError::Burned),
        );
        assert_eq!(c.may(GatedAction::SendGrantBundle), Err(PairingError::Burned));
    }

    #[test]
    fn application_authentication_cannot_precede_wallet_target_approval_and_pake() {
        let mut c = ready(Role::Wallet);
        assert_eq!(
            c.record_application_authenticated(),
            Err(PairingError::PairingTargetUnapproved),
        );
        approve_disclosed_target(&mut c);
        assert_eq!(c.record_application_authenticated(), Err(PairingError::Unconfirmed));
        c.accept_confirmation(Confirmation { role: Role::Application, binding_hash: BINDING })
            .unwrap();
        assert!(c.record_application_authenticated().is_ok());
    }

    #[test]
    fn a_party_is_not_confirmed_by_its_own_outbound_mac() {
        // PROTO-003 CON-405: "Role B SHALL NOT [accept] application data before
        // validating `cA`. Role A SHALL NOT accept the PAKE or mailbox output
        // before validating `cB`." Each side reaches `confirmed` by verifying
        // the *peer's* value. A party that unlocked on its own would need no
        // peer at all, which is the whole of the guarantee.
        for role in [Role::Wallet, Role::Application] {
            let mut c = ready(role);
            if role == Role::Wallet {
                approve_disclosed_target(&mut c);
            }
            c.accept_confirmation(Confirmation { role, binding_hash: BINDING }).unwrap();
            assert_eq!(
                c.may(GatedAction::RequestMailboxSlot),
                Err(PairingError::Unconfirmed),
                "{role:?} unlocked on its own confirmation"
            );
            assert!(!c.mutually_confirmed());
        }
    }

    #[test]
    fn consent_needs_confirmation_and_application_authentication_both() {
        // "A valid PAKE confirmation is necessary transport authentication but
        // is never sufficient application authentication or authorization."
        let mut c = ready(Role::Wallet);
        approve_disclosed_target(&mut c);
        assert_eq!(c.may(GatedAction::DisplayConsent), Err(PairingError::Unconfirmed));

        // The wallet is role B: it is confirmed by validating the application's
        // `cA`.
        c.accept_confirmation(Confirmation { role: Role::Application, binding_hash: BINDING })
            .unwrap();
        assert_eq!(
            c.may(GatedAction::DisplayConsent),
            Err(PairingError::ApplicationUnauthenticated),
            "a confirmed channel to an unauthenticated application is what REQ-222 refuses"
        );

        c.record_application_authenticated().unwrap();
        assert!(c.may(GatedAction::DisplayConsent).is_ok());
    }

    #[test]
    fn the_wallet_discloses_no_branch_and_issues_no_grant_before_con_214_authenticates() {
        // REQ-222: Selfsame "SHALL NOT disclose whether an application branch
        // exists, derive or select an existing application-account home, … issue
        // a device grant, or write a grant bundle unless the enrollment evidence
        // in CON-214 authenticates the application origin". A completed PAKE is
        // not that evidence — any application that can run a ceremony has one.
        let mut c = ready(Role::Wallet);
        approve_disclosed_target(&mut c);
        c.accept_confirmation(Confirmation { role: Role::Application, binding_hash: BINDING })
            .unwrap();
        for action in [GatedAction::DeriveApplicationBranch, GatedAction::SendGrantBundle] {
            assert_eq!(
                c.may(action),
                Err(PairingError::ApplicationUnauthenticated),
                "{action:?} was permitted on a PAKE confirmation alone"
            );
        }
        c.record_application_authenticated().unwrap();
        for action in [GatedAction::DeriveApplicationBranch, GatedAction::SendGrantBundle] {
            assert!(c.may(action).is_ok(), "{action:?}");
        }
    }

    #[test]
    fn a_confirmation_over_another_binding_burns_the_ceremony() {
        let mut c = ready(Role::Wallet);
        approve_disclosed_target(&mut c);
        let err = c
            .accept_confirmation(Confirmation { role: Role::Wallet, binding_hash: [9u8; 32] })
            .unwrap_err();
        assert_eq!(
            err,
            PairingError::PairingDowngrade(PairingDowngrade::ForeignTranscriptLabels)
        );
        assert!(c.is_burned());
    }

    #[test]
    fn the_wallet_evaluates_at_most_one_initiator_confirmation_per_ceremony() {
        // REQ-229. A second attempt is a second guess at the code, so it burns
        // the ceremony rather than being ignored.
        let mut c = ready(Role::Wallet);
        approve_disclosed_target(&mut c);
        let initiator = Confirmation { role: Role::Application, binding_hash: BINDING };
        assert!(c.accept_confirmation(initiator).is_ok());
        assert_eq!(c.accept_confirmation(initiator), Err(PairingError::Burned));
        assert!(c.is_burned());
    }

    #[test]
    fn the_roles_are_fixed_and_complementary() {
        assert_eq!(Role::Application.peer(), Role::Wallet);
        assert_eq!(Role::Wallet.peer(), Role::Application);
    }

    // ── CON-213 ────────────────────────────────────────────────────────────

    fn response<'a>() -> TransportResponse<'a> {
        TransportResponse {
            redirected: false,
            carried_credentials: false,
            carried_cookies: false,
            content_encoding: None,
            octets: 512,
            status: 200,
            destructive_read: false,
            server_nominated_endpoint: None,
        }
    }

    #[test]
    fn the_transport_policy_admits_only_a_plain_bounded_recognised_response() {
        assert!(recognise_transport_response(&response(), 4_096, &[200, 404]).is_ok());
    }

    #[test]
    fn every_condition_con_213_names_is_refused() {
        let cases: Vec<TransportResponse<'_>> = vec![
            TransportResponse { redirected: true, ..response() },
            TransportResponse { carried_credentials: true, ..response() },
            TransportResponse { carried_cookies: true, ..response() },
            TransportResponse { content_encoding: Some("gzip"), ..response() },
            TransportResponse { octets: 4_097, ..response() },
            TransportResponse { status: 500, ..response() },
            TransportResponse { destructive_read: true, ..response() },
            TransportResponse {
                server_nominated_endpoint: Some("https://elsewhere.example"),
                ..response()
            },
        ];
        assert_eq!(cases.len(), 8, "CON-213 names eight rejection conditions");
        for case in cases {
            assert_eq!(
                recognise_transport_response(&case, 4_096, &[200, 404]),
                Err(PairingError::TransportRefused),
                "{case:?}"
            );
        }
        // `identity` is not a content encoding in the sense that matters.
        let plain = TransportResponse { content_encoding: Some("identity"), ..response() };
        assert!(recognise_transport_response(&plain, 4_096, &[200, 404]).is_ok());
    }

    /// `TEST-233` and `TEST-235`, in the part that needs no SPAKE2: the relay
    /// boundary. The confirmation and mailbox-secret halves of those tests need
    /// a live PROTO-003 stack and are not covered here.
    #[test]
    fn the_two_bound_origins_are_separate_and_neither_admits_the_other() {
        // NFR-206: no wire identifier may assume the roles share a DNS origin.
        let origins = BoundOrigins {
            pairing: "https://pairing-au.provider.example".into(),
            mailbox: "https://rendezvous-au.provider.example".into(),
        };
        assert!(origins.permits_pairing("https://pairing-au.provider.example").is_ok());
        assert!(origins.permits_mailbox("https://rendezvous-au.provider.example").is_ok());

        assert_eq!(
            origins.permits_pairing("https://rendezvous-au.provider.example"),
            Err(PairingError::OriginMismatch),
            "the mailbox origin is not a PAKE relay origin"
        );
        assert_eq!(
            origins.permits_mailbox("https://pairing-au.provider.example"),
            Err(PairingError::OriginMismatch)
        );
        assert_eq!(
            origins.permits_mailbox("https://attacker.example"),
            Err(PairingError::OriginMismatch)
        );
    }

    #[test]
    fn a_descriptor_supplies_none_of_the_other_three_roles() {
        assert_eq!(ROLES_A_DESCRIPTOR_DOES_NOT_SUPPLY.len(), 3);
        for role in ["did-crdt-state", "account-authority", "status-projection"] {
            assert!(ROLES_A_DESCRIPTOR_DOES_NOT_SUPPLY.contains(&role));
        }
    }
}

// ── CON-403: the binding object, and the hash both endpoints must agree on ───

/// The nine members `CON-403` fixes, and nothing else.
///
/// # Why this is a type and not a JSON blob
///
/// Both endpoints must construct *the same* object before either processes a
/// peer frame — `CON-403` is emphatic: *"Both parties MUST hold every member
/// below before either processes a peer frame."* They build it from different
/// sources (the application from its own profile and selection, the wallet from
/// the resolved `CON-409` record plus the profile it fetched and pinned), so the
/// one thing that must not vary is the shape. A struct with nine fields and one
/// serialiser is how two implementations reach the same octets.
///
/// # What is deliberately absent
///
/// The code, `C`, and `wib` never appear here. `CON-403` says so, and the reason
/// is the whole point of the ceremony: the binding object is hashed into a
/// transcript that a relay can see the consequences of, and the password must not
/// be recoverable from it.
///
/// Two applications may share a route, provider, number and code. Their different
/// application IDs or profile digests still produce different identities,
/// transcripts, keys and confirmation MACs — which is the property the last test
/// below pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BindingObject {
    /// The canonical application identifier.
    pub application_id: String,
    /// The selected complete descriptor's digest, unpadded base64url SHA-256.
    pub descriptor_digest: String,
    /// The six-digit nameplate.
    pub nameplate: String,
    /// `route || nameplate`.
    pub number: String,
    /// The authenticated application profile's digest.
    pub profile_digest: String,
    /// The protocol name.
    pub protocol: String,
    /// The selected provider.
    pub provider_id: String,
    /// The two-digit route.
    pub route: String,
    /// The binding object version.
    pub version: i64,
}

impl BindingObject {
    /// `SHA256(RFC8785(binding_object))` — `CON-403`'s `binding_hash`.
    ///
    /// The members are listed in the contract's printed order. RFC 8785 sorts, so
    /// the order here changes nothing about the digest; it is kept so a reader
    /// comparing this to `CON-403` sees the same sequence.
    pub fn binding_hash(&self) -> [u8; 32] {
        let value = Json::obj([
            ("applicationId", Json::text(self.application_id.clone())),
            ("descriptorDigest", Json::text(self.descriptor_digest.clone())),
            ("nameplate", Json::text(self.nameplate.clone())),
            ("number", Json::text(self.number.clone())),
            ("profileDigest", Json::text(self.profile_digest.clone())),
            ("protocol", Json::text(self.protocol.clone())),
            ("providerId", Json::text(self.provider_id.clone())),
            ("route", Json::text(self.route.clone())),
            ("version", Json::int(self.version)),
        ]);
        <sha2::Sha256 as sha2::Digest>::digest(json::canonicalise(&value)).into()
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;

    fn object() -> BindingObject {
        BindingObject {
            application_id: "https://photos.example/selfsame/application".into(),
            descriptor_digest: "ZGVzY3JpcHRvci1kaWdlc3QtMzItb2N0ZXRzLWhlcmUtb2s".into(),
            nameplate: "482715".into(),
            number: "03482715".into(),
            profile_digest: "cHJvZmlsZS1kaWdlc3QtMzItb2N0ZXRzLWhlcmUtb2sten8".into(),
            protocol: "selfsame-pairing-v1".into(),
            provider_id: "au-primary".into(),
            route: "03".into(),
            version: 1,
        }
    }

    /// The same object always hashes the same way, whoever built it.
    #[test]
    fn the_binding_hash_is_a_function_of_the_nine_members() {
        assert_eq!(object().binding_hash(), object().binding_hash());
    }

    /// Every member is load-bearing.
    ///
    /// Written as a sweep rather than nine tests because the property is about
    /// the SET: a member that could change without moving the hash would be one an
    /// attacker could vary while both endpoints still agreed.
    #[test]
    fn changing_any_member_changes_the_hash() {
        let base = object().binding_hash();
        let mutations: Vec<Box<dyn Fn(&mut BindingObject)>> = vec![
            Box::new(|o| o.application_id = "https://pictura.example/selfsame/application".into()),
            Box::new(|o| o.descriptor_digest = "b3RoZXItZGVzY3JpcHRvci1kaWdlc3QtdmFsdWUtaGVy".into()),
            Box::new(|o| o.nameplate = "482716".into()),
            Box::new(|o| o.number = "03482716".into()),
            Box::new(|o| o.profile_digest = "b3RoZXItcHJvZmlsZS1kaWdlc3QtdmFsdWUtaGVyZS1v".into()),
            Box::new(|o| o.protocol = "selfsame-pairing-v2".into()),
            Box::new(|o| o.provider_id = "global-secondary".into()),
            Box::new(|o| o.route = "17".into()),
            Box::new(|o| o.version = 2),
        ];
        for (index, mutate) in mutations.iter().enumerate() {
            let mut mutated = object();
            mutate(&mut mutated);
            assert_ne!(mutated.binding_hash(), base, "member {index} did not move the hash");
        }
    }

    /// `CON-403`'s stated consequence: one code, two applications, two ceremonies.
    #[test]
    fn two_applications_sharing_a_code_do_not_share_a_binding() {
        let mut other = object();
        other.application_id = "https://pictura.example/selfsame/application".into();
        // Same route, provider, number — and the code never enters either object.
        assert_eq!(other.route, object().route);
        assert_eq!(other.number, object().number);
        assert_eq!(other.provider_id, object().provider_id);
        assert_ne!(other.binding_hash(), object().binding_hash());
    }
}
