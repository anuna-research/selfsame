# WebAuthn Level 3 vs Selfsame and `cbcl-pairing`

**Comparison date:** 2026-08-17  
**WebAuthn source:** W3C Candidate Recommendation Snapshot, 2026-05-26  
**Selfsame sources:** SPEC-004 v0.15.0-draft and SPEC-007 v0.2.1  
**CBCL source:** `cbcl-pairing` SPEC-001 v0.2.0-draft

## Executive conclusion

WebAuthn, Selfsame, and `cbcl-pairing` are not three competing implementations
of the same protocol.

- **WebAuthn** is an RP-to-authenticator registration and authentication
  protocol. It proves possession of an RP-scoped credential private key, binds
  assertions to an RP ID, origin, and fresh challenge, and can prove user
  presence or verification.
- **Selfsame** is an application/account identity and delegated-authorization
  design. A recoverable, application/account-scoped home DID issues a bounded
  VC to a separately keyed device; a verifier accepts it only after checking
  account binding, permissions, fresh controller state, revocation, validity,
  and device proof.
- **`cbcl-pairing`** is the one-time provisioning channel used to get a
  Selfsame grant from an application-controlled endpoint to a wallet/device
  endpoint. It authenticates possession of an invitation, establishes an
  encrypted channel through an optional blind relay, and gates one payload on
  exact-intent approval. It does not itself establish account identity or
  accept the grant.

The closest product-level comparison is therefore:

```text
WebAuthn
  RP account -> register authenticator credential -> repeated signed login assertions

Selfsame + cbcl-pairing
  recoverable app/account controller -> pair once -> issue device grant
                                      -> repeated grant verification + device proof
```

Selfsame materially overlaps WebAuthn on app/RP scoping, multiple accounts,
fresh challenge proof, consent, and device loss. Its additional proposition is
not “phishing-resistant public-key login”; WebAuthn already provides that with
stronger browser/OS integration. Its additional proposition is a recoverable,
user-controlled, pairwise **authorization issuer** that can delegate to and
revoke independently keyed devices using controller-signed state rather than
only an RP credential database. `cbcl-pairing` adds an application-neutral,
asynchronous, blind-relay provisioning ceremony around that delegation.

## Comparison matrix

| Dimension | WebAuthn Level 3 | Selfsame | `cbcl-pairing` | Assessment |
|---|---|---|---|---|
| Primary purpose | Strong authentication of a user to a WebAuthn RP. | Establish an app/account-scoped controller identity and authorize a device for explicit permissions. | Establish a one-time authenticated encrypted channel and deliver one approval-bound payload. | Different layers; `cbcl-pairing` is not a WebAuthn replacement. |
| Persistent authority | The RP's user account and stored credential record. | The application-account home DID and its signed `did:crdt` state, plus the application's authenticated account binding. | None after the ceremony; invitation and channel state are burned. | Selfsame moves part of authorization truth into holder-controlled signed state, but does not eliminate the application account authority. |
| Account identifier | RP supplies an opaque `user.id`/user handle; distinct accounts at one RP use distinct handles. | Application supplies an opaque stable `accountScopeId`; the wallet derives a distinct home DID and stable `acct:` alias for each `(applicationId, accountScopeId)`. | No account identifier semantics. | Both support multiple unlinkable accounts. Selfsame adds a stable controller key/DID below each account scope. |
| Key creation | Authenticator generates a credential key pair scoped to an RP. | Wallet deterministically derives a home signing key; every device installation generates a fresh random app/account-scoped device key. | Peers derive ephemeral CPace/channel keys from a one-time invitation secret. | WebAuthn and Selfsame device keys are per-site/app; only Selfsame's home controller is deterministically recoverable. |
| What the RP/application receives | Credential ID, public key, counters/backup flags, and later signed assertions. | A signed VC naming the device key, application, account, permissions, validity, and revocation entry, plus controller state needed to verify it. | An opaque application payload only after pairing gates pass. | Selfsame carries delegated authorization semantics; WebAuthn supplies authentication evidence and leaves authorization policy to the RP. |
| Routine proof | Authenticator signs RP/client context including fresh challenge; RP verifies origin, RP ID hash, user presence/verification, and signature. | Device signs a fresh nonce over application ID, account alias, and grant hash; verifier also runs the complete grant predicate. | No routine/session proof; it is a one-shot enrollment/delivery ceremony. | Selfsame's device proof resembles a custom assertion protocol, but lacks WebAuthn's standard browser/authenticator ceremony and UV signal. |
| Origin/phishing binding | User agent and authenticator enforce RP-ID scope; RP verifies expected origin, challenge, RP ID hash, and signature. This is WebAuthn's strongest advantage. | Wallet authenticates an HTTPS `applicationId`, backend enrollment evidence, profile/account/device/permission bindings, available platform caller evidence, and explicit origin/operation consent. | Binds the invitation holder, transcript, roles, intent digest, decision, and payload; application identity comes from the integrating profile, not from pairing alone. | Selfsame aims for phishing resistance by a larger application-specific chain. It does not inherit WebAuthn's universally mediated browser origin boundary, and a near-miss origin authenticated as itself can succeed if the person approves it. |
| User presence / verification | Standard UP and UV bits; passkey authenticators commonly use PIN or biometrics. Optional attestation can support authenticator policy. | Wallet shell gates root-key use on OS user presence and asks for explicit consent; the portable grant/device proof does not carry a WebAuthn-equivalent standardized UV assertion. | Records approve/decline, but does not attest that a PIN or biometric produced the decision. | WebAuthn has the cleaner and more interoperable authentication-factor signal. |
| Human-visible intent | WebAuthn requires consent for credential operations, but does not define a general permission-grant vocabulary or require an application scope summary. | Consent surface names authenticated application origin and requested permissions; accepted VC contains recognized permissions. | Requires one recognized intent and one explicit decision before payload release. | Selfsame/CBCL is stronger for explicit delegation semantics; this is separate from authenticator login consent. |
| Authorization | Successful assertion authenticates; RP applies its own authorization policy. | A valid VC is insufficient. Acceptance also checks expected app/account, allowed permission, issuer closure, revocation, time bounds, and device proof. | Pairing success and approval are explicitly insufficient; the application verifier remains authoritative. | Selfsame is an authorization profile; WebAuthn intentionally is not. |
| Recovery | WebAuthn defines backup eligibility/state but no key-backup or sync protocol. It recommends multiple credentials; credential-manager sync and account recovery are outside the standard. | Home keys can be re-derived from the hierarchy root/recovery secret. Recovery of a particular account also needs its opaque `accountScopeId` from the authenticated application account or protected metadata backup. Device keys are not recovered; new grants are issued. | No recovery; every retry uses a fresh invitation and channel. | Selfsame specifies controller recovery and re-delegation. It should not claim mnemonic-only recovery of every account; v1 is circular if Selfsame is the application's only way to authenticate the recovery request and no protected scope backup exists. |
| Revocation | RP stops accepting/removes a credential. Level 3 signal methods may opportunistically tell attached authenticators to hide or remove rejected credentials; the RP remains authoritative. | Home controller publishes an irreversible signed `RevokeCredential` entry into a grow-only `did:crdt` set; verifier requires sufficiently fresh signed state and bounded grant lifetime. | Burns only pairing invitations and ephemeral session state. | Selfsame adds portable, cryptographically verifiable revocation state; WebAuthn has a simpler RP-local revocation model. |
| Cross-device operation | Multi-device credentials may be backed up; hybrid transport supports using a phone authenticator from a desktop. Backup/sync and underlying hybrid protocol details are not defined by WebAuthn itself. | Wallet can grant a separately keyed browser, CLI, or device without copying the home key. | QR/deep-link/NFC/OS handoff carries a high-entropy invitation; optional relay permits bounded asynchronous rendezvous. | Hybrid WebAuthn covers remote authentication. CBCL covers asynchronous provisioning and arbitrary intent-bound payload delivery. |
| Privacy across applications/RPs | Credentials are RP-scoped and designed to be non-correlatable; their existence is not exposed to other RPs. | Public DIDs, aliases, grants, and device keys differ across both applications and accounts; provider selection carries no stable identity. | Relay cannot see invitation secret, identities, plaintext intent/decision, or payload, but sees network addresses, timing, sizes, mailbox IDs, and expiry. | Both provide pairwise public identifiers. Selfsame's wallet necessarily knows the whole hierarchy; a CBCL relay retains traffic-analysis metadata. |
| Attestation | Optional attestation can prove authenticator provenance/model or enterprise identity, with trust-anchor and privacy tradeoffs; the creation option defaults to `none`. | Core design deliberately avoids a global wallet allowlist; first enrollment uses a human fingerprint comparison, while application enrollment evidence authenticates the requesting application. | No hardware, wallet, or application attestation of its own. | Selfsame favors wallet plurality and human-confirmed first use; WebAuthn can enforce hardware/authenticator policy. “Device-bound” in Selfsame means key equality plus proof of possession, not hardware attestation. |
| Infrastructure | Requires an RP service plus a browser/client and authenticator. It does not require a global identity provider. Synced passkeys may involve a credential-manager service, but that is outside WebAuthn. | Requires an application account authority/profile and fresh issuer state from bundle/cache/resolvers; it forbids a mandatory or undeclared Anuna fallback. | Optional independently operated blind relay; peers can instead use a direct bidirectional transport. | “No mandatory central IdP” is not unique to Selfsame. Its differentiator is operator-neutral controller/delegation state, not mere decentralization rhetoric. |
| Portability | A credential is deliberately usable only for its RP; the same authenticator may hold unrelated credentials for many RPs. | VC bytes are independently verifiable by conforming verifiers, but remain strictly bound to one application, account, device, permission, and validity window. | Transports opaque bytes and does not reinterpret them. | Selfsame portability means verifier/transport independence inside one app scope, not cross-application SSO or a universal bearer credential. |
| Standardization and maturity | Level 3 is a W3C Candidate Recommendation; earlier WebAuthn levels and passkeys are widely deployed. | Tier-1 draft and governed prototype; production approval is explicitly absent. | Draft with locally complete implementation; independent cryptographic, adversarial, operator, profile, and production gates remain open. | Today WebAuthn is deployable infrastructure; Selfsame/CBCL is experimental design and evidence. |

## Where WebAuthn already covers Selfsame's headline claims

Selfsame should not claim the following as unique:

1. **A different public key at each application.** WebAuthn credentials are
   scoped to one RP, and authenticators are expected to make credentials at
   different RPs non-correlatable.
2. **Multiple accounts at one application.** WebAuthn has an opaque RP-supplied
   user handle and explicitly supports multiple account identities at one RP.
3. **Phishing-resistant challenge-response.** WebAuthn binds assertions to the
   RP ID, expected origin, challenge, user presence, and optionally user
   verification, using a browser/OS boundary that Selfsame would have to
   reproduce application by application.
4. **Using a phone from a desktop.** WebAuthn Level 3 exposes hybrid transport
   and multi-device credential use cases.
5. **Removing a lost credential.** An RP can stop accepting it, and Level 3 can
   signal authenticators to hide or delete stale credentials.
6. **No global identity provider.** A device-bound WebAuthn deployment needs
   only the RP and a conforming authenticator; passkey sync providers are an
   implementation option, not a WebAuthn requirement.

## What Selfsame/CBCL adds beyond WebAuthn

The strongest differentiated bundle is:

1. **A recoverable pairwise controller, not merely a credential.** Each
   application account has a stable home DID whose private key can be rederived,
   while each device has a separate non-derived key. This creates a larger
   root-compromise blast radius: compromise of the sealed hierarchy root
   compromises every application/account home below it.
2. **Delegation instead of credential-key replication.** The home controller
   issues a time-bounded, permission-bearing grant to a device. Adding a device
   does not require synchronizing the home private key or treating every device
   credential as an unrelated RP database row.
3. **Controller-signed revocation.** A verifier can check convergent signed
   revocation state and grant expiry, rather than relying solely on an RP's
   private credential table.
4. **Independent verification.** Any conforming verifier with the exact
   application profile, account binding, and fresh controller state can apply
   the same acceptance predicate. The grant is still app-specific, but is not
   meaningful only inside one server implementation.
5. **An intent-bound asynchronous provisioning protocol.** `cbcl-pairing`
   authenticates invitation possession end to end, hides semantics from the
   relay, allows the endpoints to be online at different times, displays exact
   intent, releases one payload after approval, and burns every terminal
   attempt.
6. **Operator substitution without identity rotation.** The application may
   change conforming pairing/state providers without changing the derived home
   identity.

These properties matter only when a product needs holder-controlled delegation
or verification across independently implemented components. If the requirement
is simply passwordless login to one ordinary web service, WebAuthn is smaller,
better integrated, reviewed, and deployed.

## Can they be combined?

Yes, but not by treating the current Selfsame Ed25519 device key as a WebAuthn
credential.

WebAuthn authenticators generate their own keys and sign the WebAuthn assertion
structure. Current Selfsame `CON-207` instead requires a raw Ed25519 signature
over Selfsame's `proof_input`. Even if a WebAuthn authenticator uses Ed25519,
its private key is not exposed for arbitrary signing. Direct reuse therefore
needs a new Selfsame device-proof profile that accepts and verifies a WebAuthn
assertion, including its RP ID, origin, challenge, UP/UV, and signature.

Practical compositions are:

1. **WebAuthn for routine authentication; Selfsame for the control plane.** Use
   Selfsame/CBCL to enroll or revoke device authority, then use WebAuthn for
   ordinary browser sessions. This needs an explicit mapping between a
   Selfsame grant and a registered WebAuthn credential.
2. **WebAuthn as the Selfsame device-proof mechanism.** Amend `CON-205`/`207`
   so the grant names a WebAuthn credential and the verifier accepts a complete
   WebAuthn assertion instead of a raw Ed25519 proof. This preserves browser
   origin and UV guarantees, but is a protocol change rather than an adapter.
3. **WebAuthn/platform authentication to unlock the wallet.** Use the platform
   authenticator to gate access to Selfsame's sealed hierarchy root. This
   improves local custody but does not make the resulting VC or CBCL ceremony a
   WebAuthn protocol exchange.
4. **CBCL only where WebAuthn hybrid is insufficient.** Use CBCL when the
   operation is asynchronous provisioning or must carry explicit delegation
   intent and an arbitrary verified payload. Use WebAuthn hybrid when the task
   is simply authenticating with a phone-held credential.

In particular, `cbcl-pairing` authenticates possession of the one-time
invitation secret, not the human, the RP account, DNS ownership, or wallet
provenance. Those meanings must come from the integrating Selfsame profile and
verifier.

## Recommendation

Do not position Selfsame/CBCL as “better passkeys.” Position it, if retained,
as an **application-scoped delegation and recovery control plane** that can use
WebAuthn as its routine authentication/data-plane proof.

The decisive product test is:

- If every verifier is the same RP and RP-local credential registration,
  recovery, and revocation are acceptable, use WebAuthn.
- If devices must receive independently verifiable, permission-bearing grants
  from a recoverable user-controlled app/account issuer, and provisioning must
  work through replaceable blind infrastructure, Selfsame/CBCL adds a real
  capability.

Before integration, the highest-value design change would be to specify a
WebAuthn-backed `CON-207` alternative and compare its security and complexity
against the current raw-Ed25519 device proof. That would preserve WebAuthn's
origin/UV strengths and leave Selfsame focused on the controller, delegation,
recovery, and revocation semantics WebAuthn does not define.

## Sources

- W3C, [Web Authentication: An API for accessing Public Key Credentials — Level 3](https://www.w3.org/TR/webauthn-3/), especially the Introduction, authenticator model, RP operations, credential loss/key mobility, and privacy sections.
- Selfsame, [SPEC-004 — Application- and Account-Scoped Identity](../specs/SPEC-004-application-scoped-identity.md), especially Orientation, REQ-205–208, REQ-213, REQ-215–217, REQ-222, REQ-228–230, CON-202, and CON-205–207.
- Selfsame, [SPEC-007 — `cbcl-pairing` Protocol Cutover](../specs/SPEC-007-cbcl-pairing-cutover.md), especially REQ-803–805, REQ-809, REQ-811–813, and CON-801–806.
- `cbcl-pairing`, [SPEC-001 — Reusable blind pairing](../../cbcl-pairing/specs/SPEC-001-reusable-blind-pairing.md), especially Orientation, User experience, REQ-002, REQ-008–009, REQ-013–015, and Production gates.
