# Adversarial review: SPEC-004 web-manual binding / first-contact enrolment

Reviewed `main` (`8de3f1b`) through `HEAD` (`46379bb`). Because this change is
not deployable without its two named runtime counterparts, I also inspected the
coupled `cbcl-bus` signing/allocator code at `9683681` and the `did-crdt`
rendezvous code at `b481a8b`.

## Findings

### Critical — The hub is an unauthenticated application-signature oracle

**Locations:**

- `../cbcl-bus/apps/cbcl_chat/src/shell/cbcl-chat-selfsame-application-http.lfe:56-73`
- `../cbcl-bus/apps/cbcl_chat/src/shell/cbcl-chat-selfsame-application-http.lfe:107-109`
- `../cbcl-bus/apps/cbcl_chat/src/cbcl-chat-app.lfe:221-225`
- `crates/selfsame-beam/src/enrollment.rs:130-153`
- `crates/selfsame-web-device/src/lib.rs:1299-1372`

The public `POST /selfsame/enrolment/sign` route signs any caller-supplied
canonical CON-214 statement. The profile-bound NIF verifies only that the chosen
`kid` is in the served profile and that the configured seed is its private key;
it does not establish that chat.anuna.io created the request, validate the
request against server-held ceremony state, or authenticate the caller. The
handler itself documents this missing work. Its `Access-Control-Allow-Origin: *`
also makes the response readable by arbitrary origins. The missing preflight
headers do not close the route: an attacker can make a CORS-simple POST with the
canonical JSON as `text/plain` (or with no explicit content type), and the
handler does not check the media type.

The only present mitigating condition is an unprovisioned signing seed, which
makes every enrolment return 503 and therefore makes the feature unavailable;
as soon as the key required for the feature is provisioned, the oracle is live.

**Concrete failure:** once the newly registered enrolment commands are invoked
as intended, a rogue site fetches/copies the public chat profile and WASM,
chooses a mailbox secret, account scope, device seed, request ID, and ceremony
ID, and asks chat.anuna.io to sign that statement. It then publishes the sealed
offer and gives the victim its code. The wallet fetches the genuine chat
profile, verifies a genuine chat enrolment signature, renders chat's
authenticated origin, issues a chat grant to the attacker's device key, and
writes chat's ADR-912 trust record. The attacker knows the bundle slot, sealing
secret, and device private key, so it can collect and use the credential. This
defeats the property CON-214 is meant to add over possession of the public
profile. The absent CON-221 cross-screen channel described below removes the
only intended first-contact backstop in this implementation. The current UI
dispatch defect blocks honest and hostile use alike, but it is not a security
control and fixing it immediately exposes this path.

The signing service must construct or look up the statement from authenticated,
single-use server-side ceremony state and compare every field before signing;
it must not sign a statement supplied as the authority. Caller authentication,
CSRF/origin policy, replay/rate limits, and a strict request media type should be
part of that boundary.

### High — The manual observation silently admits an Apple/native binding

**Locations:**

- `src-tauri/src/app_grant.rs:191-205`
- `crates/selfsame-app-identity/src/enrollment.rs:632-646`
- `crates/selfsame-app-identity/src/platform.rs:381-390`
- `crates/selfsame-app-identity/tests/con_219_ceremony.rs:601-604`

`observation_for_enrolment_offer` uses `platform_binding_id: None` to mean
"this was the manual web path" and claims every native binding will reject it.
The verifier rejects `None` only for Android. Apple deliberately accepts
unattributed evidence for Universal Links, so the `(None, Apple)` case falls
through successfully. The separate caller-evidence helper has the same policy.
The value therefore describes missing attribution, not the transport that was
actually used, and cannot distinguish Apple Universal Link delivery from a
pasted code.

**Concrete failure:** an Apple-only profile (with no CON-227 binding) has a
backend-signed statement naming its `apple:` binding placed in a manual
rendezvous offer. `cbcl_enrol_start` fabricates `None`; `authorise` accepts the
Apple binding; and the wallet issues and records trust over a path the profile
never declared. With the signing oracle above, a rogue caller can manufacture
this downgrade remotely for any served profile containing an Apple binding.

The first-contact adapter needs a distinct manual-transport observation, and
that adapter must require the resolved binding variant itself to be `Web`.
Apple's unattributed carve-out should remain available only to the Apple
Universal Link adapter.

### High — A real CON-219 link code is consumed by the old SPEC-001 path and can never reach the new commands

**Locations:**

- `src/app.js:509-519`
- `src-tauri/src/commands.rs:319-359`
- `src-tauri/src/lib.rs:96-101`
- `src-tauri/src/app_grant.rs:565-634`

The frontend has no invocation of `cbcl_enrol_start`, `cbcl_enrol_prepare`, or
`cbcl_enrol_confirm`; it always invokes `read_link_code`. That command performs
the read-once rendezvous GET and then parses the plaintext only as a SPEC-001
`record::Offer`. A CON-219 offer fails that parse after its mailbox slot has
already been consumed. Merely registering three additional commands does not
implement ADR-913's promised grammar dispatch.

**Concrete failure:** chat.anuna.io displays a freshly allocated enrolment code,
the user enters it in the shipped wallet, `read_link_code` consumes the sealed
offer, reports "That code isn't valid", and the code cannot be retried. No
consent, grant, or trust record is reachable in the product UI.

Dispatch must occur after one fetch/open and before either grammar-specific
state is committed, or the frontend must call one command that performs that
single-read dispatch atomically.

### High — CON-221's required two-screen fingerprint comparison has no application-side value or wire step

**Locations:**

- `src-tauri/src/app_grant.rs:400-425`
- `src/app-identity.js:289-305`
- `src/app-identity.js:399-405`
- `../cbcl-bus/apps/cbcl_chat/priv/web/app.js:818-823`

`cbcl_enrol_prepare` returns the newly derived home-DID fingerprint only to the
wallet frontend. The chat screen shows the code and then only "Waiting for your
wallet to accept"; it learns the issuer inside the bundle, which is sent only
after `cbcl_enrol_confirm`. There is no pre-confirmation wallet-to-application
message from which the application can display the independently computed
fingerprint. The existing wallet fingerprint screen is an application-details
screen, not wired to the new commands; its own source explicitly says the
wallet is not wired to the ceremony.

**Concrete failure:** on an honest first enrolment, the wallet asks whether the
other screen shows its fingerprint while the other screen has no fingerprint.
The person cannot truthfully confirm, so a conforming ceremony cannot complete.
If the UI treats the prompt as generic approval to make the feature usable,
first contact becomes TOFU and the signing-oracle attack above completes.

The protocol needs an authenticated pre-grant step that lets the application
derive/display the same issuer fingerprint before confirmation, and the UI must
drive the returned `applicability` rather than repurpose the unrelated account
details screen.

### High — The allocator destroys the private device key, then discards the returned grant

**Locations:**

- `crates/selfsame-web-device/src/lib.rs:1285-1293`
- `crates/selfsame-web-device/src/lib.rs:1299-1322`
- `crates/selfsame-web-device/src/lib.rs:1365-1372`
- `../cbcl-bus/apps/cbcl_chat/priv/web/enrol-allocator.mjs:52-61`
- `../cbcl-bus/apps/cbcl_chat/priv/web/enrol-allocator.mjs:94-112`
- `../cbcl-bus/apps/cbcl_chat/priv/web/app.js:821-823`

The JS passes an inline fresh `randomBytes(32)` as `device_seed`. Rust copies it
only long enough to derive the offer's public key, but `EnrolmentAllocator`
stores neither the seed nor a signer. After construction no component retains
the private key to which the wallet binds the grant. On reply, the shell parses
the bundle into facts, clears the allocator, and the application merely prints
"Linked"; it installs neither the compact grant nor the closure into an
application credential store.

**Concrete failure:** an otherwise successful ceremony writes pairing trust and
the browser reports success, but the alleged connected application cannot make
the CON-207 possession proof for the grant's `cnf` key and cannot authenticate
with the credential. Reloading the page makes the loss permanent. Thus the
trust record says "connected application" when no usable connection exists.

The device key must be generated and retained by the application in persistent
device-owned storage (preferably a non-exportable signing handle), and the
validated matching grant/closure must be installed atomically with it before
the application reports success.

### High — Pairing trust is committed before bundle delivery, and trust-store failure is ignored

**Locations:**

- `src-tauri/src/app_grant.rs:531-540`
- `src-tauri/src/app_grant.rs:672-692`
- `src-tauri/src/cbcl_context.rs:95-122`

`confirm_issuance` writes ADR-912 trust before `cbcl_enrol_confirm` even takes
the enrolment transport context or attempts the bundle PUT. A missing context,
slot conflict, rendezvous outage, or network censor therefore returns an error
after the REQ-906 input is already durable. Conversely, the result of
`record_pairing_trust` is discarded, so a successful bundle delivery can be
reported while the origin gate remains closed. `record_pairing_trust` itself is
a two-write record/index update, which makes ignoring its error especially
unsafe.

**Concrete failure:** a MITM drops the final PUT (or the rendezvous is down).
The application receives no grant, the wallet reports
`PairingRelayUnavailable`, but a later invitation for the profile's relay now
passes REQ-906 because the trust record survived the failed ceremony.

The first-contact state transition needs an explicit durable completion state:
deliver/acknowledge the matching bundle, commit trust with checked errors, and
retain enough state to reconcile either side of an unavoidable network/store
failure. A generic `confirm_issuance` should not perform first-contact trust
effects before its caller completes transport.

### High — The public rendezvous is an unbounded, quadratic-cost write service on the shared resolver

**Locations:**

- `../did-crdt/src/service/rendezvous.rs:41-55`
- `../did-crdt/src/service/rendezvous.rs:77-90`
- `../did-crdt/src/service/rendezvous.rs:112-131`
- `src-tauri/src/net.rs:33-44`

Anyone may PUT 4 KiB under each fresh 26-character slot. There is no global or
per-client capacity, admission token, quota, or rate limit. Every PUT takes the
global mutex and scans the entire `HashMap` with `retain`, so filling `N` slots
costs O(N^2) work while retaining roughly `4 KiB * N` for ten minutes. Wildcard
CORS and permissive preflight let any hostile webpage recruit its visitors as
writers. The service is also the wallet's compiled DID resolver, increasing the
blast radius beyond enrolment.

**Concrete failure:** an attacker streams random syntactically valid slot names
and maximum bodies from server-side clients or drive-by browsers. CPU rises
quadratically and memory remains occupied for the TTL, taking down enrolment,
DID resolution, and any other users of `did.anuna.io`. Slot entropy and AEAD
protect a particular ceremony's confidentiality/integrity; they do not limit
resource consumption.

Use bounded storage with O(1)/amortised expiry, request/body limits before full
buffering, and deployment-level rate/capacity controls. CORS should be narrowed
to approved application origins if cross-origin writers are not intentionally
open to every website.

### Medium — Separate pending states allow one ceremony's grant to be delivered into another ceremony

**Locations:**

- `src-tauri/src/app_grant.rs:623-633`
- `src-tauri/src/app_grant.rs:639-660`
- `src-tauri/src/app_grant.rs:665-692`
- `crates/selfsame-web-device/src/lib.rs:531-539`
- `crates/selfsame-web-device/src/lib.rs:1453-1460`
- `../cbcl-bus/apps/cbcl_chat/priv/web/enrol-allocator.mjs:94-112`

`cbcl_enrol_start` unconditionally replaces `pending_enrolment`, while
`prepare_issuance` stores a separate `pending_issuance`. `cbcl_enrol_confirm`
checks its ceremony ID only against the latter, then blindly takes whichever
enrolment context is current. It does not compare that context's ceremony or
request ID to the grant. The wallet then deliberately seals the old grant under
the new offer's transcript and secret, so AEAD succeeds for the new allocator.
Although `bundle_matches_offer_json` exists, the new allocator's `open_bundle`
and its JS caller only decrypt and recognise the bundle; they never call it.

**Concrete failure:** start and prepare A, start B before confirming A, then
confirm A. Trust is written for A, but A's credential and issuer closure are
sealed into B's slot under B's secret. B can decrypt and parse that private
bundle despite its ceremony/request IDs naming A; A waits forever.

Hold one indivisible pending-enrolment state keyed by both IDs, refuse
replacement while it or its confirmation is live, take it atomically at
confirmation, and require `bundle_matches_offer` inside `EnrolmentAllocator::open_bundle`.

### Medium — First-contact provider “observations” are copied from the hint, so undeclared providers pass

**Locations:**

- `src-tauri/src/app_grant.rs:178-205`
- `crates/selfsame-app-identity/src/authorise.rs:174-199`
- `crates/selfsame-app-identity/src/provider_hint.rs:106-129`

The first-contact adapter copies `provider_id` and `descriptor_digest` from the
offer's `providerHint` and passes them back as supposedly independent
observations. `authorise` compares the hint and signed statement to those copied
values but never calls `ProviderHint::verify`, so it never establishes that the
operator exists in the fetched profile or that the descriptor digest is the
profile's; it also omits the hint's `profileVersion == 1` check. The honest
`build_offer` producer does call `verify`, but wallet
authorization cannot rely on a hostile producer having used that constructor.

**Concrete failure:** a raw offer and a valid backend-signed statement both name
an undeclared provider/digest. `observation_for_enrolment_offer` mirrors those
values and `authorise` accepts them. The public signing oracle makes this input
constructible without control of the application backend. This does not by
itself substitute the fetched profile—the separate signed profile-digest checks
still hold—but it defeats CON-209's provider binding and creates a policy bypass
as soon as the selected provider affects transport or privacy handling.

`authorise` should verify the hint directly against the authenticated profile
and offer digest. If the wallet really performs provider selection, its selected
descriptor should be passed as an observation from that independent process.

## Checks that held

- I found no bypass in the new `web:<origin>` grammar. Profile recognition uses
  a closed three-member object, exact byte equality with the canonical
  `applicationId` origin, exact `id == "web:" + origin`, and duplicate-ID
  rejection (`crates/selfsame-app-identity/src/profile.rs:632-650,769-793`).
  Statement recognition independently requires the exact return origin
  (`crates/selfsame-app-identity/src/enrollment.rs:437-501`).
- The core verifier exactly binds request/ceremony IDs, application/profile
  fields, account scope, device-key digest, permissions, provider values, offer
  digest, and both timestamps (`crates/selfsame-app-identity/src/enrollment.rs:551-608`).
  I found no issued-at/expires-at or offer-digest mismatch in
  `EnrolmentAllocator`; the defects above are provenance, lifecycle, and state
  machine failures around those comparisons.

## Test assessment

`cargo test -p selfsame-app-identity --tests` and
`cargo test -p selfsame-web-device` passed. The four focused Tauri tests compile,
but all are `#[ignore]` and therefore execute zero tests in an ordinary run. In
particular, `src-tauri/tests/full_enrolment_flow.rs:152-180` does not call the
new commands, issue/build/deliver a grant bundle, or perform confirmation; it
constructs an issuer identity and then calls `record_pairing_trust` directly.
That is why it cannot detect the UI dispatch, cross-screen confirmation,
pending-state, key-retention, or commit-order failures above.

## Remediation status (2026-08-22)

Seven of the nine findings are closed in code with tests; two are recorded
here as the remaining Tier-1 design work, deferred with the rest of the
release-gate hardening to the pre-release security review.

| # | Finding | Status | Where |
|---|---------|--------|-------|
| 2 | Manual observation admits Apple/native binding | **Fixed** | `observation_for_enrolment_offer` requires a `web:` CON-214 binding |
| 9 | Provider observation copied from the hint | **Fixed** | observation runs `ProviderHint::verify` against the fetched profile |
| 3 | CON-219 code consumed by the SPEC-001 path | **Fixed** | `read_link_code` opens the slot once and dispatches by grammar to `enrol_from_opened`; the wallet frontend drives `cbcl_enrol_prepare/confirm` |
| 6 | Trust committed before delivery; error ignored | **Fixed** | `confirm_issuance` returns trust inputs; each caller commits via `commit_pairing_trust` (checked) at its real completion — the enrolment path only after the bundle PUT |
| 8 | One ceremony's grant delivered into another | **Fixed** | `PendingEnrolment` keyed by ceremony id; replacement of a live context refused; `open_bundle` runs `bundle_matches_offer` |
| 7 | Rendezvous unbounded, quadratic-cost | **Fixed** | amortised-O(1) expiry queue, `MAX_SLOTS` bound, pre-buffer `DefaultBodyLimit` (`did-crdt`). Residual: edge CORS/rate-limit |
| 1 | Hub is an unauthenticated signing oracle | **Partially hardened** | drive-by-browser vector closed (json media type required, no wildcard CORS on the sign route). **Open:** server-side ceremony-state authentication of the statement — a server-side caller can still POST a well-formed statement |
| 4 | CON-221 has no application-side fingerprint value or wire step | **Open (design)** | see below |
| 5 | Allocator discards the device key and the grant | **Open (feature)** | see below |

### Open — #4: CON-221 needs a pre-grant fingerprint channel

The wallet side of the comparison is now wired (finding 3): on a `required`
first enrolment it derives the issuer fingerprint in `cbcl_enrol_prepare` and
shows the `fingerprint-compare` screen with the two honest answers. But the
application (the chat browser) still has no value to display: it learns the
issuer only inside the bundle, which arrives after confirmation. So an honest
first enrolment **fails closed** — the person, comparing against a blank other
screen, can only answer "they're different" and terminate. That is the safe
state (never TOFU), but it is not yet a completable honest ceremony.

Closing it needs an authenticated pre-confirmation wallet→application message
from which the browser can derive/display the same issuer fingerprint before
the person answers — e.g. the wallet writes a signed fingerprint announcement
to a distinct rendezvous slot that the allocator reads and renders while the
"waiting" screen is up. This is a CON-221 wire addition (spec amendment + both
sides + adversarial review), not a local code change. The UI must keep driving
the returned `applicability` (it now does) rather than treating the prompt as
generic approval.

### Open — #5: the browser must retain the device key and install the grant

The allocator draws a fresh `device_seed` inline, uses it only to derive the
offer's public key, and retains neither the seed nor a signer; on reply the
shell parses the bundle and prints "Linked" without installing the compact
grant or closure into any application credential store. So even a fully
successful ceremony leaves the "connected application" unable to make the
CON-207 possession proof for the grant's `cnf` key, and a reload loses it.

Closing it needs the browser application to generate and retain the device key
in device-owned persistent storage (preferably a non-exportable WebCrypto
signing handle in IndexedDB) and to install the validated matching
grant/closure atomically with it before reporting success. This is an
application-credential-store feature in `cbcl-bus`'s web client, coupled to the
key generation, not a wallet change.
