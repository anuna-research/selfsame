# Pairing completion runbook — chat.anuna.io

State as of 2026-08-22. Everything software is built, verified, and deployed or
branch-ready. What remains are three owner actions: one Tier-1 gate decision,
one deploy, one physical install. This is the exact sequence.

## Already live (no action needed)

- `https://chat.anuna.io/selfsame/application` — ratified web-only CON-002
  profile, HTTP 200, `application/selfsame-profile+json`, SHA-256
  `6ac06f627bcf30755553cce415a168cff1498350da6464874397f12b10bc4999`.
- `https://did.anuna.io/rendezvous/:slot` + `/dids/:did/closure` — SPEC-001
  mailbox and closure, verified (201 / 200-once / 404).
- Wallet enrolment wire code-complete: `cbcl_enrol_start/prepare/confirm`
  (selfsame branch `spec/spec-004-web-manual-binding`).

## Branches to merge (all pushed, none merged; deploys ran from branches)

- selfsame `spec/spec-004-web-manual-binding` (CON-227 + wallet wire)
- cbcl-bus `feat/ratify-production-profile` (profile ratified, routes, authority fix)
- did-crdt `feat/spec-001-rendezvous-routes` (rendezvous upstream)

## The three remaining actions

### 1 — Open the hub CON-214 signing gate (Tier-1 GATE-00 decision — OWNER ONLY)

The hub enrolment signer (`cbcl-chat-enrolment-signer:sign/1`) is gated by
`cbcl-chat-path-b-gate:profile/0`, which returns `tier-1-unapproved` by design.
SPEC-053 requires **cross-stack gate evidence** to exist before this opens —
this is a reviewed-release decision, not a code flip, and deliberately so
(a rejected shortcut this session, SPEC-008 REQ-909, is the cautionary case).

To open it, as the repository owner:
- produce/record the GATE-00 cross-stack evidence the spec names;
- point the signer at the published profile
  (`cbcl-chat-selfsame-application-gate:document/0`, already open) or open the
  Path-B admission gate per its own review;
- provision the enrolment seed as a Fly secret to the path
  `selfsame_enrolment_seed_path` names, and set `selfsame_enrolment_kid` =
  `enrollment-2026-08`, `selfsame_application_id` =
  `https://chat.anuna.io/selfsame/application`.
  The seed is held at `~/.selfsame/enrolment-seed-2026-08.hex` (64 hex, mode
  600); its public half is already in the ratified profile.

### 2 — Deploy the merged branches

```
# cbcl-bus (hub: routes + ratified profile + signer, once gate opened)
cd ~/Code/cbcl-bus && fly deploy --remote-only
# did-crdt already deployed from its branch; redeploy after merge if desired
```

### 3 — Install the wallet and link (PHYSICAL — OWNER ONLY)

The APK is **already built** (2026-08-22), carrying the CON-227 web-binding
recognition and the `cbcl_enrol_*` wire:

```
src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk
```

It is unsigned. To install:
```
# sign it (or build a signed variant with your release keystore), then:
adb install -r <signed.apk>
```
Rebuild after any wallet change with:
```
cd ~/Code/selfsame
NDK_HOME=~/Library/Android/sdk/ndk/27.1.12297006 ANDROID_HOME=~/Library/Android/sdk \
  cargo tauri android build --apk --target aarch64
```

Then on the phone: open the wallet, and from chat.anuna.io start a link — the
chat app allocates a CON-219 offer (signed by the now-enabled hub), writes it
to the did.anuna.io mailbox; the wallet's `cbcl_enrol_start` fetches it,
authenticates the profile live, shows consent; on confirm the trust record is
written and the SPEC-008 origin gate then admits the anuna-1 relay. Pairing
proceeds.

## Why the refusal persists until all three are done

The pairing gate (SPEC-008 REQ-906) needs a held pairing-trust record. That
record is written only by `cbcl_enrol_confirm` after a completed enrolment
ceremony. The ceremony needs a hub-signed CON-214 offer (action 1) reachable
by an installed wallet build (action 3). Until both, every pairing attempt
correctly refuses — which is the fail-closed behaviour, not a bug.
