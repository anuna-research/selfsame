# SPEC-006 Red Gate

Date: 2026-08-17

## Dependency baseline

Command:

`cargo test -p selfsame-pairing --test dependency -- --nocapture`

Observed behavioral failure:

```text
test_701_compiled_dependency_matches_the_reviewed_baseline ... FAILED
left: "red-gate-stub"
right: "197d4cb3d1560ab5328df28fc984269799c510f9"
test result: FAILED. 0 passed; 1 failed
```

The test compiled and exercised the intentionally incorrect baseline value.
The next implementation step replaces only that stub with the reviewed dependency evidence.

## Adapter behavior

Command:

`cargo test -p selfsame-pairing --test adapter -- --nocapture`

Observed behavioral failures after successful compilation:

```text
test_703_and_705_approved_ceremony_reaches_selfsame_acceptance ... FAILED
the exact carrier establishes a session: Unavailable
test_710_decline_releases_no_payload_and_calls_no_selfsame_verifier ... FAILED
the exact carrier establishes a session: Unavailable
test result: FAILED. 0 passed; 2 failed
```

Both tests reached the deliberately unavailable adapter behavior. The next step
implements the real endpoint ceremony without weakening either assertion.

### HTTP shell Red Gate

`cargo test -p selfsame-pairing --test demo_http test_704_application_page_bootstraps_a_bound_session -- --exact`
compiled the Axum stub and failed behaviorally on 2026-08-17: TEST-704 expected
HTTP 200 but received the deliberate HTTP 501 placeholder. No compilation error
was counted as Red Gate evidence.

### Browser Red Gate

`node --test tests/cbcl-pairing-demo.mjs` launched Chromium and completed the
approved and declined browser journey, then failed behaviorally because the
non-loopback subprocess assertion observed stderr before the pipe closed. The
test therefore detected a real lifecycle-observation defect; the server itself
did exit with status 2. The test was repaired to collect stderr concurrently.

### Consent mutation gate

The adapter was deliberately changed so `decline()` called `approve()`.
`TEST-710` failed because the outcome was no longer `Declined`; this killed the
mutation before it could release a payload or call the Selfsame verifier. The
production decline reducer path was then restored.

### Selfsame-verifier mutation gate

The adapter was deliberately changed to construct `Acceptance` after only
closed-language grant recognition, bypassing signature, issuer, binding,
freshness, and proof checks. After an initial type-annotation compile error was
fixed and excluded from the evidence, `TEST-706` failed behaviorally because a
mutated signature was accepted. The authoritative verifier call was restored.

The same parse-only mutation was repeated after the acceptance boundary began
consuming private `ApprovedCredential` values. `TEST-706` failed behaviorally,
then passed after the direct thirteen-step verifier call was restored.
