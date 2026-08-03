//! Bounded parallel capability probes — `CON-208` steps 4 and 5, `NFR-207`.
//!
//! > Probes both pairing and mailbox capabilities for all descriptors in the
//! > lowest-priority group **concurrently** with a per-probe deadline of at most
//! > 1500 ms.
//!
//! Both adverbs are obligations. `NFR-207` states the reason for the first:
//! "Health probes SHALL be bounded and parallel. A slow high-priority provider
//! SHALL NOT serially block all fallbacks." Probing a group in sequence turns
//! one stalled provider into the group's latency, and with two groups that is
//! two stalls before the person sees anything.
//!
//! # Why both services, always
//!
//! `CON-213` step 5 requires *both* capability objects. A provider may run only
//! one of the two, and one healthy service is not a usable descriptor — so the
//! two probes are issued together and their outcomes reported together. An
//! implementation that short-circuited on the first failure would still be
//! correct, but it would lose the diagnostic `OBS-207` wants: a descriptor
//! failing on pairing alone is a different operational story from one failing on
//! both.
//!
//! # What *is* decided here, and what is not
//!
//! `CON-401` and `CON-301` do not describe a "plausible success" — each fixes an
//! exact JSON object, an exact media type, `Cache-Control: no-store`, and a
//! 2,048-byte ceiling, and says in as many words that anything else "makes the
//! descriptor ineligible". So the response check belongs here, at the only place
//! that ever sees the response. A probe that reported `true` for a `204`, or for
//! `text/plain` carrying arbitrary bytes, would let a broken or hostile provider
//! be selected and suppress the fallback that exists for exactly that case —
//! the ceremony would then fail later, further from the cause.
//!
//! What stays in [`selfsame_app_identity::selection`] is the *eligibility* rule:
//! which descriptors are in the lowest-priority group, how the two flags
//! combine, and what happens when a group is exhausted. A probe result remains a
//! hint and never a trust anchor — `CON-208` says so — and answering "is this a
//! conforming capability object?" does not change that.

use std::time::{Duration, Instant};

use selfsame_app_identity::profile::RendezvousDescriptor;
use selfsame_app_identity::selection::{ProbeOutcome, MAX_PROBE_MILLISECONDS};

use crate::{bounded_body, carried_cookies, client, has_content_encoding, media_type};

/// The per-probe deadline `CON-208` step 4 caps.
pub const PROBE_DEADLINE: Duration = Duration::from_millis(MAX_PROBE_MILLISECONDS as u64);

/// The PROTO-003 `CON-401` capability endpoint: `pairingUrl || "/pair/v1/healthz"`.
const PAIRING_CAPABILITY_PATH: &str = "/pair/v1/healthz";

/// The PROTO-002 `CON-301` capability endpoint: `base_url || "/healthz"`.
const MAILBOX_CAPABILITY_PATH: &str = "/healthz";

/// `CON-401` and `CON-301` both cap a capability body at 2,048 octets.
const MAX_CAPABILITY_OCTETS: usize = 2_048;

/// The exact eight members and values `CON-401` fixes for a pairing capability.
const PAIRING_CAPABILITY: &[(&str, Expected)] = &[
    ("protocol", Expected::Text("selfsame-pairing-v1")),
    ("status", Expected::Text("ok")),
    ("nameplateDigits", Expected::Int(6)),
    ("sessionTtlSeconds", Expected::Int(600)),
    ("frameBytes", Expected::Int(32)),
    ("claimSemantics", Expected::Text("single-responder")),
    ("relaySemantics", Expected::Text("opaque-four-frame")),
    ("providerPakeRole", Expected::Text("none")),
];

/// The exact seven members and values `CON-301` fixes for a mailbox capability.
const MAILBOX_CAPABILITY: &[(&str, Expected)] = &[
    ("protocol", Expected::Text("selfsame-rendezvous-v1")),
    ("status", Expected::Text("ok")),
    ("maxRecordBytes", Expected::Int(69_632)),
    ("slotTtlSeconds", Expected::Int(600)),
    ("writeSemantics", Expected::Text("immutable-idempotent")),
    ("readSemantics", Expected::Text("repeatable-until-expiry")),
    ("cors", Expected::Bool(true)),
];

/// One fixed member value. Both contracts are `const`-valued throughout: there
/// is "no runtime feature or algorithm negotiation" to express.
#[derive(Clone, Copy)]
enum Expected {
    Text(&'static str),
    Int(i64),
    Bool(bool),
}

/// Probe every descriptor in a group concurrently (`CON-208` step 4).
///
/// Returns one outcome per descriptor, in the order given, so the result can be
/// handed straight to [`selfsame_app_identity::selection::choose`].
pub async fn probe_group(descriptors: &[&RendezvousDescriptor]) -> Vec<ProbeOutcome> {
    let futures = descriptors.iter().map(|d| probe_one(d));
    // `join_all` is the parallelism NFR-207 requires. A `for` loop here would
    // satisfy every other clause of CON-208 and quietly violate this one.
    futures_join_all(futures).await
}

/// Probe one descriptor's two services concurrently.
pub async fn probe_one(descriptor: &RendezvousDescriptor) -> ProbeOutcome {
    let started = Instant::now();
    let pairing = format!("{}{PAIRING_CAPABILITY_PATH}", descriptor.pairing_url);
    let mailbox = format!("{}{MAILBOX_CAPABILITY_PATH}", descriptor.url);

    let (pairing_ok, mailbox_ok) = tokio::join!(
        capability_ok(&pairing, PAIRING_CAPABILITY),
        capability_ok(&mailbox, MAILBOX_CAPABILITY)
    );

    // The elapsed time is the slower of the two, because they ran together.
    let elapsed = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
    ProbeOutcome { pairing_ok, mailbox_ok, elapsed_milliseconds: elapsed }
}

/// One bounded capability request, judged against its contract's fixed object.
///
/// `CON-213`'s response policy applies here as everywhere: no redirect, no
/// cookies, no content encoding, and no server-nominated endpoint. A probe that
/// accepted a redirect would let a provider point the ceremony elsewhere before
/// the authenticated hint has had anything to say about it.
///
/// On top of that, `CON-401` and `CON-301` each fix the whole response:
/// **exactly** `200`, `application/json`, `Cache-Control: no-store`, at most
/// 2,048 octets, and a JSON object with exactly the declared members and values.
/// Both spell out that anything else — "unknown or missing members, duplicate
/// names, redirects, content encoding, a media type other than
/// `application/json`, a body over 2,048 bytes, or a non-`200` response" — makes
/// the descriptor ineligible, so every one of those is a `false` here.
///
/// # The deadline covers everything the probe does
///
/// `CON-208` step 4 caps *the probe*, not the request inside it. Handing
/// [`PROBE_DEADLINE`] to `reqwest` bounds only what happens after the client
/// exists, and building one is not free: it loads the platform root store, which
/// is synchronous CPU work. Under load that work serialises — a measured 3,565
/// ms elapsed against a 1,500 ms deadline, with the connects never overlapping
/// — so the advertised bound held over a part of the probe while the whole took
/// twice as long, and `NFR-207`'s fallbacks waited for it.
///
/// So the deadline is started here, before the client exists, and the
/// construction is moved to the blocking pool. One client per request is kept:
/// [`crate::client`] builds a fresh one so no connection pool is shared between
/// providers, which is the same unlinkability argument its documentation makes
/// about cookie jars, and that is not what was costing the time.
async fn capability_ok(url: &str, expected: &[(&str, Expected)]) -> bool {
    // A probe that could not be completed inside the contract's bound is not a
    // healthy descriptor, so the elapsed deadline is `false` like every other
    // way of failing to see a conforming capability object.
    tokio::time::timeout(PROBE_DEADLINE, capability_response_ok(url, expected))
        .await
        .unwrap_or(false)
}

async fn capability_response_ok(url: &str, expected: &[(&str, Expected)]) -> bool {
    // `spawn_blocking`, so the root-store load happens on the blocking pool
    // rather than on the thread polling every other probe in the group. The
    // timeout above can then elapse while a build is still queued, instead of
    // waiting for CPU work no timer can interrupt.
    let Ok(Ok(http)) = tokio::task::spawn_blocking(|| client(PROBE_DEADLINE)).await else {
        return false;
    };
    let Ok(response) = http
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
    else {
        return false;
    };

    // `200` exactly. `is_success()` would admit `204 No Content`, whose empty
    // body is not the object either contract requires.
    if response.status() != reqwest::StatusCode::OK
        || has_content_encoding(&response)
        || carried_cookies(&response)
        || media_type(&response) != "application/json"
        || !is_no_store(&response)
    {
        return false;
    }

    let Ok(body) = bounded_body(response, MAX_CAPABILITY_OCTETS).await else { return false };
    capability_matches(&body, expected)
}

/// `Cache-Control: no-store`, which both contracts require on every response.
fn is_no_store(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|d| d.trim().eq_ignore_ascii_case("no-store")))
}

/// Whether the octets are exactly the capability object the contract declares.
///
/// Uses the core's recogniser rather than a permissive parser, so the
/// duplicate-member and canonical-number prohibitions `CON-301` names are the
/// same ones every other Selfsame document is read under.
fn capability_matches(octets: &[u8], expected: &[(&str, Expected)]) -> bool {
    use selfsame_app_identity::json::{self, Json, Limits};

    let limits = Limits { max_bytes: MAX_CAPABILITY_OCTETS, max_depth: 4 };
    let Ok(value) = json::recognise(octets, limits) else { return false };
    let Some(members) = value.as_object() else { return false };

    // "The JSON object has exactly those eight members and values." Exactly:
    // a missing member and an extra one are both refusals, so the count is
    // checked before the values.
    if members.len() != expected.len() {
        return false;
    }
    expected.iter().all(|(name, want)| match (value.get(name), want) {
        (Some(Json::String(got)), Expected::Text(w)) => got == w,
        (Some(Json::Integer(got)), Expected::Int(w)) => got == w,
        (Some(Json::Bool(got)), Expected::Bool(w)) => got == w,
        _ => false,
    })
}

/// Poll a fixed set of futures to completion concurrently.
///
/// Public because [`crate::state`] needs the same thing for `CON-210`'s
/// parallel fan-out, and two copies of a concurrency helper is two places for
/// one of them to become sequential without anyone noticing.
pub async fn join_all_public<F, T>(futures: Vec<F>) -> Vec<T>
where
    F: core::future::Future<Output = T>,
{
    futures_join_set(futures).await
}

/// `futures::future::join_all` without the dependency.
///
/// Three lines against a crate, which is rung 5 of the Simplicity Ladder rather
/// than rung 4: the only thing needed is "poll these together", and `tokio` is
/// already present.
async fn futures_join_all<F, T>(futures: impl IntoIterator<Item = F>) -> Vec<T>
where
    F: core::future::Future<Output = T>,
{
    let handles: Vec<_> = futures.into_iter().collect();
    let mut out = Vec::with_capacity(handles.len());
    // `FuturesUnordered` would be the general answer; with a group bounded at 64
    // descriptors, joining a fixed set is enough and needs nothing new.
    for result in futures_join_set(handles).await {
        out.push(result);
    }
    out
}

async fn futures_join_set<F, T>(futures: Vec<F>) -> Vec<T>
where
    F: core::future::Future<Output = T>,
{
    // Poll every future to completion concurrently on this task. The futures
    // are I/O-bound and already carry their own deadline, so no spawn is needed
    // and none is used — spawning would require `Send` bounds this crate has no
    // reason to impose on its callers.
    let mut pinned: Vec<_> = futures.into_iter().map(Box::pin).collect();
    let mut results: Vec<Option<T>> = (0..pinned.len()).map(|_| None).collect();
    let mut remaining = pinned.len();
    core::future::poll_fn(|cx| {
        for (i, fut) in pinned.iter_mut().enumerate() {
            if results[i].is_none() {
                if let core::task::Poll::Ready(value) = fut.as_mut().poll(cx) {
                    results[i] = Some(value);
                    remaining -= 1;
                }
            }
        }
        if remaining == 0 {
            core::task::Poll::Ready(())
        } else {
            core::task::Poll::Pending
        }
    })
    .await;
    results.into_iter().map(|r| r.expect("every future completed")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(id: &str, host: &str) -> RendezvousDescriptor {
        RendezvousDescriptor {
            id: id.into(),
            url: format!("https://{host}"),
            protocol: "selfsame-rendezvous-v1".into(),
            pairing_url: format!("https://pairing-{host}"),
            pairing_protocol: "selfsame-pairing-v1".into(),
            pairing_route: "03".into(),
            priority: 10,
            weight: 50,
            valid_until: 2_000_000_000,
            digest: [0u8; 32],
        }
    }

    #[test]
    fn the_probe_deadline_is_the_one_con_208_caps() {
        assert_eq!(PROBE_DEADLINE, Duration::from_millis(1_500));
        assert_eq!(PROBE_DEADLINE.as_millis() as u32, MAX_PROBE_MILLISECONDS);
    }

    #[test]
    fn the_capability_paths_are_the_ones_the_protocols_publish() {
        // CON-401: `pairingUrl || "/pair/v1/healthz"`.
        // CON-301: `base_url || "/healthz"`.
        // Any other spelling returns 404 from every conforming provider, which
        // reads as "no healthy descriptor" and exhausts the whole roster.
        assert_eq!(PAIRING_CAPABILITY_PATH, "/pair/v1/healthz");
        assert_eq!(MAILBOX_CAPABILITY_PATH, "/healthz");
    }

    const GOOD_PAIRING: &[u8] = br#"{"protocol":"selfsame-pairing-v1","status":"ok",
        "nameplateDigits":6,"sessionTtlSeconds":600,"frameBytes":32,
        "claimSemantics":"single-responder","relaySemantics":"opaque-four-frame",
        "providerPakeRole":"none"}"#;

    const GOOD_MAILBOX: &[u8] = br#"{"protocol":"selfsame-rendezvous-v1","status":"ok",
        "maxRecordBytes":69632,"slotTtlSeconds":600,
        "writeSemantics":"immutable-idempotent","readSemantics":"repeatable-until-expiry",
        "cors":true}"#;

    #[test]
    fn the_declared_capability_objects_are_accepted() {
        assert!(capability_matches(GOOD_PAIRING, PAIRING_CAPABILITY));
        assert!(capability_matches(GOOD_MAILBOX, MAILBOX_CAPABILITY));
    }

    #[test]
    fn an_empty_or_arbitrary_body_is_not_a_capability_object() {
        // The 204 case, and the text/plain case, once they reach the body: both
        // used to reach an unconditional `true`.
        for body in [&b""[..], b"ok", b"null", b"[]", b"{}"] {
            assert!(!capability_matches(body, PAIRING_CAPABILITY), "{body:?} is not a capability");
            assert!(!capability_matches(body, MAILBOX_CAPABILITY), "{body:?} is not a capability");
        }
    }

    #[test]
    fn a_missing_extra_or_altered_member_makes_the_descriptor_ineligible() {
        // Missing one member.
        assert!(!capability_matches(
            br#"{"protocol":"selfsame-rendezvous-v1","status":"ok","maxRecordBytes":69632,
                 "slotTtlSeconds":600,"writeSemantics":"immutable-idempotent",
                 "readSemantics":"repeatable-until-expiry"}"#,
            MAILBOX_CAPABILITY
        ));
        // One member too many.
        assert!(!capability_matches(
            br#"{"protocol":"selfsame-rendezvous-v1","status":"ok","maxRecordBytes":69632,
                 "slotTtlSeconds":600,"writeSemantics":"immutable-idempotent",
                 "readSemantics":"repeatable-until-expiry","cors":true,"extra":1}"#,
            MAILBOX_CAPABILITY
        ));
        // A larger advertised record limit: "a version-1 client never sends or
        // accepts more".
        assert!(!capability_matches(
            br#"{"protocol":"selfsame-rendezvous-v1","status":"ok","maxRecordBytes":131072,
                 "slotTtlSeconds":600,"writeSemantics":"immutable-idempotent",
                 "readSemantics":"repeatable-until-expiry","cors":true}"#,
            MAILBOX_CAPABILITY
        ));
        // An unknown protocol token: "clients reject every unknown token".
        assert!(!capability_matches(
            br#"{"protocol":"selfsame-rendezvous-v2","status":"ok","maxRecordBytes":69632,
                 "slotTtlSeconds":600,"writeSemantics":"immutable-idempotent",
                 "readSemantics":"repeatable-until-expiry","cors":true}"#,
            MAILBOX_CAPABILITY
        ));
        // A draining provider: CON-301 says `/healthz` returns 503 with an
        // empty body, but a `"status":"draining"` object is refused too.
        assert!(!capability_matches(
            br#"{"protocol":"selfsame-rendezvous-v1","status":"draining","maxRecordBytes":69632,
                 "slotTtlSeconds":600,"writeSemantics":"immutable-idempotent",
                 "readSemantics":"repeatable-until-expiry","cors":true}"#,
            MAILBOX_CAPABILITY
        ));
    }

    #[test]
    fn a_string_where_an_integer_belongs_is_refused() {
        // `"6"` is not `6`. A permissive comparison would coerce and accept a
        // provider advertising something it does not implement.
        assert!(!capability_matches(
            br#"{"protocol":"selfsame-pairing-v1","status":"ok","nameplateDigits":"6",
                 "sessionTtlSeconds":600,"frameBytes":32,"claimSemantics":"single-responder",
                 "relaySemantics":"opaque-four-frame","providerPakeRole":"none"}"#,
            PAIRING_CAPABILITY
        ));
    }

    #[test]
    fn a_duplicate_member_name_is_refused() {
        // CON-301 names this explicitly. The core's recogniser is what enforces
        // it, which is why the body goes through `json::recognise` rather than a
        // permissive parser that would keep one of the two.
        assert!(!capability_matches(
            br#"{"protocol":"selfsame-pairing-v1","protocol":"selfsame-pairing-v1",
                 "status":"ok","nameplateDigits":6,"sessionTtlSeconds":600,"frameBytes":32,
                 "claimSemantics":"single-responder","relaySemantics":"opaque-four-frame",
                 "providerPakeRole":"none"}"#,
            PAIRING_CAPABILITY
        ));
    }

    #[test]
    fn a_body_over_the_bound_is_refused_by_the_recogniser_too() {
        // `bounded_body` refuses it in transit; this is the second line, for a
        // body that arrives inside the transport bound but pads past the
        // contract's own 2,048.
        let mut oversized = GOOD_MAILBOX.to_vec();
        oversized.splice(1..1, format!(r#""pad":"{}","#, "x".repeat(2_100)).bytes());
        assert!(!capability_matches(&oversized, MAILBOX_CAPABILITY));
    }

    #[test]
    fn the_two_capabilities_are_not_interchangeable() {
        assert!(!capability_matches(GOOD_PAIRING, MAILBOX_CAPABILITY));
        assert!(!capability_matches(GOOD_MAILBOX, PAIRING_CAPABILITY));
    }

    #[tokio::test]
    async fn a_group_is_polled_together_and_not_one_after_another() {
        // NFR-207: "Health probes SHALL be bounded and parallel. A slow
        // high-priority provider SHALL NOT serially block all fallbacks."
        //
        // A barrier decides it, and decides it exactly. Each future below waits
        // on a barrier that opens only once all four have reached it, so the
        // set completes if and only if all four are in flight at the same
        // moment. Under `futures_join_all` it returns immediately; under a
        // `for` loop — the mistake `probe_group`'s comment warns about — the
        // first future waits for three that have not been started, forever.
        // There is no threshold to tune and nothing to measure.
        //
        // # Why this replaced a wall-clock test
        //
        // This assertion used to time four unreachable probes and require the
        // group to finish inside three deadlines. It measured the machine
        // rather than the code, and it failed in CI for two compounding reasons
        // that both look identical to "probed in sequence":
        //
        // 1. Four descriptors carry *eight* hosts, so the original `.invalid`
        //    fixture timed eight concurrent DNS queries. In isolation that took
        //    0.02 s; under load, 7.98 s — above the 6 s a fully serial probe
        //    would cost, which no reading of the result can attribute to
        //    sequencing.
        // 2. Moving to a loopback listener removed DNS and it still failed, at
        //    9.76 s. The numbers say why: each probe reported 3565 ms against a
        //    1500 ms deadline. Every capability request builds its own
        //    `reqwest::Client`, and that construction is CPU work sitting
        //    *outside* the per-probe timeout — so when `cargo test --workspace`
        //    runs the crates' test binaries concurrently, the client builds
        //    serialise and the connects never overlap. The join was parallel
        //    the whole time.
        //
        // The per-request client is still not the thing to change:
        // [`crate::client`] builds one per call so that no connection pool is
        // shared between providers, which is the same unlinkability argument
        // its own documentation makes about cookie jars. What *was* wrong is
        // where the construction sat — [`capability_ok`] now starts the
        // deadline before it and runs it on the blocking pool, so the 3,565 ms
        // reading is a bound violation that would no longer happen. This test
        // still does not measure it: a barrier decides sequencing exactly, and
        // a stopwatch would go back to measuring the machine.
        use std::sync::Arc;
        let barrier = Arc::new(tokio::sync::Barrier::new(4));
        let futures: Vec<_> = (0..4)
            .map(|i| {
                let barrier = Arc::clone(&barrier);
                async move {
                    barrier.wait().await;
                    i
                }
            })
            .collect();

        let joined = tokio::time::timeout(Duration::from_secs(10), futures_join_all(futures))
            .await
            .expect("a sequential implementation cannot pass this barrier and times out here");
        assert_eq!(joined, vec![0, 1, 2, 3], "every future ran, and results keep their order");
    }

    /// A loopback listener that accepts connections and then says nothing.
    ///
    /// Returns its port and the accept task's handle. Accepted streams are
    /// retained rather than dropped, because dropping one closes the connection
    /// and lets the client fail fast — the point of this server is to make a
    /// probe cost its full deadline against something that is *reachable*, so
    /// nothing depends on name resolution or routing.
    async fn stalling_listener() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("binds");
        let port = listener.local_addr().expect("has an address").port();
        let task = tokio::spawn(async move {
            let mut held = Vec::new();
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => held.push(stream),
                    Err(_) => return,
                }
            }
        });
        (port, task)
    }

    #[tokio::test]
    async fn a_group_of_silent_servers_yields_one_ineligible_outcome_each() {
        // The bounded half of `NFR-207`, kept as an integration check now that
        // the parallel half is decided by a barrier above.
        //
        // A server that accepts and then never speaks is the case a deadline
        // exists for: no error comes back, so only the bound ends it. Loopback
        // rather than an unresolvable name, so this exercises the timeout
        // rather than the machine's resolver — and it carries no wall-clock
        // assertion, because the deadline is the contract and how long the
        // runtime takes to notice it is not.
        let (port, server) = stalling_listener().await;
        let host = format!("127.0.0.1:{port}");
        let ds: Vec<RendezvousDescriptor> = (0..4)
            .map(|i| RendezvousDescriptor {
                id: format!("p{i}"),
                url: format!("https://{host}"),
                pairing_url: format!("https://{host}"),
                ..descriptor(&format!("p{i}"), "unused.example")
            })
            .collect();
        let refs: Vec<&RendezvousDescriptor> = ds.iter().collect();

        let outcomes = probe_group(&refs).await;
        server.abort();

        assert_eq!(outcomes.len(), 4, "one outcome per descriptor, in order");
        for outcome in &outcomes {
            assert!(!outcome.pairing_ok, "a server that never answers has no capability");
            assert!(!outcome.mailbox_ok);
            assert!(!outcome.is_eligible());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_probe_ends_by_the_deadline_and_not_at_the_end_of_its_own_work() {
        // `CON-208` step 4 caps the probe at 1,500 ms. On a paused clock time
        // advances only when the runtime is idle, so this measures where the
        // deadline sits rather than how fast the machine is: a server that
        // accepts and says nothing hands the probe to the timer, and the timer
        // is the only thing that can end it.
        //
        // What this pins is that the bound governs the whole probe. The client
        // construction that used to sit outside it is now inside, so a build
        // that overran could no longer push a probe past the cap while every
        // fallback behind it waited.
        let (port, server) = stalling_listener().await;
        let host = format!("127.0.0.1:{port}");
        let d = RendezvousDescriptor {
            url: format!("https://{host}"),
            pairing_url: format!("https://{host}"),
            ..descriptor("slow", "unused.example")
        };

        let started = tokio::time::Instant::now();
        let outcome = probe_one(&d).await;
        let elapsed = started.elapsed();
        server.abort();

        assert!(!outcome.is_eligible(), "a server that never answers has no capability");
        assert!(elapsed <= PROBE_DEADLINE, "the probe ran {elapsed:?}, past its 1,500 ms cap");
    }

    #[tokio::test]
    async fn a_descriptor_whose_hosts_do_not_resolve_fails_both_halves() {
        let d = descriptor("dead", "nonexistent.invalid");
        let outcome = probe_one(&d).await;
        assert!(!outcome.pairing_ok);
        assert!(!outcome.mailbox_ok);
        assert!(!outcome.is_eligible());
    }
}
