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
//! # What is *not* decided here
//!
//! Whether the capability body is acceptable. `CON-401` and `CON-301` define
//! those shapes and belong to PROTO-003 and PROTO-002; this module reports
//! whether a bounded request returned a plausible success, and the eligibility
//! decision stays in [`selfsame_app_identity::selection`]. A probe result is a
//! hint, never a trust anchor — `CON-208` says so, and keeping the judgement in
//! the pure core is how that stays true.

use std::time::{Duration, Instant};

use selfsame_app_identity::profile::RendezvousDescriptor;
use selfsame_app_identity::selection::{ProbeOutcome, MAX_PROBE_MILLISECONDS};

use crate::{carried_cookies, client, has_content_encoding};

/// The per-probe deadline `CON-208` step 4 caps.
pub const PROBE_DEADLINE: Duration = Duration::from_millis(MAX_PROBE_MILLISECONDS as u64);

/// The PROTO-003 capability path.
const PAIRING_CAPABILITY_PATH: &str = "/selfsame-pairing/v1/capability";

/// The PROTO-002 capability path.
const MAILBOX_CAPABILITY_PATH: &str = "/selfsame-rendezvous/v1/capability";

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

    let (pairing_ok, mailbox_ok) = tokio::join!(reachable(&pairing), reachable(&mailbox));

    // The elapsed time is the slower of the two, because they ran together.
    let elapsed = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
    ProbeOutcome { pairing_ok, mailbox_ok, elapsed_milliseconds: elapsed }
}

/// One bounded capability request.
///
/// `CON-213`'s response policy applies here as everywhere: no redirect, no
/// cookies, no content encoding, and no server-nominated endpoint. A probe that
/// accepted a redirect would let a provider point the ceremony elsewhere before
/// the authenticated hint has had anything to say about it.
async fn reachable(url: &str) -> bool {
    let Ok(http) = client(PROBE_DEADLINE) else { return false };
    let Ok(response) = http
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await
    else {
        return false;
    };
    if response.status().is_redirection()
        || !response.status().is_success()
        || has_content_encoding(&response)
        || carried_cookies(&response)
    {
        return false;
    }
    // The capability body's *shape* is PROTO-002/PROTO-003's to judge. What is
    // decided here is only that a bounded, unredirected, uncompressed,
    // cookie-free success arrived.
    true
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

    #[tokio::test]
    async fn an_unreachable_group_is_probed_in_parallel_and_not_in_sequence() {
        // NFR-207: "A slow high-priority provider SHALL NOT serially block all
        // fallbacks." Four descriptors that will not resolve each burn a
        // deadline; in sequence that is four deadlines, in parallel it is one.
        //
        // The assertion is deliberately loose — this measures wall-clock on a
        // machine under test load — but a serial implementation would take at
        // least 4× the deadline and cannot pass it.
        let ds: Vec<RendezvousDescriptor> = (0..4)
            .map(|i| descriptor(&format!("p{i}"), &format!("nonexistent-{i}.invalid")))
            .collect();
        let refs: Vec<&RendezvousDescriptor> = ds.iter().collect();

        let started = Instant::now();
        let outcomes = probe_group(&refs).await;
        let elapsed = started.elapsed();

        assert_eq!(outcomes.len(), 4);
        for outcome in &outcomes {
            assert!(!outcome.is_eligible(), "an unresolvable host is not eligible");
        }
        assert!(
            elapsed < PROBE_DEADLINE * 3,
            "probing took {elapsed:?}, which suggests the group was probed in sequence"
        );
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
