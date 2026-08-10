//! The durable consumed-`requestId` ledger — `CON-214` step 5.
//!
//! `enrollment::RequestLedger` is the pure type and calls itself *"the sole
//! permitted mutation once syntactically valid evidence reaches step 5"*. It is
//! in-memory, which is correct for a contract that must not depend on storage —
//! and useless on its own, because a replay that survives an app restart is
//! exactly the one worth defending against. This is where it lives across
//! restarts.
//!
//! # Why the ledger is bounded without a policy
//!
//! A naive consumed-ID set grows forever, and a set that grows forever
//! eventually gets pruned by whoever is holding the pager. It needs no policy
//! here, because `CON-219` already bounds an offer's life: `expiresAt` is at
//! most 120 seconds after `issuedAt`.
//!
//! So a consumed `requestId` need only be retained **until the offer it
//! belonged to expires**. After that instant a replay of the same offer is
//! refused by the expiry check regardless, so remembering it adds nothing. The
//! ledger prunes on every use and its steady-state size is the number of offers
//! a person can start in two minutes.
//!
//! # Ordering
//!
//! Consumption happens **before any key is touched**. A ledger updated after
//! signing is a ledger that has already let the second signature happen, and
//! the whole point of step 5 is that the mutation precedes the authority it
//! guards.

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::store::{self, StoreError};

/// The store entry holding the ledger.
pub const LEDGER_ENTRY: &str = "enrollment-ledger-v1";

/// A defensive ceiling on retained entries.
///
/// Expiry pruning is what actually bounds this, and at 120-second offers the
/// steady state is small. The cap exists for the case where pruning is wrong —
/// a clock that jumps backwards, say — so that a defect in the bound is a
/// refusal rather than an entry that grows without limit.
const MAX_ENTRIES: usize = 256;

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// This `requestId` has already been consumed. `CON-214`'s `EnrollmentReplay`.
    #[error("this request has already been used")]
    Replay,
    /// The ledger is full and nothing could be pruned.
    #[error("too many ceremonies in flight")]
    LedgerFull,
    #[error(transparent)]
    Store(#[from] StoreError),
}

// SIMPLIFY: one process-wide mutex over a read-modify-write of a single store
// entry. The ceiling is cross-process concurrency: two instances of this app
// running against one keychain could interleave and both consume the same id.
// A Tauri application is single-instance, so the ceiling is not reachable
// today. The upgrade path is a store primitive with compare-and-swap, which
// `tauri-plugin-selfsame-store` does not currently expose — NFR-002.
static LOCK: Mutex<()> = Mutex::new(());

/// Consume `request_id`, or refuse because it has been consumed already.
///
/// `expires_at` is the offer's own expiry, and is what lets the entry be
/// forgotten later. `now` is the wallet's clock, passed rather than read so
/// that this function is testable and so the same instant governs the pruning
/// and the check.
pub fn consume(request_id: &str, expires_at: i64, now: i64) -> Result<(), ReplayError> {
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut entries = load()?;
    record(&mut entries, request_id, expires_at, now)?;
    save(&entries)?;
    Ok(())
}

/// The decision, with no I/O in it.
///
/// Separated from [`consume`] because it is the whole of what this module
/// decides, and because a ledger tested through a keyring is a ledger tested
/// against whatever credential store the machine happens to have. On a CI
/// runner with no Secret Service the backing store answers every read with
/// nothing, so a test asserting "the second attempt is a replay" fails for a
/// reason that has nothing to do with replay.
///
/// `entries` is mutated only on success: a refused attempt leaves the ledger
/// exactly as it was, so a caller cannot half-consume an id.
fn record(
    entries: &mut BTreeMap<String, i64>,
    request_id: &str,
    expires_at: i64,
    now: i64,
) -> Result<(), ReplayError> {
    // Prune first, so a full ledger of expired entries does not refuse a
    // legitimate ceremony.
    entries.retain(|_, &mut expiry| expiry > now);

    if entries.contains_key(request_id) {
        return Err(ReplayError::Replay);
    }
    if entries.len() >= MAX_ENTRIES {
        return Err(ReplayError::LedgerFull);
    }

    entries.insert(request_id.to_owned(), expires_at);
    Ok(())
}

/// Whether `entries` already holds a live record for `request_id`.
fn holds(entries: &BTreeMap<String, i64>, request_id: &str, now: i64) -> bool {
    entries.get(request_id).is_some_and(|&expiry| expiry > now)
}

/// Whether an id is already consumed, without consuming it.
///
/// For the review path, which must not mutate: a person looking at a consent
/// screen has not decided anything, and a review that burned the id would make
/// the offer unusable by the very act of showing it.
pub fn is_consumed(request_id: &str, now: i64) -> Result<bool, ReplayError> {
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let entries = load()?;
    Ok(holds(&entries, request_id, now))
}

fn load() -> Result<BTreeMap<String, i64>, ReplayError> {
    match store::get(LEDGER_ENTRY)? {
        // A ledger that will not parse is treated as empty rather than as a
        // hard failure. The alternative is bricking issuance on a corrupt
        // entry, and the cost of the choice is bounded: the ids it forgot
        // belong to offers that expire within two minutes.
        Some(json) => Ok(serde_json::from_str(&json).unwrap_or_default()),
        None => Ok(BTreeMap::new()),
    }
}

fn save(entries: &BTreeMap<String, i64>) -> Result<(), ReplayError> {
    let json = serde_json::to_string(entries).map_err(|_| ReplayError::LedgerFull)?;
    store::set(LEDGER_ENTRY, &json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_785_412_800;

    /// A ledger with nothing in it. Owned by the test, so nothing here depends
    /// on the machine having a working credential store — which is what broke
    /// these tests on a CI runner with no Secret Service, where every read
    /// answered "nothing" and a replay looked like a first use.
    fn ledger() -> BTreeMap<String, i64> {
        BTreeMap::new()
    }

    #[test]
    fn a_request_id_is_consumable_once() {
        let mut l = ledger();
        assert!(record(&mut l, "req-a", NOW + 120, NOW).is_ok());
        assert!(matches!(record(&mut l, "req-a", NOW + 120, NOW), Err(ReplayError::Replay)));
    }

    /// The property the whole module exists for: a second issuance from the
    /// same still-valid offer must not produce a second credential.
    #[test]
    fn a_still_valid_offer_cannot_be_replayed() {
        let mut l = ledger();
        record(&mut l, "req-b", NOW + 120, NOW).unwrap();
        // One second later the offer is still perfectly valid, which is exactly
        // the window a replay would use.
        assert!(matches!(record(&mut l, "req-b", NOW + 120, NOW + 1), Err(ReplayError::Replay)));
    }

    /// A refusal leaves the ledger untouched, so nothing is half-consumed.
    #[test]
    fn a_refused_attempt_does_not_change_the_ledger() {
        let mut l = ledger();
        record(&mut l, "req-x", NOW + 120, NOW).unwrap();
        let before = l.clone();
        let _ = record(&mut l, "req-x", NOW + 120, NOW);
        assert_eq!(l, before);
    }

    /// Once the offer has expired the entry is forgotten, because expiry then
    /// does the refusing and remembering adds nothing.
    #[test]
    fn an_entry_is_forgotten_once_its_offer_expires() {
        let mut l = ledger();
        record(&mut l, "req-c", NOW + 120, NOW).unwrap();
        assert!(holds(&l, "req-c", NOW + 119));
        assert!(!holds(&l, "req-c", NOW + 121));
        // And the id becomes reusable — harmlessly, since any offer bearing it
        // is now refused for expiry before the ledger is ever consulted.
        assert!(record(&mut l, "req-c", NOW + 240, NOW + 121).is_ok());
    }

    #[test]
    fn asking_does_not_consume() {
        let mut l = ledger();
        assert!(!holds(&l, "req-d", NOW));
        assert!(!holds(&l, "req-d", NOW));
        assert!(record(&mut l, "req-d", NOW + 120, NOW).is_ok());
    }

    #[test]
    fn expired_entries_do_not_fill_the_ledger() {
        let mut l = ledger();
        for i in 0..MAX_ENTRIES {
            record(&mut l, &format!("old-{i}"), NOW + 120, NOW).unwrap();
        }
        // Full at `NOW`, and a fresh ceremony is refused rather than silently
        // evicting somebody else's entry.
        assert!(matches!(record(&mut l, "overflow", NOW + 120, NOW), Err(ReplayError::LedgerFull)));
        // Two minutes later every one of them has expired and the ledger is
        // usable again without anyone pruning it by hand.
        assert!(record(&mut l, "later", NOW + 240, NOW + 121).is_ok());
    }

    /// Pruning happens before the cap is checked, so a ledger full of expired
    /// entries does not refuse a legitimate ceremony.
    #[test]
    fn pruning_precedes_the_cap() {
        let mut l = ledger();
        for i in 0..MAX_ENTRIES {
            record(&mut l, &format!("stale-{i}"), NOW + 10, NOW).unwrap();
        }
        assert_eq!(l.len(), MAX_ENTRIES);
        assert!(record(&mut l, "fresh", NOW + 130, NOW + 11).is_ok());
        assert_eq!(l.len(), 1, "every expired entry is dropped, not just enough of them");
    }
}
