//! `PROTO-003` `CON-409` resolution — what a scanned code turns into.
//!
//! # The one thing this screen must not imply
//!
//! A resolved record is an **unauthenticated, bearer-routable hint**. `CON-409`
//! is unusually blunt about it: the signature *"proves only that whoever holds
//! `C` wrote it; it establishes neither application authority nor an intended
//! recipient"*, and a party who knows `C` can publish a coherent record for a
//! **different** application and complete the PAKE for it — the `binding_hash`
//! is internally consistent either way, so confirmation cannot detect the
//! substitution.
//!
//! So [`PairingTarget`] carries `claimed_application_id`, not `application_id`.
//! The name is the whole point: the field is a claim, the screen must say so,
//! and there is nothing this command could do to make it more than that.
//!
//! # Why the resolution is here and not in the webview
//!
//! The application's CSP is `connect-src 'self' ipc: http://ipc.localhost`, so
//! the webview cannot fetch a record or a profile at all. That constraint points
//! the right way: a resolution that ran in the page would put the record's
//! origin, the profile fetch, and the descriptor probe inside the least
//! trustworthy process in the system.
//!
//! # What it stops at
//!
//! The binding object, and no further. It claims no nameplate, sends no PAKE
//! frame, and derives no key — `CON-409` requires the wallet to display the
//! claimed identity *before* either, and a command that resolved and claimed in
//! one call would have shown the person nothing to decide on.

use serde::Serialize;

use selfsame_app_identity::pairing::BindingObject;
use selfsame_app_identity::pairing_code::{self, Code, MeetingRecord};
use selfsame_app_identity::profile::ApplicationId;
use selfsame_app_identity_net::profile as profile_net;

use crate::commands::{now, UiError};

type Result<T> = std::result::Result<T, UiError>;

/// How long the record and profile fetches may take, in total.
const RESOLVE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);

/// The largest record envelope a wallet will read.
const MAX_ENVELOPE_OCTETS: usize = 8 * 1024;

/// What the consent screen is given.
///
/// Every string here is either a claim from the record or a fact this wallet
/// derived. Nothing is a verified statement about who is asking, because at this
/// point in the ceremony no such statement exists.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingTarget {
    /// The `applicationId` the record CLAIMS. Displayed as a claim.
    pub claimed_application_id: String,
    /// Its HTTPS origin, which `CON-409` requires be shown alongside — a person
    /// comparing a full URL reads the path and misses the host, and the host is
    /// the part that decides who they are about to be granted by.
    pub claimed_origin: String,
    /// The six-digit nameplate the ceremony will meet at.
    pub nameplate: String,
    /// The descriptor selected from the profile, by id.
    pub provider_id: String,
    /// The pairing endpoint the selected descriptor names.
    pub pairing_url: String,
    /// `binding_hash`, base64url — the value both endpoints must agree on.
    /// Returned so the answering step cannot recompute it from different inputs.
    pub binding_hash: String,
    /// Seconds until the record expires.
    pub expires_in: i64,
    /// The profile octets, recognised and digest-matched, for the steps after
    /// this one. Carried rather than re-fetched so the ceremony binds to the
    /// exact bytes whose digest was checked.
    pub profile: Vec<u8>,
}

/// Resolve a scanned or typed pairing code.
///
/// `CON-409`'s steps, in its order: recover `C` and verify the checksum; derive
/// the address and resolve; verify the signature; reject expiry; recognise the
/// closed member set; fetch the profile and match its digest; select the unique
/// descriptor; construct the binding.
#[tauri::command]
pub async fn read_pairing_code(code: String) -> Result<PairingTarget> {
    // Step 1. A QR carries the bootstrap; a typed code carries twelve words.
    // Both are renderings of the same sixteen octets, and the checksum is
    // verified here — before any address is derived or any socket is opened.
    let code = Code::from_qr_payload(&code)
        .or_else(|_| Code::from_words(&code))
        .map_err(|_| UiError::from("That code isn't valid."))?;

    // Step 2. The address is a function of `C` alone, so nothing about where to
    // look came from the person or the wire.
    let point = code.meeting_point();
    let envelope = resolve_record(&point.address_text()).await?;

    // Steps 3, 4, 5 — signature, expiry, closed member set — are the pure core's.
    let record = pairing_code::recognise_meeting_record(
        &point.address(),
        &envelope.payload,
        &envelope.signature,
        now() as i64,
    )
    .map_err(|_| UiError::from("That code isn't valid."))?;

    // Step 6. The profile comes from the canonical `applicationId` ORIGIN, not
    // from the record, and its digest must equal what the record claimed. This
    // is the only thing in the whole resolution that ties the claim to bytes
    // somebody else served.
    let application_id = ApplicationId::parse(&record.application_id)
        .map_err(|_| UiError::from("That code isn't valid."))?;
    // `UiError` converts `crate::net::NetError`, not the profile client's, and
    // the two are different types. Mapped explicitly rather than widened: a
    // blanket conversion would let any future network error reach a person as
    // whatever this one happens to say.
    let fetched = profile_net::fetch(&application_id, now() as i64)
        .await
        .map_err(|_| UiError::from("UnverifiedApplication"))?;
    if selfsame_app_identity::codec::b64url(fetched.profile.digest()) != record.profile_digest {
        // The record named an application whose published profile is not the one
        // it committed to. That is a substitution, not a stale cache.
        return Err(UiError::from("PairingProfileMismatch"));
    }

    // Step 7. Exactly one descriptor. `providerId` is REQUIRED alongside the
    // digest because `pairingUrl` alone is ambiguous when one profile declares
    // two descriptors at one origin — so a match by URL would be a coin flip.
    let descriptor = fetched
        .profile
        .rendezvous
        .iter()
        .find(|d| d.id == record.provider_id)
        .ok_or_else(|| UiError::from("PairingProviderUnknown"))?;

    // Step 8. The binding, built from THIS wallet's own resolved profile and
    // selection. `CON-403` requires both parties to hold every member before
    // either processes a peer frame, and building it from the record alone would
    // be taking the initiator's word for what the ceremony is about.
    let binding = BindingObject {
        application_id: application_id.as_str().to_owned(),
        descriptor_digest: selfsame_app_identity::codec::b64url(&descriptor.digest),
        nameplate: record.nameplate.clone(),
        number: format!("{}{}", descriptor.pairing_route, record.nameplate),
        profile_digest: record.profile_digest.clone(),
        protocol: descriptor.pairing_protocol.clone(),
        provider_id: record.provider_id.clone(),
        route: descriptor.pairing_route.clone(),
        version: 1,
    };

    // Read before the record is taken apart, since `expires_in` needs the whole
    // of it and the fields below move out.
    let expires_in = expires_in(&record);
    Ok(PairingTarget {
        claimed_origin: application_id.origin().to_owned(),
        claimed_application_id: application_id.as_str().to_owned(),
        nameplate: record.nameplate,
        provider_id: record.provider_id,
        pairing_url: descriptor.pairing_url.clone(),
        binding_hash: selfsame_app_identity::codec::b64url(&binding.binding_hash()),
        expires_in,
        profile: fetched.octets,
    })
}

fn expires_in(record: &MeetingRecord) -> i64 {
    selfsame_app_identity::time::parse_date_time_stamp(&record.expires_at)
        .map(|at| at - now() as i64)
        .unwrap_or(0)
}

/// The record envelope, as the host serves it.
struct Envelope {
    payload: Vec<u8>,
    signature: [u8; 64],
}

/// Fetch and decode the envelope at a meeting address.
///
/// Nothing here checks the signature: that is the caller's, against an address
/// this wallet derived. A fetch that verified would be verifying against
/// whatever the response claimed the address was.
async fn resolve_record(address: &str) -> Result<Envelope> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        payload: String,
        signature: String,
    }

    let host = record_host();
    let response = reqwest::Client::builder()
        .timeout(RESOLVE_DEADLINE)
        .build()
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?
        .get(format!("{host}/pairing/records/{address}"))
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?;
    if !response.status().is_success() {
        // `CON-409`: a code that resolves no record returns
        // `PairingRecordUnavailable`, and a resolving party SHALL NOT search
        // installed applications, historic profiles, provider lists, DNS
        // guesses, or any other endpoint for a match, nor retry with a mutated
        // code. So this is where it stops.
        return Err(UiError::from("PairingRecordUnavailable"));
    }
    let body = response
        .bytes()
        .await
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?;
    if body.len() > MAX_ENVELOPE_OCTETS {
        return Err(UiError::from("PairingRecordUnavailable"));
    }
    let wire: Wire =
        serde_json::from_slice(&body).map_err(|_| UiError::from("PairingRecordUnavailable"))?;

    use base64ct::Encoding as _;
    let payload = base64ct::Base64UrlUnpadded::decode_vec(&wire.payload)
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?;
    let signature: [u8; 64] = base64ct::Base64UrlUnpadded::decode_vec(&wire.signature)
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?
        .try_into()
        .map_err(|_| UiError::from("PairingRecordUnavailable"))?;
    Ok(Envelope { payload, signature })
}

/// Where records are resolved from.
///
/// A deployment declares record hosts in its profile's `pairingRecordRelays`,
/// but a wallet has no profile until step 6 — it needs a host to resolve the
/// record that names the application whose profile it would read. So the host is
/// a wallet-side setting rather than a profile-side one, exactly as the
/// `CON-208` endpoint table is, and for the same reason: nothing in a code is an
/// address.
fn record_host() -> String {
    std::env::var("SELFSAME_PAIRING_RECORDS")
        .unwrap_or_else(|_| "https://rendezvous.cbcl.chat".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The view names the claim as a claim.
    ///
    /// A field called `application_id` on a consent screen is read as "this is
    /// who is asking". `CON-409` says it is not, and no code in this file can
    /// make it so — the name is the only place that distinction survives being
    /// passed to a designer.
    #[test]
    fn the_target_names_the_application_as_claimed() {
        let json = serde_json::to_string(&PairingTarget {
            claimed_application_id: "https://chat.anuna.io/selfsame/application".into(),
            claimed_origin: "https://chat.anuna.io".into(),
            nameplate: "482715".into(),
            provider_id: "dev-local".into(),
            pairing_url: "https://localhost:8443".into(),
            binding_hash: "x".into(),
            expires_in: 300,
            profile: vec![],
        })
        .unwrap();
        assert!(json.contains("claimedApplicationId"));
        assert!(json.contains("claimedOrigin"));
        assert!(
            !json.contains("\"applicationId\""),
            "an unqualified applicationId would read as verified",
        );
    }
}
