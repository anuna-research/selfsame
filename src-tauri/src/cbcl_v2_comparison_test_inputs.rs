//! Canonical, typed comparison substitutions for disposable native fixtures.
use super::KID;
use cbcl_pairing::credential_v2::{CredentialV2Carrier, CredentialV2Kind, CredentialV2Object};
use ciborium::Value;
use ed25519_dalek::SigningKey;
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_pairing::credential_v2::{
    build_authority_status_response, CredentialV2AuthorityStatus,
};
use sha2::{Digest as _, Sha256};

pub(super) fn alter(
    original: CredentialV2Object,
    field: &str,
    profile: &ApplicationProfile,
    carrier: &CredentialV2Carrier,
    offer_digest: [u8; 32],
    earlier_predecessor: [u8; 32],
    signing: &SigningKey,
) -> CredentialV2Object {
    let mut value: Value = ciborium::de::from_reader(original.body()).unwrap();
    assert_eq!(cbor2::to_canonical_vec(&value).unwrap(), original.body());
    let entries = value.as_map_mut().unwrap();
    let preview = entries
        .iter()
        .find(|(k, _)| k.as_text() == Some("previewIssuerDid"))
        .unwrap()
        .1
        .as_text()
        .unwrap()
        .to_owned();
    let other = format!("did:crdt:{}", "b".repeat(64));
    assert!(other.parse::<did_crdt::Did>().is_ok());
    assert_ne!(preview, other);
    let mut kind = original.kind();
    let mut intent = *original.intent_digest();
    let set = |entries: &mut Vec<(Value, Value)>, key: &str, replacement: Value| {
        let members: Vec<_> = entries
            .iter_mut()
            .filter(|(k, _)| k.as_text() == Some(key))
            .collect();
        assert_eq!(members.len(), 1);
        let (_, member) = members.into_iter().next().unwrap();
        *member = replacement;
    };
    match field {
        "carrierCeremonyId" => set(entries, field, Value::Bytes(vec![0x91; 32])),
        "predecessorDigest" => set(entries, field, Value::Bytes(earlier_predecessor.to_vec())),
        "intentDigest" => intent = [0x93; 32],
        "previewIssuerDid" => {
            set(entries, field, Value::Text(other.clone()));
            set(
                entries,
                "previewFingerprintDigest",
                Value::Bytes(Sha256::digest(other.as_bytes()).to_vec()),
            );
        }
        "previewFingerprintDigest" => set(entries, field, Value::Bytes(vec![0x96; 32])),
        "authorityStatusDigest" => set(entries, field, Value::Bytes(vec![0x97; 32])),
        "result" => set(entries, field, Value::Text("bound-same-did".into())),
        "kind" => kind = CredentialV2Kind::BindingConfirmed,
        "authorityStatusResponse"
        | "statusOffer"
        | "statusSignature"
        | "boundOther"
        | "boundSame" => {
            let mut ceremony = *carrier.carrier_ceremony_id();
            let mut offer = offer_digest;
            let status = match field {
                "boundOther" => CredentialV2AuthorityStatus::Bound(other),
                "boundSame" => CredentialV2AuthorityStatus::Bound(preview),
                _ => CredentialV2AuthorityStatus::NoBinding,
            };
            if field == "authorityStatusResponse" {
                ceremony = [0x98; 32];
            }
            if field == "statusOffer" {
                offer = [0x99; 32];
            }
            let mut response =
                build_authority_status_response(profile, ceremony, offer, &status, KID, signing)
                    .unwrap()
                    .response;
            // Preserve the canonical tuple and all typed fields. Only a
            // signature octet changes; the outer response digest is recomputed.
            if field == "statusSignature" {
                *response.last_mut().unwrap() ^= 1;
            }
            if matches!(field, "boundOther" | "boundSame") {
                kind = CredentialV2Kind::BindingConfirmed;
                set(entries, "result", Value::Text("bound-same-did".into()));
            }
            set(
                entries,
                "authorityStatusDigest",
                Value::Bytes(Sha256::digest(&response).to_vec()),
            );
            set(entries, "authorityStatusResponse", Value::Bytes(response));
        }
        _ => panic!("declared comparison fixture case"),
    }
    CredentialV2Object::new(kind, intent, cbor2::to_canonical_vec(&value).unwrap()).unwrap()
}
