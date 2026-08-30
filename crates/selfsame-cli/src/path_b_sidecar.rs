//! Closed JSON stdin/stdout bridge from verified resolver I/O to the CBCL NIF.

use std::io::{Read, Write};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use selfsame_app_identity::profile::ApplicationProfile;
use selfsame_app_identity::alias::{stable_acct_uri, AcctUri};
use selfsame_app_identity_net::state::resolve_path_b_quorum;
use selfsame_app_identity_net::webfinger::fetch_reciprocal_or_absent;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request { profile: Vec<u8>, did: String }
#[derive(Serialize)]
struct Response<T> { resolver_closures: T, account: String, jrd: Vec<u8> }

/// Resolve a JSON request read from stdin and emit only NIF-ready closure facts.
pub fn run() -> Result<()> {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).context("read Path-B request")?;
    let request: Request = serde_json::from_str(&input).context("closed Path-B request JSON")?;
    let profile = ApplicationProfile::recognise(&request.profile).context("recognise profile")?;
    let runtime = tokio::runtime::Runtime::new()?;
    // Stamped BEFORE the fetch, deliberately. This is the verifier's own record
    // of when it obtained the state; taking it afterwards would understate the
    // age by however long the fetch took — exactly the interval a slow or
    // stalling resolver controls. Erring old cannot make stale state look fresh.
    let fetched_at_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs() as i64;
    let quorum = runtime.block_on(resolve_path_b_quorum(&profile, &request.did))?;
    let account = stable_acct_uri(&request.did, &profile.account_authority);
    let acct = AcctUri::parse(&account)?;
    // Projected ONCE. It was built twice before, which with a clock reading
    // inside would have stamped two different times into one answer.
    let resolver_closures = quorum.nif_closures(fetched_at_seconds)?;
    let aka = resolver_closures.first().map(|c| c.also_known_as.clone()).unwrap_or_default();
    // First contact publishes no reciprocal JRD yet (the application binds the
    // account only when it accepts this very credential), so absence is an
    // answer — an empty `jrd` — while a wrong or malformed one still refuses.
    let jrd = runtime
        .block_on(fetch_reciprocal_or_absent(&acct, &request.did, &aka))?
        .unwrap_or_default();
    serde_json::to_writer(std::io::stdout(), &Response { resolver_closures, account, jrd })?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_profile_fixture_is_accepted_but_a_closure_member_is_not() {
        let vectors: serde_json::Value = serde_json::from_slice(include_bytes!("../../../test-vectors/spec-004-v1.json")).unwrap();
        let profile = vectors["con_201_application_profile"][0]["input"]["profile"].as_str().unwrap().as_bytes().to_vec();
        let request = serde_json::json!({ "profile": profile, "did": "did:crdt:bad" });
        let parsed: Request = serde_json::from_value(request).expect("fixture request is closed");
        ApplicationProfile::recognise(&parsed.profile).expect("SPEC-004 fixture is recognised");

        let hostile = serde_json::json!({ "profile": profile, "did": "did:crdt:bad", "resolver_closures": [] });
        assert!(serde_json::from_value::<Request>(hostile).is_err());
    }
}
