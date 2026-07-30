# Selfsame functional prior art

**Research date:** 2026-07-30

**Question:** Does another project already do what the application- and
account-scoped Selfsame design does?

**Scope:** Functional and architectural overlap, not project-name collisions.

## Finding

No project in this desk survey combines the complete Selfsame shape:

1. one recoverable private root;
2. deterministic, unlinkable application **and account** home DIDs;
3. ordinary multi-account switching without user-managed derivation settings;
4. RFC 7565 public aliases separated from opaque authorization aliases;
5. device-bound W3C VC grants;
6. controller-owned, convergent `did:crdt` credential revocation; and
7. application-selected rendezvous/state operators with no mandatory Selfsame
   service.

The design is nevertheless a synthesis of well-established ideas rather than
an isolated invention. Its closest antecedents are Microsoft CardSpace for
pairwise deterministic identifiers, SLIP-0013 for recoverable
service-specific keys, passkeys for the expected user experience, Fission ODD
for a working decentralized application stack, and peer DIDs/DIDComm for
pairwise decentralized communication.

This is an engineering landscape review, not an exhaustive novelty or patent
search.

## Comparison

| Project or standard | Material overlap | What remains different from Selfsame |
|---|---|---|
| Microsoft CardSpace / Information Cards | A PPID was deterministically derived from card-specific material and relying-party identity, producing a different pseudonym for each relying party. Microsoft also described relying-party-specific key derivation. | Historical, centrally brokered identity-selector model; no application/account `did:crdt` homes, VC device grants, or CRDT revocation. |
| SLIP-0013 | Derives a deterministic key hierarchy from a master seed and service URI, with an index for multiple identities at one service; backup of the master seed recovers identities. | Key convention rather than a complete account, discovery, linking, VC, or revocation protocol. |
| OpenID Connect pairwise subject identifiers | Gives different locally unique `sub` values to different clients or sectors, deterministically and non-reversibly. | The OpenID Provider remains the common issuer and infrastructure operator; it does not give the holder recoverable application-specific controller keys. |
| WebAuthn and synced passkeys | RP-scoped credentials, multiple account selectors at one RP, device-bound proof, and a “choose account and continue” experience. Synced passkeys provide cross-device recovery. | Sync is delegated to a passkey-provider account; credentials are not application-account home DIDs or portable VC grants, and revocation is RP/provider state. |
| Fission ODD / Webnative | Decentralized identity and storage SDK, UCAN authorization, encrypted WNFS, account recovery, application namespaces, and device-linking flows. This is the closest implemented product bundle found. | Does not use the exact pairwise deterministic app/account DID hierarchy, RFC 7565 alias model, W3C VC device grant, or `did:crdt` G-Set revocation specified here. |
| GNUnet re:claimID | Decentralized identity provider with encrypted attributes, per-relying-party authorization tickets, revocation, and OpenID Connect integration. | Begins from user identities and attribute sharing rather than one recoverable root yielding isolated application-account homes and device grants. |
| Peer DIDs plus DIDComm | Pairwise private DIDs without a central resolver, out-of-band establishment, mediators, multiple endpoints, and endpoint failover. | Supplies relationship identity and messaging pieces, not Selfsame’s recovery hierarchy, application account switch, VC grant, or grant-revocation state. |
| UCAN | Delegable, attenuated capabilities; a stable DID can authorize multiple agents/devices without sharing its private key, with revocation mechanisms. | Capability delegation does not itself define pairwise recoverable app/account identities, aliases, rendezvous selection, or `did:crdt` state. |
| Decentralized Web Nodes | Multiple nodes can replicate a DID owner’s data, with permission grants and provider-independent node operation. | Uses an owner DID and replicated data plane; it does not create separate deterministic homes for every application account. |
| Hyperledger AnonCreds | Holder link secret, unlinkable presentations, and issuer revocation registries demonstrate mature privacy-preserving credential techniques. | Optimizes anonymous credential presentation, not discoverable per-application device identities or controller-owned CRDT revocation. |

## Design implications

- CardSpace and OIDC establish strong precedent for pairwise identifiers, but
  Selfsame should avoid recreating their common-provider correlation point.
- SLIP-0013 supports the recovery-root → service branch idea. Selfsame’s
  explicit random `accountScopeId` is the additional mechanism needed for two
  accounts at one application without deriving from PII.
- Passkeys are the right UX benchmark: application account selection should
  automatically select the matching credential branch. Selfsame should not
  expose derivation indexes or provider endpoints to users.
- Fission ODD is the most important implementation comparison. Before claiming
  product novelty, prototype reviews should compare Selfsame ceremonies,
  recovery, UCAN/device authorization, and operator dependencies directly
  against ODD.
- Peer DIDs, DIDComm, UCAN, and DWNs are plausible components or
  interoperability targets. None removes the need for Selfsame’s precise
  profile and cross-field authorization predicate.
- Making `did:crdt` revocation authoritative is a meaningful differentiator:
  the resolver transports signed state, while an optional W3C Bitstring Status
  List is only a home-authorized projection for generic VC consumers.

## Primary sources

- Microsoft, [A First Look at InfoCard](https://learn.microsoft.com/en-us/archive/msdn-magazine/2006/april/security-briefs-a-first-look-at-infocard).
- SatoshiLabs, [SLIP-0013: Authentication using deterministic hierarchy](https://slips.readthedocs.io/en/latest/slip-0013/).
- OpenID Foundation, [OpenID Connect Core 1.0 — pairwise identifier algorithm](https://openid.net/specs/openid-connect-core-1_0.html#PairwiseAlg).
- W3C, [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/).
- FIDO Alliance, [Passkeys](https://fidoalliance.org/passkeys/).
- Fission / ODD SDK, [TypeScript ODD repository](https://github.com/oddsdk/ts-odd).
- GNUnet, [re:claimID specification](https://lsd.gnunet.org/lsd0002/).
- Decentralized Identity Foundation, [Peer DID Method Specification](https://identity.foundation/peer-did-method-spec/).
- Decentralized Identity Foundation, [DIDComm Messaging v2.0](https://identity.foundation/didcomm-messaging/spec/v2.0/).
- UCAN, [Delegation](https://ucan.xyz/delegation/).
- Decentralized Identity Foundation, [Decentralized Web Node specification](https://identity.foundation/decentralized-web-node/spec/).
- Hyperledger, [AnonCreds specification](https://hyperledger.github.io/anoncreds-spec/).
