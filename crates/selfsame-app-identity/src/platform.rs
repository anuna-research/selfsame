//! Platform adapter conformance — `CON-222` (Android), `CON-223` (Apple),
//! `REQ-220`, `REQ-223`, `REQ-225`.
//!
//! # What is here and what cannot be
//!
//! The *dispatch* is native code: `PackageManager`, `PendingIntent`,
//! `UIApplication.open`. That FFI is not in this crate and cannot be — it has no
//! meaning outside an integration harness with a real OS, which is why
//! `TEST-239` requires "real Android and Apple platform adapters with hostile
//! sibling apps and alternate link handlers installed".
//!
//! What **is** here is the part that decides conformance: the binding-identifier
//! grammars, the caller-identity comparison, the dispatch-policy flags each
//! platform requires, and the return-path origin rule. `CON-215` says a future
//! adapter "must provide equivalent installed-target authentication,
//! no-network-fallback behavior, one-shot delivery, and a caller-binding signal
//! for `CON-214`" and that "declaring itself equivalent is insufficient".
//! [`AdapterConformance`] is what a claim of equivalence is checked against.
//!
//! # The asymmetry between the two platforms is real, and stated
//!
//! Android gives the wallet the calling package. Apple does not:
//!
//! > Apple provides no general equivalent of Android's calling-package
//! > attribution for a Universal Link open. The wallet therefore compares only
//! > what the platform genuinely authenticates — the association between the
//! > return URI's origin and the declared binding — and SHALL NOT treat any
//! > payload-supplied identifier as caller evidence. The residual gap is closed
//! > by the `CON-214` backend signature and by `CON-221` confirmation, not by
//! > the platform.
//!
//! That is why [`CallerEvidence`] has an `Unattributed` variant rather than
//! defaulting to "trust the payload". An adapter that filled the gap with a
//! caller-supplied identifier would be manufacturing evidence, and `CON-222`
//! says plainly: "A caller-supplied package name in the payload is never
//! evidence of anything."
//!
//! # Recording an identity is not checking it against a registry
//!
//! `CON-222` has the wallet read the target's signing certificate before
//! dispatch — and then says what that is *for*:
//!
//! > That identity is recorded for the person's benefit and for post-hoc audit —
//! > it is **not** checked against a registry, because none exists, which is
//! > precisely why `CON-221` confirmation is required at first enrollment.
//!
//! So [`AndroidTarget::signing_certificates`] is data to record, and there is no
//! function here that "verifies" it against anything. Adding one would imply an
//! authority that does not exist.

use crate::profile::MobileBinding;

/// Result of asking an operating-system adapter to open an authenticated target.
///
/// This is transport-neutral policy output. It carries no pairing secret,
/// invitation, credential, or callback value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchResult {
    /// Delivered to the verified installed wallet.
    Dispatched,
    /// No conforming wallet is installed.
    WalletUnavailable,
    /// A candidate exists but its signing identity did not verify.
    UnverifiedWalletTarget,
}

impl DispatchResult {
    /// Whether the caller must abandon the attempted delivery.
    pub fn burns_attempt(self) -> bool {
        self != DispatchResult::Dispatched
    }
}

/// `CON-222`: the Android API level floor.
///
/// "Level 30 is the floor because package visibility filtering and the maturity
/// of verified App Links below it make both wallet discovery and the return path
/// unreliable in ways an application cannot detect." A floor set for
/// undetectability rather than for features.
pub const MIN_ANDROID_API_LEVEL: u32 = 30;

/// Which platform an adapter serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    /// `CON-222`.
    Android,
    /// `CON-223`.
    Apple,
}

/// What the platform could tell the wallet about its caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallerEvidence {
    /// Android: the calling package, from the `PendingIntent` creator or
    /// `getCallingPackage()`.
    Package(String),
    /// Apple: the platform authenticated the return URI's origin against the
    /// declared association, and nothing more.
    AssociatedOrigin(String),
    /// The platform attributed nothing.
    ///
    /// Not an error and not a licence: `CON-223` records that Apple genuinely
    /// provides no general caller attribution for a Universal Link open, and the
    /// residual gap is closed by the `CON-214` signature and `CON-221`
    /// confirmation rather than by the platform.
    Unattributed,
}

/// Why a platform check refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    /// The caller does not match the binding the `CON-214` evidence names.
    #[error("PlatformBindingMismatch")]
    PlatformBindingMismatch,
    /// The adapter would have to fall back outside its permitted boundary.
    #[error("UnverifiedWalletTarget")]
    UnverifiedWalletTarget,
    /// No conforming wallet is installed.
    ///
    /// `CON-222`: "where none does, the result is `WalletUnavailable` and an
    /// install action containing no ceremony value." Distinct from
    /// [`UnverifiedWalletTarget`](Self::UnverifiedWalletTarget), which means a
    /// candidate existed and did not authenticate — the person is offered an
    /// install in the first case and a refusal in the second, and a caller that
    /// cannot tell them apart renders the wrong one.
    #[error("WalletUnavailable")]
    WalletUnavailable,
    /// The OS is below the level the contract requires.
    ///
    /// Externally this collapses to `WalletUnavailable` — no conforming wallet
    /// can run here — while staying separable in a local diagnostic.
    #[error("WalletUnavailable")]
    BelowMinimumApiLevel,
    /// A binding identifier is not the shape its platform fixes.
    #[error("HandoffMalformed")]
    MalformedBindingId,
    /// The adapter's declared policy is not conformant.
    #[error("UnverifiedWalletTarget")]
    NonConformantAdapter,
}

// ── the dispatch policy each platform fixes ────────────────────────────────

/// The properties `CON-215` requires of **any** adapter, and against which a
/// claim of equivalence is checked.
///
/// Every field is a prohibition restated positively, so that an adapter which
/// leaves one `false` is visibly non-conformant rather than merely undocumented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdapterConformance {
    /// Delivery is constrained to a positively identified installed target.
    ///
    /// Android: an **explicit** component intent. Apple: `universalLinksOnly`.
    pub installed_target_authenticated: bool,
    /// Failure to reach that target is terminal.
    ///
    /// No browser, embedded web view, install page, custom URL scheme,
    /// clipboard, notification, or analytics sink ever receives ceremony
    /// material. `REQ-223` enumerates them; this is the flag that says the
    /// adapter honours it.
    pub no_network_or_web_fallback: bool,
    /// Any result capability handed out is single-use.
    pub one_shot_delivery: bool,
    /// Any result capability handed out cannot be modified by the receiver.
    pub immutable_result_capability: bool,
    /// The adapter can supply a caller-binding signal for `CON-214`, or
    /// truthfully reports that its platform cannot.
    pub caller_binding_signal: bool,
}

impl AdapterConformance {
    /// What `CON-222` fixes for Android.
    ///
    /// `FLAG_IMMUTABLE` and `FLAG_ONE_SHOT` are both required "even though
    /// `CON-215`'s return object carries no authority — defence in depth costs
    /// nothing here". Mutability would let the wallet inject fields into the
    /// return; multi-use would let it replay one.
    pub const ANDROID: Self = Self {
        installed_target_authenticated: true,
        no_network_or_web_fallback: true,
        one_shot_delivery: true,
        immutable_result_capability: true,
        caller_binding_signal: true,
    };

    /// What `CON-223` fixes for Apple.
    ///
    /// `caller_binding_signal` is `false` and that is the contract, not a
    /// shortfall: Apple provides no general caller attribution for a Universal
    /// Link open, and `CON-223` says so rather than pretending otherwise.
    pub const APPLE: Self = Self {
        installed_target_authenticated: true,
        no_network_or_web_fallback: true,
        one_shot_delivery: true,
        immutable_result_capability: true,
        caller_binding_signal: false,
    };

    /// Whether a claimed adapter meets the bar for its platform.
    ///
    /// The four universal properties are required of every adapter. The
    /// caller-binding signal is required only where the platform can provide
    /// one, because requiring it everywhere would push an Apple adapter toward
    /// manufacturing the evidence it cannot obtain.
    pub fn is_conformant(&self, platform: Platform) -> Result<(), PlatformError> {
        let required = match platform {
            Platform::Android => Self::ANDROID,
            Platform::Apple => Self::APPLE,
        };
        let universal = self.installed_target_authenticated
            && self.no_network_or_web_fallback
            && self.one_shot_delivery
            && self.immutable_result_capability;
        if !universal {
            return Err(PlatformError::NonConformantAdapter);
        }
        if required.caller_binding_signal && !self.caller_binding_signal {
            return Err(PlatformError::NonConformantAdapter);
        }
        Ok(())
    }
}

// ── CON-222: Android ───────────────────────────────────────────────────────

/// What the Android adapter observed about a candidate wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AndroidTarget {
    /// The package name `PackageManager` returned.
    pub package_name: String,
    /// The signing-certificate digests read with `GET_SIGNING_CERTIFICATES`.
    ///
    /// Recorded, never checked against a registry: none exists, which is
    /// precisely why `CON-221` confirmation is required at first enrollment.
    pub signing_certificates: Vec<String>,
}

/// How the adapter proposes to deliver the handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AndroidDispatch {
    /// An explicit component intent to one selected package.
    ExplicitComponent,
    /// An implicit intent.
    ///
    /// Never permitted to carry ceremony material, "under any circumstance,
    /// **including when exactly one candidate resolves**". That clause exists
    /// because "only one handler resolved" is the reasoning that makes an
    /// implicit intent feel safe, and it is wrong: resolution is not identity.
    Implicit,
}

/// Choose an Android dispatch target (`CON-222`).
///
/// Zero candidates is [`DispatchResult::WalletUnavailable`] and an install action
/// carrying no ceremony value. More than one is a choice for the person, not for
/// the adapter — an adapter that picked would be choosing which app receives the
/// ceremony.
pub fn android_select(
    candidates: &[AndroidTarget],
    api_level: u32,
    person_chose: Option<&str>,
) -> Result<AndroidTarget, PlatformError> {
    if api_level < MIN_ANDROID_API_LEVEL {
        return Err(PlatformError::BelowMinimumApiLevel);
    }
    match candidates.len() {
        // The ordinary state of a device with no wallet yet. Not a failed
        // check — there was nothing to check — so the caller can offer the
        // install action CON-222 describes instead of reporting a refusal.
        0 => Err(PlatformError::WalletUnavailable),
        1 => Ok(candidates[0].clone()),
        _ => {
            let chosen = person_chose.ok_or(PlatformError::UnverifiedWalletTarget)?;
            candidates
                .iter()
                .find(|c| c.package_name == chosen)
                .cloned()
                .ok_or(PlatformError::UnverifiedWalletTarget)
        }
    }
}

/// Whether a dispatch mechanism may carry ceremony material (`CON-222`).
pub fn android_may_carry_ceremony(dispatch: AndroidDispatch) -> Result<(), PlatformError> {
    match dispatch {
        AndroidDispatch::ExplicitComponent => Ok(()),
        AndroidDispatch::Implicit => Err(PlatformError::UnverifiedWalletTarget),
    }
}

// ── CON-223: Apple ─────────────────────────────────────────────────────────

/// The outcome of an Apple Universal Link open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniversalLinkOutcome {
    /// An associated installed application handled it.
    Handled,
    /// No associated installed application could handle it.
    ///
    /// **Terminal.** "Per Apple's own semantics the option exists so that
    /// absence is a dispatch failure rather than a web navigation, and treating
    /// it otherwise would disclose the link outside the permitted boundary."
    NotHandled,
}

/// Turn a Universal Link outcome into a dispatch result (`CON-223`).
///
/// There is deliberately no parameter for "what to do instead". The absence of a
/// fallback path in the signature is the contract: an adapter cannot open
/// Safari, an embedded web view, an install page, or a custom URL scheme,
/// because this function offers nowhere to say so.
pub fn apple_dispatch(outcome: UniversalLinkOutcome, universal_links_only: bool) -> DispatchResult {
    if !universal_links_only {
        // Without the option set, a failed open becomes a web navigation, which
        // discloses the link outside the permitted boundary.
        return DispatchResult::UnverifiedWalletTarget;
    }
    match outcome {
        UniversalLinkOutcome::Handled => DispatchResult::Dispatched,
        UniversalLinkOutcome::NotHandled => DispatchResult::WalletUnavailable,
    }
}

// ── caller identity, both platforms ────────────────────────────────────────

/// Compare what the platform attributed against the `CON-214` binding.
///
/// `CON-222`: "The wallet obtains the calling package through the
/// `PendingIntent` creator, or `getCallingPackage()` where the invocation form
/// provides it, and compares it to the `platformBindingId` in the `CON-214`
/// evidence. A mismatch is `PlatformBindingMismatch`."
///
/// `CON-223`: the wallet "compares only what the platform genuinely
/// authenticates" and "SHALL NOT treat any payload-supplied identifier as caller
/// evidence".
///
/// # Absent attribution is permitted on exactly one platform
///
/// [`CallerEvidence::Unattributed`] passes against an **Apple** binding and
/// closes nothing: `CON-223` gives the wallet nothing but the associated origin
/// to compare, so refusing there would refuse every conforming Apple ceremony,
/// and the binding is left to the `CON-214` signature and `CON-221`
/// confirmation.
///
/// It does **not** pass against an Android binding. `CON-222` states the
/// comparison as an obligation with a named failure:
///
/// > The wallet obtains the calling package through the `PendingIntent`
/// > creator, or `getCallingPackage()` where the invocation form provides it,
/// > and compares it to the `platformBindingId` in the `CON-214` evidence. A
/// > mismatch is `PlatformBindingMismatch`.
///
/// An adapter that supplies no package on Android has not performed that
/// comparison, and "I could not check" is not a pass. Letting it through would
/// make the mandatory check optional for exactly the caller with a reason to
/// suppress it — the Apple carve-out would become a universal bypass, reachable
/// by any Android caller whose adapter simply reports nothing.
pub fn caller_matches_binding(
    evidence: &CallerEvidence,
    binding: &MobileBinding,
) -> Result<(), PlatformError> {
    match (evidence, binding) {
        (CallerEvidence::Package(package), MobileBinding::Android { package_name, .. }) => {
            if package == package_name {
                Ok(())
            } else {
                Err(PlatformError::PlatformBindingMismatch)
            }
        }
        (CallerEvidence::AssociatedOrigin(origin), MobileBinding::Apple { return_uri, .. }) => {
            // The association between the return URI's origin and the declared
            // binding is the only thing Apple authenticates.
            let declared = crate::uri::recognise(return_uri, crate::uri::UriPolicy::PROVIDER_URL)
                .map_err(|_| PlatformError::PlatformBindingMismatch)?;
            if origin == declared.origin {
                Ok(())
            } else {
                Err(PlatformError::PlatformBindingMismatch)
            }
        }
        // Apple: the platform attributed nothing, which CON-223 anticipates.
        // Not evidence, and not a failure.
        (CallerEvidence::Unattributed, MobileBinding::Apple { .. }) => Ok(()),
        // Web: the binding is the profile's authenticated admission that no
        // platform will attribute a caller (CON-227), so unattributed is the
        // conforming case — and the ONLY passing case. Any attributed caller
        // against a web binding falls to the catch-all below: an OS-mediated
        // handoff claiming a manual binding is a contradiction, and refusing
        // it keeps same-device dispatch on the stronger CON-222/CON-223 forms.
        (CallerEvidence::Unattributed, MobileBinding::Web { .. }) => Ok(()),
        // Android: CON-222 requires the calling-package comparison, and an
        // unattributed caller is one it could not be performed on.
        (CallerEvidence::Unattributed, MobileBinding::Android { .. }) => {
            Err(PlatformError::PlatformBindingMismatch)
        }
        // Android evidence against an Apple binding or vice versa: a caller on
        // one platform presenting the other's binding.
        _ => Err(PlatformError::PlatformBindingMismatch),
    }
}

/// The platform a binding identifier belongs to, recovered from its own prefix.
pub fn binding_platform(binding_id: &str) -> Result<Platform, PlatformError> {
    if binding_id.starts_with("android:") {
        Ok(Platform::Android)
    } else if binding_id.starts_with("apple:") {
        Ok(Platform::Apple)
    } else {
        Err(PlatformError::MalformedBindingId)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn android_binding() -> MobileBinding {
        MobileBinding::Android {
            id: "android:com.example.photos:AAAA".into(),
            package_name: "com.example.photos".into(),
            signing_certificate_sha256: vec!["AAAA".into()],
        }
    }

    fn apple_binding() -> MobileBinding {
        MobileBinding::Apple {
            id: "apple:TEAM123456:com.example.photos:https://photos.example".into(),
            team_id: "TEAM123456".into(),
            bundle_id: "com.example.photos".into(),
            return_uri: "https://photos.example/.well-known/selfsame/return".into(),
        }
    }

    fn target(package: &str) -> AndroidTarget {
        AndroidTarget {
            package_name: package.into(),
            signing_certificates: vec!["AAAA".into()],
        }
    }

    // ── CON-222 ────────────────────────────────────────────────────────────

    #[test]
    fn an_api_level_below_thirty_is_refused() {
        // The floor is set for undetectability, not features: below it, package
        // visibility filtering and App Link verification fail in ways an
        // application cannot detect.
        assert_eq!(
            android_select(&[target("com.wallet")], 29, None),
            Err(PlatformError::BelowMinimumApiLevel)
        );
        assert!(android_select(&[target("com.wallet")], 30, None).is_ok());
    }

    #[test]
    fn no_candidate_is_wallet_unavailable_and_several_is_the_persons_choice() {
        // CON-222: "where none does, the result is `WalletUnavailable` and an
        // install action containing no ceremony value." The install action is
        // the caller's to offer, and it can only offer it if the outcome says
        // "no wallet here" rather than "a wallet failed to authenticate".
        assert_eq!(
            android_select(&[], 30, None),
            Err(PlatformError::WalletUnavailable)
        );

        let two = [target("com.wallet.a"), target("com.wallet.b")];
        // An adapter that picked would be choosing which app receives the
        // ceremony.
        assert_eq!(
            android_select(&two, 30, None),
            Err(PlatformError::UnverifiedWalletTarget)
        );
        assert_eq!(
            android_select(&two, 30, Some("com.wallet.b"))
                .unwrap()
                .package_name,
            "com.wallet.b"
        );
        // A choice naming something that did not resolve.
        assert_eq!(
            android_select(&two, 30, Some("com.attacker")),
            Err(PlatformError::UnverifiedWalletTarget)
        );
    }

    #[test]
    fn an_implicit_intent_never_carries_ceremony_material() {
        // "under any circumstance, including when exactly one candidate
        // resolves" — resolution is not identity, and "only one handler
        // resolved" is exactly the reasoning that makes this feel safe.
        assert!(android_may_carry_ceremony(AndroidDispatch::ExplicitComponent).is_ok());
        assert_eq!(
            android_may_carry_ceremony(AndroidDispatch::Implicit),
            Err(PlatformError::UnverifiedWalletTarget)
        );
    }

    #[test]
    fn a_calling_package_is_compared_against_the_binding() {
        assert!(caller_matches_binding(
            &CallerEvidence::Package("com.example.photos".into()),
            &android_binding()
        )
        .is_ok());
        // TEST-230's "an app using the expected package name under the wrong
        // signing certificate" is caught here only by name; the certificate is
        // recorded for audit, not checked against a registry.
        assert_eq!(
            caller_matches_binding(
                &CallerEvidence::Package("com.attacker.app".into()),
                &android_binding()
            ),
            Err(PlatformError::PlatformBindingMismatch)
        );
    }

    #[test]
    fn the_recorded_signing_identity_is_data_and_not_a_check() {
        // There is deliberately no `verify_signing_certificate` here. CON-222:
        // "it is **not** checked against a registry, because none exists, which
        // is precisely why CON-221 confirmation is required at first
        // enrollment." A function implying an authority would invent one.
        let t = target("com.wallet");
        assert_eq!(t.signing_certificates, vec!["AAAA".to_string()]);
    }

    // ── CON-223 ────────────────────────────────────────────────────────────

    #[test]
    fn a_universal_link_that_reaches_nothing_is_terminal() {
        assert_eq!(
            apple_dispatch(UniversalLinkOutcome::Handled, true),
            DispatchResult::Dispatched
        );
        assert_eq!(
            apple_dispatch(UniversalLinkOutcome::NotHandled, true),
            DispatchResult::WalletUnavailable
        );
        assert!(apple_dispatch(UniversalLinkOutcome::NotHandled, true).burns_attempt());
    }

    #[test]
    fn opening_without_universal_links_only_is_not_a_dispatch() {
        // Without the option, a failed open becomes a web navigation, which
        // discloses the link outside the permitted boundary.
        assert_eq!(
            apple_dispatch(UniversalLinkOutcome::Handled, false),
            DispatchResult::UnverifiedWalletTarget
        );
    }

    #[test]
    fn apple_caller_evidence_is_the_association_and_nothing_else() {
        assert!(caller_matches_binding(
            &CallerEvidence::AssociatedOrigin("https://photos.example".into()),
            &apple_binding()
        )
        .is_ok());
        assert_eq!(
            caller_matches_binding(
                &CallerEvidence::AssociatedOrigin("https://attacker.example".into()),
                &apple_binding()
            ),
            Err(PlatformError::PlatformBindingMismatch)
        );
    }

    #[test]
    fn an_unattributed_apple_caller_passes_and_closes_nothing() {
        // The residual gap is closed by the CON-214 signature and CON-221
        // confirmation, not by the platform. Refusing here would refuse every
        // conforming Apple ceremony; treating a payload value as evidence would
        // be worse.
        assert!(caller_matches_binding(&CallerEvidence::Unattributed, &apple_binding()).is_ok());
    }

    #[test]
    fn an_unattributed_android_caller_fails_the_mandatory_comparison() {
        // CON-222 makes the calling-package comparison an obligation with a
        // named failure. An adapter that reports nothing has not performed it,
        // and "could not check" is not "checked and matched" — otherwise the
        // Apple carve-out becomes a universal bypass any Android caller can
        // reach by staying quiet.
        assert_eq!(
            caller_matches_binding(&CallerEvidence::Unattributed, &android_binding()),
            Err(PlatformError::PlatformBindingMismatch)
        );
    }

    #[test]
    fn evidence_from_one_platform_does_not_satisfy_the_others_binding() {
        assert_eq!(
            caller_matches_binding(
                &CallerEvidence::Package("com.example.photos".into()),
                &apple_binding()
            ),
            Err(PlatformError::PlatformBindingMismatch)
        );
        assert_eq!(
            caller_matches_binding(
                &CallerEvidence::AssociatedOrigin("https://photos.example".into()),
                &android_binding()
            ),
            Err(PlatformError::PlatformBindingMismatch)
        );
    }

    // ── CON-215's equivalence bar ──────────────────────────────────────────

    #[test]
    fn both_shipped_adapter_policies_are_conformant_for_their_platform() {
        assert!(AdapterConformance::ANDROID
            .is_conformant(Platform::Android)
            .is_ok());
        assert!(AdapterConformance::APPLE
            .is_conformant(Platform::Apple)
            .is_ok());
    }

    #[test]
    fn apples_missing_caller_signal_is_the_contract_and_androids_absence_is_not() {
        // CON-223 records the gap rather than pretending otherwise, so an Apple
        // adapter without a caller signal conforms. An Android one does not:
        // the platform provides it, so omitting it is a choice.
        assert!(AdapterConformance::APPLE
            .is_conformant(Platform::Apple)
            .is_ok());
        assert_eq!(
            AdapterConformance::APPLE.is_conformant(Platform::Android),
            Err(PlatformError::NonConformantAdapter)
        );
    }

    #[test]
    fn dropping_any_universal_property_fails_the_equivalence_bar() {
        // CON-215: "Declaring itself equivalent is insufficient."
        let mutations: [fn(&mut AdapterConformance); 4] = [
            |a| a.installed_target_authenticated = false,
            |a| a.no_network_or_web_fallback = false,
            |a| a.one_shot_delivery = false,
            |a| a.immutable_result_capability = false,
        ];
        for (i, mutate) in mutations.iter().enumerate() {
            for platform in [Platform::Android, Platform::Apple] {
                let mut claimed = match platform {
                    Platform::Android => AdapterConformance::ANDROID,
                    Platform::Apple => AdapterConformance::APPLE,
                };
                mutate(&mut claimed);
                assert_eq!(
                    claimed.is_conformant(platform),
                    Err(PlatformError::NonConformantAdapter),
                    "mutation {i} on {platform:?}"
                );
            }
        }
    }

    #[test]
    fn a_binding_identifier_names_its_own_platform() {
        assert_eq!(
            binding_platform("android:com.example.photos:AAAA").unwrap(),
            Platform::Android
        );
        assert_eq!(
            binding_platform("apple:TEAM123456:com.example.photos:https://photos.example").unwrap(),
            Platform::Apple
        );
        assert_eq!(
            binding_platform("windows:x"),
            Err(PlatformError::MalformedBindingId)
        );
        assert_eq!(binding_platform(""), Err(PlatformError::MalformedBindingId));
    }

    #[test]
    fn the_error_tokens_are_the_ones_con_215_closes_over() {
        // CON-226 requires a corpus case for each closed token; these are the
        // platform contracts' contribution to that set.
        assert_eq!(
            PlatformError::PlatformBindingMismatch.to_string(),
            "PlatformBindingMismatch"
        );
        assert_eq!(
            PlatformError::UnverifiedWalletTarget.to_string(),
            "UnverifiedWalletTarget"
        );
        assert_eq!(
            PlatformError::BelowMinimumApiLevel.to_string(),
            "WalletUnavailable"
        );
    }
}
