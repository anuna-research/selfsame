#![forbid(unsafe_code)]
//! `cbcl_selfsame_erl`: the isolated BEAM binding for Selfsame Path-B.
//!
//! This is deliberately not linked into `cbcl_erl`.  The latter is the
//! established CBCL parser NIF; keeping the dependency graphs separate avoids
//! turning an identity-verifier addition into a parser availability risk.

pub mod enrollment;
pub mod path_b;

pub use enrollment::{sign_enrollment_profile_bound, sign_enrollment_statement};
pub use path_b::{
    standing_cache_expiry, verified_revocation_union, verify_path_b_pure, PathBPresentation,
    ResolverClosure,
};

fn load(env: rustler::Env<'_>, _info: rustler::Term<'_>) -> bool {
    env.register::<path_b::StandingGrantResource>().is_ok()
}

rustler::init!("cbcl_selfsame_erl", load = load);
