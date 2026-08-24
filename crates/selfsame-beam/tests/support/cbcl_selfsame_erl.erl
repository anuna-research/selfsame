%% A real BEAM-side harness for the Rustler boundary.
%%
%% The module name must match rustler::init!, and every registered NIF needs a
%% stub so erlang:load_nif/2 can replace the functions atomically. `run/0`
%% deliberately exercises sign_enrollment/4 only.
-module(cbcl_selfsame_erl).

-on_load(load_nif/0).

-export([
    operation_permission/2,
    path_b_standing_cache_expiry/1,
    recognise_credential_v2_profile/5,
    prepare_credential_v2_offer/15,
    finalize_credential_v2_offer/8,
    verify_credential_v2_offer_proof/6,
    build_credential_v2_authority_status/6,
    rehydrate_path_b/2,
    run/0,
    sign_enrollment/4,
    sign_enrollment_profile_bound/4,
    verified_path_b_revocations/2,
    verify_path_b/2,
    verify_path_b_sealed/2,
    verify_path_b_standing/3
]).

load_nif() ->
    erlang:load_nif(os:getenv("SELFSAME_NIF_PATH"), 0).

operation_permission(_, _) -> nif_not_loaded().
path_b_standing_cache_expiry(_) -> nif_not_loaded().
rehydrate_path_b(_, _) -> nif_not_loaded().
recognise_credential_v2_profile(_, _, _, _, _) -> nif_not_loaded().
prepare_credential_v2_offer(_, _, _, _, _, _, _, _, _, _, _, _, _, _, _) ->
    nif_not_loaded().
finalize_credential_v2_offer(_, _, _, _, _, _, _, _) ->
    nif_not_loaded().
verify_credential_v2_offer_proof(_, _, _, _, _, _) ->
    nif_not_loaded().
build_credential_v2_authority_status(_, _, _, _, _, _) ->
    nif_not_loaded().
sign_enrollment(_, _, _, _) -> nif_not_loaded().

%% Declared because `rustler::init!` registers every NIF in the crate and
%% `load_nif` answers `bad_lib` when the library exports one this module does
%% not — taking every OTHER entry point down with it. This harness exercises
%% `sign_enrollment/4`; the stub still has to exist.
sign_enrollment_profile_bound(_, _, _, _) -> nif_not_loaded().
verified_path_b_revocations(_, _) -> nif_not_loaded().
verify_path_b(_, _) -> nif_not_loaded().
verify_path_b_sealed(_, _) -> nif_not_loaded().
verify_path_b_standing(_, _, _) -> nif_not_loaded().

nif_not_loaded() ->
    erlang:nif_error(nif_not_loaded).

run() ->
    FixtureDir = os:getenv("SELFSAME_NIF_FIXTURE_DIR"),
    Statement = read(FixtureDir, "statement.bin"),
    InvalidVersion = read(FixtureDir, "invalid-version.bin"),
    DeclaredPublicKey = read(FixtureDir, "declared-public-key.bin"),
    OtherPublicKey = read(FixtureDir, "other-public-key.bin"),
    Seed = read(FixtureDir, "seed.bin"),
    OtherSeed = read(FixtureDir, "other-seed.bin"),
    Kid = <<"https://photos.example/selfsame/application#enrollment-2026-01">>,

    Compact = expect_ok(
        sign_enrollment(Statement, Kid, DeclaredPublicKey, Seed),
        accepting_control
    ),
    ok = file:write_file(filename:join(FixtureDir, "compact.bin"), Compact),

    %% Hold the declaration, kid, and statement fixed; vary only the seed.
    expect_rejected(
        sign_enrollment(Statement, Kid, DeclaredPublicKey, OtherSeed),
        mismatched_seed
    ),
    %% The converse mutation proves the declared-key argument is actually read.
    expect_rejected(
        sign_enrollment(Statement, Kid, OtherPublicKey, Seed),
        mismatched_declaration
    ),

    %% This was the review's exact grammar reproduction: a single version
    %% mutation must be refused before a private key signs it.
    expect_rejected(
        sign_enrollment(InvalidVersion, Kid, DeclaredPublicKey, Seed),
        invalid_profile_version
    ),

    %% Typed Rustler arguments used to make these decoder failures escape the
    %% function as badarg. Term decoding now happens inside the opaque boundary.
    expect_rejected(
        sign_enrollment(not_a_binary, Kid, DeclaredPublicKey, Seed),
        statement_term_decode
    ),
    expect_rejected(
        sign_enrollment(Statement, not_a_binary, DeclaredPublicKey, Seed),
        kid_term_decode
    ),
    expect_rejected(
        sign_enrollment(Statement, Kid, not_a_binary, Seed),
        public_key_term_decode
    ),
    expect_rejected(
        sign_enrollment(Statement, Kid, DeclaredPublicKey, not_a_binary),
        seed_term_decode
    ),
    expect_rejected(
        sign_enrollment(Statement, <<16#ff>>, DeclaredPublicKey, Seed),
        kid_utf8_decode
    ),
    expect_rejected(
        sign_enrollment(Statement, Kid, <<0>>, Seed),
        public_key_binary_decode
    ),
    expect_rejected(
        sign_enrollment(Statement, Kid, DeclaredPublicKey, <<0>>),
        seed_binary_decode
    ),

    %% Sixteen MiB is intentionally far beyond the 4,096-octet pre-allocation
    %% ceiling. The timer starts after BEAM creates the input, so it measures the
    %% NIF refusal. With one scheduler, a regression to JSON-escaping every NUL
    %% monopolises that scheduler and exceeds this generous one-second bound.
    LargeKid = binary:copy(<<0>>, 16 * 1024 * 1024),
    Started = erlang:monotonic_time(microsecond),
    expect_rejected(
        sign_enrollment(Statement, LargeKid, DeclaredPublicKey, Seed),
        oversized_kid
    ),
    Elapsed = erlang:monotonic_time(microsecond) - Started,
    expect_true(Elapsed < 1000000, oversized_kid_scheduler_bound),
    ok.

read(Directory, Name) ->
    {ok, Bytes} = file:read_file(filename:join(Directory, Name)),
    Bytes.

expect_ok({ok, Compact}, _) when is_binary(Compact) ->
    Compact;
expect_ok(_, Label) ->
    erlang:error(Label).

expect_rejected({error, rejected}, _) ->
    ok;
expect_rejected(_, Label) ->
    erlang:error(Label).

expect_true(true, _) ->
    ok;
expect_true(false, Label) ->
    erlang:error(Label).
