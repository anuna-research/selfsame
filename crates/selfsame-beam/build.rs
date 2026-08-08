//! Make Cargo's Darwin cdylib loadable through Erlang's `.so` convention.

fn main() {
    #[cfg(target_os = "macos")]
    println!(
        "cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libcbcl_selfsame_erl.so"
    );
}
