//! Shared hermeticity helpers for the integration tests.
//!
//! Not a test target of its own (Cargo compiles `tests/common/mod.rs` as a
//! module, not as a binary), so both `open_cli.rs` and `close_cli.rs` include
//! it with `mod common;`.
#![allow(dead_code)]

/// The CDP debug port ask-bridge uses when `ASK_BRIDGE_DEBUG_PORT` is unset.
pub const DEFAULT_DEBUG_PORT: u16 = 9223;

/// Ask the OS for a port nobody is using, then release it.
///
/// WHY every test that spawns the CLI must do this: `start_chrome_if_needed`
/// and `close_ask_chrome_on_debug_port` both ADOPT whatever ask-bridge browser
/// is listening on the debug port — one drives it over CDP, the other TERMs and
/// force-kills it. With the port hardcoded, `cargo test` on a machine where the
/// user's ask-bridge browser is up would do that to THEIR logged-in browser.
/// A private port makes that structurally impossible.
pub fn reserve_debug_port() -> u16 {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("no ephemeral port available");
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Refuse to run if anything is listening on `port`.
///
/// Belt to `reserve_debug_port`'s braces, and it is not redundant: it is the
/// only thing that still fires if the injection regresses (a `9223` literal
/// left behind, the env var renamed) and the child falls back to the default
/// port where the user's real browser is. It converts that regression from a
/// silent, dangerous pass into a named failure.
pub fn assert_debug_port_is_free(port: u16) {
    use std::net::TcpStream;
    use std::time::Duration;
    let addr = format!("127.0.0.1:{port}");
    if TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_millis(500)).is_ok() {
        panic!(
            "REFUSING TO RUN: something is already listening on {addr}, which is \
             a debug port this test's CLI child may use. ask-bridge adopts an \
             existing listener on that port and both drives it over CDP and \
             force-kills it, so continuing would act on a browser that is not \
             ours -- possibly the user's own logged-in one. Stop that listener \
             (`ask-bridge close`) and re-run."
        );
    }
}

/// Whether an external tool this test needs to BUILD its scenario is available.
/// A missing one is an environment gap, not a failure of the code under test,
/// so the caller skips — the same trade-off the repo makes elsewhere for
/// platform tools. It never hides a real failure: without the tool the scenario
/// cannot be constructed at all.
/// A PATH lookup rather than a `--version` probe: `lsof` has no `--version`, so
/// running one and reading its exit status reported the tool as MISSING and
/// silently skipped the test that needed it.
pub fn have_tool(name: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| {
        let candidate = dir.join(name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            candidate
                .metadata()
                .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            candidate.is_file()
        }
    })
}
