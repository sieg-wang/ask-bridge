mod common;
use common::{DEFAULT_DEBUG_PORT, assert_debug_port_is_free, have_tool, reserve_debug_port};

#[cfg(unix)]
mod stub {
    use std::process::{Child, Command, Stdio};

    /// A stand-in for a HUNG ask-bridge browser: it holds a listener on the
    /// debug port, carries `--ask-bridge-instance` in its argv so the real
    /// process probes classify it as ask-bridge's own Chrome, and IGNORES
    /// SIGTERM. That last part is the whole scenario — a browser that answers
    /// TERM needs no escalation.
    ///
    /// The listener socket is held by THIS process rather than a child, so the
    /// PID `lsof` reports is the same PID whose command line carries the marker.
    /// A child holding the socket would survive its parent's death and keep the
    /// port wedged, which would test the harness instead of the code.
    ///
    /// It gets its own process group so teardown can signal the whole subtree
    /// and can never reach a process this test did not spawn.
    pub fn spawn_hung_browser(port: u16) -> Child {
        use std::os::unix::process::CommandExt;
        // It must ACCEPT, not merely listen: ask-bridge polls the port with a
        // fresh connect every 100ms and never reads, so an unaccepted backlog
        // fills and the kernel starts refusing — which the poll reads as "the
        // port closed". A stub that only listens therefore tests the backlog,
        // not the escalation (observed: `close` reported "Debug port closed, but
        // browser process(es) N are still running").
        let code = "\
import signal, socket, sys, threading, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', int(sys.argv[2])))
s.listen(64)

def drain():
    while True:
        try:
            conn, _ = s.accept()
            conn.close()
        except OSError:
            return

threading.Thread(target=drain, daemon=True).start()
sys.stderr.write('ready\\n')
sys.stderr.flush()
time.sleep(120)
";
        Command::new("python3")
            .arg("-c")
            .arg(code)
            // Argv the probes read. The marker must be a whitespace-delimited
            // argument, which is what `command_has_argument` requires.
            .arg("--ask-bridge-instance")
            .arg(port.to_string())
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("could not spawn the hung-browser stub")
    }

    /// Unconditional teardown: SIGKILL the stub's own process group. Runs even
    /// when the assertions have already failed, so a failing run never leaks a
    /// process that keeps the port wedged for the next one.
    pub fn force_teardown(child: &mut Child) {
        let pgid = child.id();
        assert!(pgid > 1, "refusing to signal process group {pgid}");
        let _ = Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{pgid}")])
            .status();
        let _ = child.kill();
        let _ = child.wait();
    }

    pub fn wait_until_listening(port: u16) -> bool {
        use std::net::TcpStream;
        use std::time::{Duration, Instant};
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    pub fn port_is_closed(port: u16) -> bool {
        use std::net::TcpStream;
        use std::time::{Duration, Instant};
        let addr: std::net::SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

/// AB-A3: `ask-bridge close` must be able to end a HUNG browser on macOS/Linux,
/// not only on Windows.
///
/// The graceful-TERM-then-escalate path existed, but the escalation block was
/// `#[cfg(target_os = "windows")]` and its identity helpers were
/// `#[cfg(any(target_os = "windows", test))]`. So on macOS a browser that
/// ignores SIGTERM left the debug port wedged until a human ran `kill -9` by
/// hand — and, worse for a review, the ten unit assertions covering
/// `validated_force_kill_pids` / `snapshot_shows_browser_gone` compiled into the
/// test binary on macOS while the shipped macOS binary contained no code path
/// they could influence. Green tests, absent feature.
///
/// This test drives the REAL binary on its own ephemeral port, so it exercises
/// the shipped macOS path and can never touch a browser it did not spawn.
#[cfg(unix)]
#[test]
fn close_force_kills_a_browser_that_ignores_sigterm() {
    use std::process::Command;
    use std::time::Instant;

    if !have_tool("python3") {
        eprintln!("SKIP: python3 is needed to build the hung-browser stub");
        return;
    }
    if !have_tool("lsof") {
        eprintln!("SKIP: lsof is how ask-bridge identifies the port's owner");
        return;
    }

    let port = reserve_debug_port();
    assert_debug_port_is_free(DEFAULT_DEBUG_PORT);
    assert_debug_port_is_free(port);

    let home = tempfile::tempdir().unwrap();
    let mut hung = stub::spawn_hung_browser(port);
    let hung_pid = hung.id().to_string();

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(
            stub::wait_until_listening(port),
            "the stub never took the port, so this test cannot observe anything"
        );

        let started = Instant::now();
        let out = Command::new(env!("CARGO_BIN_EXE_ask-bridge"))
            .arg("close")
            .env("HOME", home.path())
            .env("USERPROFILE", home.path())
            .env("ASK_BRIDGE_DEBUG_PORT", port.to_string())
            .output()
            .unwrap();
        let elapsed = started.elapsed();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();

        assert!(
            out.status.success(),
            "`close` failed against a browser that ignores SIGTERM after {:?}.\n\
             stdout: {stdout}\nstderr: {stderr}\n\
             On macOS/Linux there is no force-kill escalation, so the graceful \
             poll times out and the debug port stays wedged until a human runs \
             kill -9.",
            elapsed
        );
        assert!(
            stdout.contains("Closed ask-bridge Chrome browser instance"),
            "close reported something other than a close: {stdout:?} {stderr:?}"
        );
        assert!(
            stub::port_is_closed(port),
            "close returned success but the debug port is still accepting \
             connections, so the next `open` still cannot use it"
        );
    }));

    stub::force_teardown(&mut hung);
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }

    // Only meaningful once the assertions above have passed: `close` itself must
    // have ended the process, not the teardown.
    assert!(
        !process_exists(&hung_pid),
        "the hung browser process {hung_pid} outlived a successful close"
    );
}

#[cfg(unix)]
fn process_exists(pid: &str) -> bool {
    std::process::Command::new("ps")
        .args(["-p", pid])
        .output()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .skip(1)
                .any(|line| !line.trim().is_empty())
        })
        .unwrap_or(false)
}

/// The escalation must be gated on the IDENTITY proofs, not on the port poll.
///
/// A force kill that fires because "the port is still open" would send SIGKILL
/// to whatever PID the pre-TERM snapshot recorded — and between that snapshot
/// and the signal the browser may have exited and the kernel may have handed the
/// number to an unrelated process. That is the one way this fix could be worse
/// than the wedged port it replaces, so the guards are pinned as source
/// structure: no `-KILL` / `taskkill /F` may be issued from a list that was not
/// produced by `validated_force_kill_pids`.
#[test]
fn the_force_kill_is_reachable_only_through_the_revalidated_pid_list() {
    let src = include_str!("../src/main.rs");
    let (production, _tests) = src
        .split_once("\n#[cfg(test)]\n")
        .expect("src/main.rs no longer has a #[cfg(test)] block to split on");

    // The re-validation helpers must be compiled on every platform, not only
    // under `cfg(windows, test)` -- that combination is exactly what let ten
    // green assertions cover code the macOS binary did not contain.
    for helper in [
        "fn validated_force_kill_pids",
        "fn snapshot_shows_browser_gone",
        "fn same_pid_set",
    ] {
        let at = production
            .find(helper)
            .unwrap_or_else(|| panic!("{helper} is gone"));
        let preceding = &production[at.saturating_sub(200)..at];
        assert!(
            !preceding.contains("target_os = \"windows\""),
            "{helper} is still gated to Windows, so the non-Windows escalation \
             it is supposed to validate cannot call it"
        );
    }

    // The force kill must exist at exactly ONE site, and that site must be the
    // one that re-reads each PID's identity immediately before signalling.
    // Counting the sites is the point: a second, unvalidated `-KILL` added
    // later is the regression this test exists to catch, and no behavioural
    // test can see it until it fires on the wrong process.
    let kill_sites: Vec<(usize, &str)> = production
        .lines()
        .enumerate()
        .filter(|(_, line)| {
            let code = line.split("//").next().unwrap_or("");
            code.contains("\"-KILL\"") || code.contains("\"/F\"")
        })
        .map(|(index, line)| (index + 1, line.trim()))
        .collect();
    assert_eq!(
        kill_sites.len(),
        2,
        "expected exactly two force-kill lines (the POSIX and Windows arms of \
         signal_validated_ask_pids); found {kill_sites:?}"
    );

    let signaller = production
        .find("fn signal_validated_ask_pids")
        .expect("the validated signaller is gone, so nothing re-checks identity");
    let body_end = production[signaller..]
        .find("\nfn ")
        .map(|offset| signaller + offset)
        .unwrap_or(production.len());
    let signaller_body = &production[signaller..body_end];
    for (line_no, line) in &kill_sites {
        assert!(
            signaller_body.contains(line),
            "force kill at line {line_no} is outside signal_validated_ask_pids, \
             so nothing re-reads the PID's command line before SIGKILL: {line}"
        );
    }
    assert!(
        signaller_body.contains("command_identifies_ask_chrome"),
        "signal_validated_ask_pids no longer re-checks identity before signalling"
    );

    // And the only caller allowed to ask for Force must be fed by the
    // re-validated list, never by the pre-TERM snapshot.
    for (index, line) in production.lines().enumerate() {
        if !line.contains("AskChromeSignal::Force") || line.contains("=>") {
            continue;
        }
        assert!(
            line.contains("force_kill_pids"),
            "a force-kill call at line {} is fed by something other than \
             validated_force_kill_pids: {}",
            index + 1,
            line.trim()
        );
    }
}
