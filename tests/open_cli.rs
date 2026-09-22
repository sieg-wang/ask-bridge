mod common;
use common::{DEFAULT_DEBUG_PORT, assert_debug_port_is_free, reserve_debug_port};

#[cfg(unix)]
#[test]
fn open_does_not_replace_newer_preferences_written_during_startup() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    let debug_port = reserve_debug_port();
    assert_debug_port_is_free(DEFAULT_DEBUG_PORT);
    assert_debug_port_is_free(debug_port);

    let home = tempfile::tempdir().unwrap();
    let default_dir = home
        .path()
        .join(".config/ask-bridge/chrome-profile/Default");
    std::fs::create_dir_all(&default_dir).unwrap();
    let preferences = default_dir.join("Preferences");
    let padding = "x".repeat(64 * 1024 * 1024);
    std::fs::write(
        &preferences,
        serde_json::to_vec(&serde_json::json!({
            "profile": {"exit_type": "Crashed"},
            "padding": padding,
            "generation": "old"
        }))
        .unwrap(),
    )
    .unwrap();

    let watched_dir = default_dir.clone();
    let watched_preferences = preferences.clone();
    let watched_launched = home.path().join("browser-launched");
    let writer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            let staging_exists = std::fs::read_dir(&watched_dir)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".Preferences.askbridge.tmp.")
                });
            if staging_exists || watched_launched.exists() {
                let successor = watched_dir.join("Preferences.browser-successor");
                std::fs::write(
                    &successor,
                    r#"{"profile":{"exit_type":"Crashed"},"generation":"browser-newer","keep":42}"#,
                )
                .unwrap();
                std::fs::rename(successor, &watched_preferences).unwrap();
                return true;
            }
            thread::sleep(Duration::from_millis(1));
        }
        false
    });

    let browser = home.path().join("fake-browser");
    let launched = home.path().join("browser-launched");
    std::fs::write(
        &browser,
        format!("#!/bin/sh\n: > '{}'\nexit 0\n", launched.display()),
    )
    .unwrap();
    let mut mode = std::fs::metadata(&browser).unwrap().permissions();
    mode.set_mode(0o755);
    std::fs::set_permissions(&browser, mode).unwrap();

    let binary = env!("CARGO_BIN_EXE_ask-bridge");
    let mut cli = Command::new(binary)
        .args(["--browser", browser.to_str().unwrap(), "open"])
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        // The durable half of the hermeticity fix: the child probes, launches
        // on and closes THIS port, so no listener anywhere else on the machine
        // can be adopted by a test run.
        .env("ASK_BRIDGE_DEBUG_PORT", debug_port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(15);
    while !launched.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    let _ = cli.kill();
    let _ = cli.wait();

    assert!(
        launched.exists(),
        "public open seam never launched the browser"
    );
    assert!(
        writer.join().unwrap(),
        "did not observe Preferences staging or browser launch"
    );
    let current: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&preferences).unwrap()).unwrap();
    assert_eq!(current["generation"], "browser-newer");
    assert_eq!(current["keep"], 42);
}

/// The file the guard reads, and the name it reports, so a failure names the
/// file a human has to edit rather than just a line number.
const PORT_SOURCE_PATH: &str = "src/main.rs";

/// The one line that is allowed to name the port number.
const PORT_DECLARATION: &str = "const DEFAULT_DEBUG_PORT: u16 = 9223;";

/// Every line of `src` (labelled `path`) that names the default debug port
/// somewhere it could act as a port-bearing literal, reported as
/// `path:line: text`.
///
/// It never truncates a line. Exactly two exemptions, and both are decided on
/// the WHOLE line: the single port declaration, and a line that is nothing but
/// a comment.
///
/// WHY not "strip the comment, then scan what is left": that is what the first
/// version did, by cutting each line at its first "//" — and "//" appears in
/// far more than comments. The first of the 25 port sites,
/// "--browser-url=http://127.0.0.1:9223", carries one inside a string literal
/// four characters left of the digits, so the scan ended before reaching them
/// and the guard reported ok with the hermeticity hole reopened. Deciding
/// "comment or code" at an arbitrary column needs a Rust lexer — escapes, raw
/// strings (src/main.rs has multi-line ones full of "//"), the '"' and '\''
/// char literals it also has, nested block comments — and every gap in a
/// hand-rolled lexer is a SILENT PASS: the same bug class again with a longer
/// fuse. Special-casing "http://" would be worse still, since the next
/// unlisted shape wins.
///
/// So this scans the entire line and exempts only whole lines. That needs no
/// lexer, because a Rust line whose first non-whitespace characters are "//"
/// cannot also contain code. Everything else is scanned in full: a trailing
/// comment, a block comment, prose inside a multi-line string. Those can raise
/// a false alarm, which a human answers by not spelling the number there; a
/// missed literal would silently hand a test the user's real browser.
///
/// The underscore strip is the same argument applied to the digits: to rustc,
/// 9_223 and 9223 are one literal, and rustfmt and clippy accept both.
fn bare_port_literal_offenders(path: &str, src: &str) -> Vec<String> {
    let mut offenders = Vec::new();
    for (index, line) in src.lines().enumerate() {
        let trimmed = line.trim();
        // A whole-line comment may name the port; nothing else may.
        if trimmed.starts_with("//") || trimmed == PORT_DECLARATION {
            continue;
        }
        if line.replace('_', "").contains("9223") {
            offenders.push(format!("{path}:{}: {}", index + 1, trimmed));
        }
    }
    offenders
}

/// The half of `src/main.rs` that ships inside the binary.
fn production_source() -> &'static str {
    include_str!("../src/main.rs")
        .split_once("\n#[cfg(test)]\n")
        .expect("src/main.rs no longer has a #[cfg(test)] block to split on")
        .0
}

/// A partial port substitution is worse than none: the CLI would launch the
/// browser with `--remote-debugging-port=<injected>` and then probe 9223 (or
/// the reverse), so `open` would hang and `close` would refuse to act. This
/// test reads the source and fails if a bare port literal reappears in the
/// port-bearing code, which is the only mistake that reintroduces the
/// hermeticity hole without any other test noticing.
#[test]
fn the_debug_port_is_read_from_one_place() {
    let production = production_source();
    let offenders = bare_port_literal_offenders(PORT_SOURCE_PATH, production);

    assert!(
        offenders.is_empty(),
        "bare 9223 literal(s) back in port-bearing code — every site must go \
         through debug_port()/debug_addr() or the CLI launches on one port and \
         probes another:\n{}",
        offenders.join("\n")
    );

    // Negative control on the real input rather than a fixture: a scanner that
    // has stopped seeing src/main.rs at all — a moved file, a #[cfg(test)]
    // split that swallowed the whole body, a match that can no longer fire —
    // reports zero offenders too, and would report ok forever.
    let relapsed = format!("{production}\n    let port = 9223;\n");
    assert!(
        !bare_port_literal_offenders(PORT_SOURCE_PATH, &relapsed).is_empty(),
        "the guard reported nothing for a source that definitely contains a \
         bare port literal, so its green above proves nothing"
    );
}

/// A test for the GUARD, because the guard's first version reported ok on
/// precisely the mistake it exists to catch.
///
/// It stripped line comments by truncating at the first "//", and "//" lives in
/// far more places than comments. The first of the 25 port sites,
/// "--browser-url=http://127.0.0.1:9223", carries one inside a string literal
/// four characters to the left of the digits, so the scan ended before it ever
/// reached them: 24 sites covered, and the one missed was the exact
/// partial-substitution shape the guard exists to prevent.
#[test]
fn the_port_guard_reports_a_literal_whose_line_also_contains_a_url() {
    // Line 1 is the pre-AB-A1 text of src/main.rs:1508, verbatim. Line 2 is the
    // shape the broken guard did catch, kept as an in-fixture control. Line 3
    // is the same literal spelled the way rustfmt and clippy accept without
    // comment: to rustc, 9_223 and 9223 are one literal. Line 4 carries a
    // genuine comment that is not alone on its line, and is deliberately an
    // offender — the guard never decides "comment or code" mid-line.
    let fixture = r#"        "--browser-url=http://127.0.0.1:9223".to_string(),
    let stream = TcpStream::connect("127.0.0.1:9223"); // adopt whatever answers
        mcp_args.push(format!("--browser-url=http://127.0.0.1:{}", 9_223));
    let port = debug_port(); // was 9223 before ASK_BRIDGE_DEBUG_PORT existed
"#;

    assert_eq!(
        bare_port_literal_offenders(PORT_SOURCE_PATH, fixture),
        vec![
            r#"src/main.rs:1: "--browser-url=http://127.0.0.1:9223".to_string(),"#.to_string(),
            r#"src/main.rs:2: let stream = TcpStream::connect("127.0.0.1:9223"); // adopt whatever answers"#
                .to_string(),
            r#"src/main.rs:3: mcp_args.push(format!("--browser-url=http://127.0.0.1:{}", 9_223));"#
                .to_string(),
            r#"src/main.rs:4: let port = debug_port(); // was 9223 before ASK_BRIDGE_DEBUG_PORT existed"#
                .to_string(),
        ],
        "the guard must name the file and the line of every port literal it \
         finds, including one whose line also contains a // that is not a \
         comment"
    );
}

/// The other half of the contract, or the guard above is satisfiable by
/// flagging every line that mentions the number: what it must leave alone.
///
/// Exactly two exemptions. The single port declaration, and a line that is
/// ENTIRELY a comment — "//", "///" or "//!" as its first non-whitespace
/// characters. Prose may keep naming the number, and a URL that contains it,
/// because a Rust line whose first token starts with "//" cannot also hold
/// code; that is decidable without lexing string literals, which is what the
/// broken version got wrong.
#[test]
fn the_port_guard_leaves_the_declaration_and_whole_line_comments_alone() {
    let fixture = r#"const DEFAULT_DEBUG_PORT: u16 = 9223;
/// Waits until the browser is listening on port 9223 before returning.
    // Port 9223 is only the default; ASK_BRIDGE_DEBUG_PORT overrides it.
//! Talks CDP to http://127.0.0.1:9223 unless that env var says otherwise.
"#;

    let offenders = bare_port_literal_offenders(PORT_SOURCE_PATH, fixture);
    assert!(
        offenders.is_empty(),
        "the guard flagged the one allowed declaration or a line that is \
         nothing but a comment:\n{}",
        offenders.join("\n")
    );
}
