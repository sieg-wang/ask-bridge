//! `install.sh` and `install.ps1` are what `ask-bridge update` runs, and what
//! they do is overwrite the binary the user then runs. Two properties of that
//! chain are load-bearing and neither was checked anywhere:
//!
//! 1. the release archive is verified against the SHA-256 the release workflow
//!    already publishes beside it (`release.yml`, "Package binary") before the
//!    binary is swapped -- `npm/postinstall.cjs` has always done this for the
//!    same archive, the shell installer did not;
//! 2. the updater does not pipe a downloaded script straight into a shell,
//!    where a body that stops half way through is executed as far as it got and
//!    the pipeline still reports the shell's exit status, not the download's.
//!
//! There are TWO installers and property 1 was added to one of them first, so
//! read the coverage here as two unequal halves rather than one guarantee:
//!
//! * `install.sh` is covered by an offline end-to-end run
//!   (`install_sh_leaves_the_existing_binary_alone_when_...`) that executes the
//!   real script and inspects the bytes on disk, so disabling the gate in place
//!   is caught;
//! * `install.ps1` is covered by text alone (`install_ps1_*`), because there is
//!   no PowerShell on the machine this was written on. See the comment on
//!   `Assert-ReleaseChecksum` in install.ps1 for the exact mutation that
//!   survives on that side.
//!
//! Property 2 is likewise one-sided: `no_updater_path_pipes_a_download_into_a_
//! shell` forbids `| bash`, and the Windows arm still does `irm ... | iex`,
//! pinned as a known gap rather than fixed.

const INSTALL_SH: &str = include_str!("../install.sh");
const INSTALL_PS1: &str = include_str!("../install.ps1");

/// The digest of `path`, computed the way `install.sh` computes it: `shasum`
/// if it is there, `sha256sum` otherwise.
///
/// Mirroring the installer's own fallback is the point. Hard-requiring
/// `shasum` makes the test stricter than the code it covers, and on a runner
/// that ships only `sha256sum` it fails as though the installer were broken.
#[cfg(unix)]
fn sha256_of(path: &std::path::Path) -> String {
    use std::process::Command;

    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .or_else(|_| Command::new("sha256sum").arg(path).output())
        .expect("one of shasum/sha256sum must exist -- install.sh needs one too");
    assert!(
        output.status.success(),
        "hashing {} failed: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    text.split_whitespace()
        .next()
        .expect("the hashing tool printed no digest")
        .to_string()
}

/// Everything the checksum gate needs, pulled out of the shipped `install.sh`
/// so the test runs the real function body rather than a copy of it.
#[cfg(unix)]
fn shell_function(source: &str, name: &str) -> String {
    let header = format!("\n{name}() {{\n");
    let body = source
        .split_once(&header)
        .unwrap_or_else(|| panic!("install.sh no longer defines {name}()"))
        .1;
    let end = body
        .find("\n}\n")
        .unwrap_or_else(|| panic!("{name}() in install.sh is not brace-balanced at column 0"));
    format!("{name}() {{\n{}\n}}\n", &body[..end])
}

/// A tampered archive -- the shape a mirror, a caching proxy or a truncated
/// body produces -- must not be installed, and a checksum file that is not a
/// checksum must not count as agreement.
#[cfg(unix)]
#[test]
fn install_sh_refuses_an_archive_that_does_not_match_the_published_checksum() {
    use std::io::Write;
    use std::process::Command;

    let dir = tempfile::tempdir().unwrap();
    let archive = dir
        .path()
        .join("ask-bridge-x86_64-unknown-linux-gnu.tar.xz");
    std::fs::write(&archive, b"the real release archive").unwrap();

    // The published checksum, computed the same way the release workflow does.
    let digest = sha256_of(&archive);

    let script = dir.path().join("verify.sh");
    let mut file = std::fs::File::create(&script).unwrap();
    write!(
        file,
        "#!/bin/bash\n{}\nverify_release_checksum \"$1\" \"$2\"\n",
        shell_function(INSTALL_SH, "verify_release_checksum")
    )
    .unwrap();
    drop(file);

    let verify_archive = |archive: &std::path::Path, checksum_body: &str| -> bool {
        let checksum_file = dir.path().join("checksum");
        std::fs::write(&checksum_file, checksum_body).unwrap();
        Command::new("bash")
            .arg(&script)
            .arg(archive)
            .arg(&checksum_file)
            .status()
            .expect("bash should be available on unix")
            .success()
    };
    let verify = |checksum_body: &str| -> bool { verify_archive(&archive, checksum_body) };

    // Positive control first: the real release file, in the exact format the
    // workflow writes ("<hash>  <file>"), still installs.
    assert!(
        verify(&format!(
            "{digest}  ask-bridge-x86_64-unknown-linux-gnu.tar.xz\n"
        )),
        "the published checksum of the real archive was rejected"
    );
    assert!(
        verify(&format!("{}  x\n", digest.to_uppercase())),
        "the workflow's hash is lower-case, but a hex digest is case-insensitive \
         and must not be rejected on case alone"
    );

    for (body, why) in [
        (
            format!("{}  x\n", "0".repeat(64)),
            "a checksum that does not match the archive",
        ),
        (String::new(), "an empty checksum file"),
        (
            "404: Not Found\n".to_string(),
            "an error page saved where the checksum should be",
        ),
        (
            format!("{}  x\n", &digest[..63]),
            "a truncated digest that is a prefix of the right one",
        ),
    ] {
        assert!(
            !verify(&body),
            "the installer accepted {why} and would have overwritten the user's binary"
        );
    }

    // Two unknowns must not compare equal. An archive that cannot be hashed
    // yields an empty digest, and so does a checksum file with nothing in it;
    // a bare string comparison calls that agreement.
    assert!(
        !verify_archive(&dir.path().join("never-downloaded.tar.xz"), ""),
        "an unhashable archive and an empty checksum file were treated as a match"
    );
}

/// The gate is worth nothing after the fact: by the time `tar` has run and the
/// binary has been copied over `$INSTALL_DIR/ask-bridge`, refusing is too late.
#[test]
fn install_sh_verifies_before_it_extracts() {
    let verify = INSTALL_SH
        .find("verify_release_checksum \"$TEMP_DIR/$ARTIFACT_NAME\"")
        .expect("install.sh must check the archive against the published SHA-256");
    let download = INSTALL_SH
        .find("${RELEASE_URL}.sha256")
        .expect("install.sh must download the .sha256 the release workflow publishes");
    let extract = INSTALL_SH
        .find("tar -xJf")
        .expect("install.sh must still extract the archive");

    assert!(
        download < verify && verify < extract,
        "install.sh must download the checksum, then verify, then extract \
         (offsets: download {download}, verify {verify}, extract {extract})"
    );
}

/// The two tests above check the comparison in isolation and the textual order
/// of download/verify/extract. Neither notices whether a failed verification
/// still *stops* the installer: turning the `exit 1` at the call site into a
/// warning leaves both of them green. This one runs the shipped `install.sh`
/// end to end -- `curl`, `node`, `npx` and `uname` stubbed, so no network, no
/// browser and no Homebrew -- and looks at the binary that ends up on disk.
///
/// The archive the stubbed download hands over is a *valid* `tar.xz` carrying a
/// different binary, because that is the shape of a swapped release. A merely
/// corrupt file would be rejected by `tar` even with the checksum gate deleted,
/// and this test would then pass for a reason that has nothing to do with the
/// gate.
#[cfg(unix)]
#[test]
fn install_sh_leaves_the_existing_binary_alone_when_the_published_checksum_does_not_match() {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    const GENUINE: &[u8] = b"#!/bin/sh\n# the genuine release binary\n";
    const TAMPERED: &[u8] = b"#!/bin/sh\n# TAMPERED payload\n";
    const PREEXISTING: &[u8] = b"the binary the user already has";

    let dir = tempfile::tempdir().unwrap();
    let stubs = dir.path().join("stubs");
    std::fs::create_dir_all(&stubs).unwrap();
    let write_stub = |name: &str, body: &str| {
        let file = stubs.join(name);
        std::fs::write(&file, body).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
    };

    // Serves whichever file the two environment variables point at. Written to
    // accept the flags in any order so that changing `curl -fL x -o y` does not
    // by itself turn this test green or red.
    write_stub(
        "curl",
        r#"#!/bin/bash
url=""; out=""
while [ $# -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
case "$url" in
    *.sha256) cp "$SERVED_CHECKSUM" "$out" ;;
    *) cp "$SERVED_ARCHIVE" "$out" ;;
esac
"#,
    );
    // install.sh only asks whether these two exist.
    write_stub("node", "#!/bin/bash\nexit 0\n");
    write_stub("npx", "#!/bin/bash\nexit 0\n");
    // Pin the platform. The Darwin arm shells out to Homebrew when Chrome is
    // missing; the Linux arm only warns, which is what a test may do.
    write_stub(
        "uname",
        "#!/bin/bash\ncase \"$1\" in\n    -m) echo x86_64 ;;\n    *) echo Linux ;;\nesac\n",
    );

    // Two releases under the same name: the one whose checksum was published,
    // and the one the download actually delivers.
    let archive = |name: &str, payload: &[u8]| -> PathBuf {
        let stage = dir.path().join(format!("stage-{name}"));
        std::fs::create_dir_all(&stage).unwrap();
        std::fs::write(stage.join("ask-bridge"), payload).unwrap();
        let out = dir.path().join(format!("{name}.tar.xz"));
        let built = Command::new("tar")
            .arg("-cJf")
            .arg(&out)
            .arg("-C")
            .arg(&stage)
            .arg("ask-bridge")
            .status()
            .expect("tar should be available on unix")
            .success();
        assert!(built, "could not build the {name} test archive");
        out
    };
    let genuine = archive("genuine", GENUINE);
    let tampered = archive("tampered", TAMPERED);

    let published = dir.path().join("genuine.sha256");
    let digest = sha256_of(&genuine);
    std::fs::write(
        &published,
        format!("{digest}  ask-bridge-x86_64-unknown-linux-gnu.tar.xz\n"),
    )
    .unwrap();

    let home = dir.path().join("home");
    let installed = home.join(".local").join("bin").join("ask-bridge");
    let run = |served: &Path| -> (bool, Vec<u8>, String) {
        std::fs::create_dir_all(installed.parent().unwrap()).unwrap();
        std::fs::write(&installed, PREEXISTING).unwrap();
        let out = Command::new("bash")
            .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/install.sh"))
            .env(
                "PATH",
                format!("{}:{}", stubs.display(), std::env::var("PATH").unwrap()),
            )
            .env("HOME", &home)
            // Keep the installer's own `mktemp -d` inside the test's tempdir.
            .env("TMPDIR", dir.path())
            .env("SERVED_ARCHIVE", served)
            .env("SERVED_CHECKSUM", &published)
            .output()
            .expect("bash should be available on unix");
        (
            out.status.success(),
            std::fs::read(&installed).unwrap(),
            String::from_utf8_lossy(&out.stdout).to_string()
                + &String::from_utf8_lossy(&out.stderr),
        )
    };

    // Positive control first. Without it, an installer that fell over on one of
    // the stubs would "refuse" the tampered archive for a reason that has
    // nothing to do with the checksum.
    let (ok, bytes, log) = run(&genuine);
    assert!(ok, "the genuine release was not installed:\n{log}");
    assert_eq!(bytes, GENUINE, "the genuine release was not what landed");

    let (ok, bytes, log) = run(&tampered);
    assert!(
        !ok,
        "install.sh reported success after being handed an archive that does \
         not match the published checksum:\n{log}"
    );
    assert_ne!(
        bytes, TAMPERED,
        "install.sh overwrote the user's binary with the tampered payload"
    );
    assert_eq!(
        bytes, PREEXISTING,
        "the binary the user already had did not survive the refusal"
    );
}

/// `install.ps1` with its comments removed, so the assertions below read the
/// script and not the prose describing it. This is load-bearing rather than
/// tidy: the comment on the call site names `Expand-Archive`, which by itself
/// is enough to invert the ordering test.
///
/// Whole comment lines only -- and then it *checks* that no `#` is left, so the
/// day someone writes a trailing `# ...` this panics instead of quietly letting
/// comment text be counted as code.
fn powershell_code(source: &str) -> String {
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !code.contains('#'),
        "install.ps1 now uses `#` outside a whole-line comment, which this \
         stripper cannot tell from code -- teach it before trusting it"
    );
    code
}

/// The body of `function <name> { ... }` in the shipped `install.ps1`,
/// delimited the way the file is written: a top-level function's closing brace
/// is the only `}` at column 0 after its header. Panics rather than returning
/// an empty body, so a renamed or re-indented function cannot make the
/// assertions below vacuously true.
fn powershell_function(source: &str, name: &str) -> String {
    let header = format!("\nfunction {name} {{\n");
    let body = source
        .split_once(&header)
        .unwrap_or_else(|| panic!("install.ps1 no longer defines function {name}"))
        .1;
    let end = body.find("\n}\n").unwrap_or_else(|| {
        panic!("function {name} in install.ps1 is not brace-balanced at column 0")
    });
    body[..end].to_string()
}

/// The Windows half of the same gate. Until 2026-08-14 `install.ps1` had no
/// checksum check of any kind -- `grep -inE 'hash|digest|sha' install.ps1`
/// returned nothing -- while `install.sh` had one, so a guarantee that read as
/// "the installer verifies the release" held on exactly one of the two
/// platforms `ask-bridge update` installs on.
///
/// Verifying after `Expand-Archive` has run and the binaries have been copied
/// over `$InstallDir` is not a refusal, so the order is part of the property.
#[test]
fn install_ps1_verifies_the_published_checksum_before_it_extracts() {
    let code = powershell_code(INSTALL_PS1);
    let archive = code
        .find("Invoke-WebRequest -Uri $ReleaseUrl -OutFile $ZipPath")
        .expect("install.ps1 must still download the release archive");
    let checksum = code
        .find("\"${ReleaseUrl}.sha256\"")
        .expect("install.ps1 must download the .sha256 the release workflow publishes");
    let verify = code
        .find("Assert-ReleaseChecksum -Archive")
        .expect("install.ps1 must check the archive against the published SHA-256");
    let extract = code
        .find("Expand-Archive")
        .expect("install.ps1 must still extract the archive");

    assert!(
        archive < verify && checksum < verify && verify < extract,
        "install.ps1 must download the archive and its checksum, then verify, \
         then extract (offsets: archive {archive}, checksum {checksum}, \
         verify {verify}, extract {extract})"
    );
}

/// A verification that prints and carries on is not a verification. This looks
/// at the gate's body for the two shapes that make it one -- reject the digest
/// on format *before* comparing it, and `throw` on both branches -- because the
/// ordering test above cannot see either.
///
/// Text only, and deliberately not dressed up as more: no PowerShell exists on
/// the machine this was written on, so `install.sh`'s trick of executing the
/// real installer against stubbed downloads has no counterpart here. A mutation
/// that keeps the text and disables the effect (`if ($false -and $actual -ne
/// $expected)`) satisfies every assertion below.
#[test]
fn install_ps1_checksum_gate_refuses_instead_of_warning() {
    let body = powershell_function(&powershell_code(INSTALL_PS1), "Assert-ReleaseChecksum");

    assert!(
        body.contains("Get-FileHash") && body.contains("SHA256"),
        "install.ps1 no longer hashes the archive it is about to install:\n{body}"
    );
    assert!(
        body.contains("$actual -ne $expected"),
        "install.ps1 no longer compares the archive's digest with the published \
         one:\n{body}"
    );
    // An empty checksum file, a truncated digest and a "404: Not Found" page
    // saved where the checksum should be all have to fail on shape, before the
    // comparison: "" -eq "" is the one way two unknowns compare equal.
    assert!(
        body.contains("-notmatch '^[a-f0-9]{64}$'"),
        "install.ps1 no longer requires the published checksum to *be* a SHA-256 \
         before trusting a match:\n{body}"
    );
    assert!(
        body.matches("throw").count() >= 2,
        "both the malformed-checksum branch and the mismatch branch must end the \
         install; one of them no longer throws:\n{body}"
    );
    for spelling in ["Write-Host", "Write-Warning", "Write-Error", "return"] {
        assert!(
            !body.contains(spelling),
            "the checksum gate reports a failure with `{spelling}` instead of \
             refusing, so install.ps1 would carry on and overwrite the user's \
             binary with the archive it just rejected:\n{body}"
        );
    }
}

/// `curl ... | bash` hands the shell whatever arrived. A connection that drops
/// half way through delivers half a script, which bash runs as far as it got --
/// and the pipeline's exit status is bash's, so the update reports success.
/// Downloading to a file first makes the failed download the failure.
///
/// This covers the Unix spelling only. The Windows arm is still
/// `irm ... | iex`; see
/// `known_gap_the_windows_updater_pipes_the_installer_into_powershell`.
#[test]
fn no_updater_path_pipes_a_download_into_a_shell() {
    for (name, source) in [
        ("src/main.rs", include_str!("../src/main.rs")),
        ("src/update.rs", include_str!("../src/update.rs")),
    ] {
        // Whole comment lines are dropped, because the code has to be allowed
        // to *describe* the pipe it no longer uses. Only whole lines: cutting
        // every line at its first `//` would also cut the `https://` inside a
        // string literal, and a re-introduced `"curl https://x | bash"` would
        // then hide behind its own URL.
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !code.contains("| bash"),
            "{name} still pipes a downloaded installer straight into a shell"
        );
    }
}

/// Known gap, disclosed rather than closed: on Windows `ask-bridge update`
/// still runs `powershell -NoProfile -Command "irm .../install.ps1 | iex"`
/// (src/update.rs and the inline fallback in src/main.rs). That is the same
/// pattern the test above forbids -- a body that stops half way through is
/// executed as far as it got, and the exit status reported is PowerShell's,
/// not the download's -- and the checksum `Assert-ReleaseChecksum` now verifies
/// says nothing about it, because it covers the *archive* that script fetches,
/// not the script.
///
/// Not closed here for one reason, stated plainly: the replacement is
/// PowerShell that downloads to a file and runs the file, and there is no
/// PowerShell on the machine this was written on to run it even once. Shipping
/// an unrun rewrite of the update path is worse than shipping a pinned gap.
///
/// This asserts today's behaviour so it cannot change unnoticed in either
/// direction. A failure means the gap was closed -- rewrite this test and move
/// `| iex` into `no_updater_path_pipes_a_download_into_a_shell` beside
/// `| bash`; do not delete it.
#[test]
fn known_gap_the_windows_updater_pipes_the_installer_into_powershell() {
    for (name, source) in [
        ("src/main.rs", include_str!("../src/main.rs")),
        ("src/update.rs", include_str!("../src/update.rs")),
    ] {
        let code: String = source
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            code.contains("install.ps1 | iex"),
            "{name} no longer pipes the Windows installer into PowerShell -- \
             the gap this test exists to disclose is closed, so rewrite it to \
             forbid `| iex` rather than deleting it"
        );
    }
}
