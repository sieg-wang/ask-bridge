//! `install.sh` is what `ask-bridge update` runs, and what it does is overwrite
//! the binary the user then runs. Two properties of that chain are load-bearing
//! and neither was checked anywhere:
//!
//! 1. the release archive is verified against the SHA-256 the release workflow
//!    already publishes beside it (`release.yml`, "Package binary") before the
//!    binary is swapped -- `npm/postinstall.cjs` has always done this for the
//!    same archive, the shell installer did not;
//! 2. the updater does not pipe a downloaded script straight into a shell,
//!    where a body that stops half way through is executed as far as it got and
//!    the pipeline still reports the shell's exit status, not the download's.

const INSTALL_SH: &str = include_str!("../install.sh");

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
    let good = Command::new("shasum")
        .args(["-a", "256"])
        .arg(&archive)
        .output()
        .expect("shasum should be available on unix");
    assert!(good.status.success());
    let digest = String::from_utf8(good.stdout).unwrap();
    let digest = digest.split_whitespace().next().unwrap().to_string();

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

/// `curl ... | bash` hands the shell whatever arrived. A connection that drops
/// half way through delivers half a script, which bash runs as far as it got --
/// and the pipeline's exit status is bash's, so the update reports success.
/// Downloading to a file first makes the failed download the failure.
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
