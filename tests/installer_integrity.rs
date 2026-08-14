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
    let digest = Command::new("shasum")
        .args(["-a", "256"])
        .arg(&genuine)
        .output()
        .expect("shasum should be available on unix");
    assert!(digest.status.success());
    let digest = String::from_utf8(digest.stdout).unwrap();
    let digest = digest.split_whitespace().next().unwrap();
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
