//! The six places the release version is written by hand (AGENTS.md,
//! "版本更新必須同步修改的 6 個檔案") must all agree with `Cargo.toml`.
//!
//! Drift is silent in the worst direction. `install.sh` and `install.ps1` are
//! what `ask-bridge update` pipes into a shell (`run_update_command` in
//! src/main.rs, and src/update.rs), so a stale `VERSION` there downloads the
//! *previous* release, prints "Successfully installed!" and exits 0 -- leaving
//! the user on an old binary with no warning anywhere in the chain. Nothing
//! downstream catches it either: the release smoke test only matches
//! `--version` against `^ask-bridge \d+\.\d+\.\d+`, never against the git tag,
//! so a stale `#[command(version)]` ships a release that misreports itself to
//! every user. Only `package.json` self-heals, because npm-publish.yml runs
//! `npm version` against the tag.

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn every_hand_written_version_matches_cargo_toml() {
    // Anti-tautology: `env!` is only worth comparing the other five against if
    // it really came from `[package]`, so pin the line it was read from first.
    let cargo_toml = include_str!("../Cargo.toml").replace("\r\n", "\n");
    assert!(
        cargo_toml.contains(&format!("\nversion = \"{VERSION}\"\n")),
        "Cargo.toml [package] no longer carries `version = \"{VERSION}\"`"
    );

    let sites = [
        (
            "package.json",
            include_str!("../package.json"),
            format!("\"version\": \"{VERSION}\""),
        ),
        (
            "src/main.rs",
            include_str!("../src/main.rs"),
            format!("#[command(version = \"{VERSION}\")]"),
        ),
        (
            "install.sh",
            include_str!("../install.sh"),
            format!("VERSION=\"{VERSION}\""),
        ),
        (
            "install.ps1",
            include_str!("../install.ps1"),
            format!("$Version = \"{VERSION}\""),
        ),
        (
            "scripts/ask.sh",
            include_str!("../scripts/ask.sh"),
            format!("VERSION=\"{VERSION}\""),
        ),
    ];

    for (name, source, needle) in sites {
        assert!(
            source.replace("\r\n", "\n").contains(&needle),
            "{name} does not carry `{needle}`. `ask-bridge update` runs \
             install.sh, so a stale VERSION there silently reinstalls the \
             previous release and reports success."
        );
    }
}
