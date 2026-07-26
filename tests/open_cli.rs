#[cfg(unix)]
#[test]
fn open_does_not_replace_newer_preferences_written_during_startup() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

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
