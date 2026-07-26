use std::process::{Command, Stdio};

#[test]
fn concurrent_config_commands_preserve_each_others_fields() {
    let home = tempfile::tempdir().unwrap();
    let config_dir = home.path().join(".config/ask-bridge");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_path = config_dir.join("config.json");

    // Keep both CLI processes inside the same read/merge/write window long
    // enough to exercise the lost-update race deterministically.
    let padding = "x".repeat(16 * 1024 * 1024);
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({ "keep": padding })).unwrap(),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_ask-bridge");
    let mut provider = Command::new(binary)
        .args(["config", "--provider", "gemini"])
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut browser = Command::new(binary)
        .args(["config", "--browser", binary])
        .env("HOME", home.path())
        .env("USERPROFILE", home.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let provider_status = provider.wait().unwrap();
    let browser_status = browser.wait().unwrap();
    assert!(provider_status.success(), "provider command failed");
    assert!(browser_status.success(), "browser command failed");

    let config: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(config_path).unwrap()).unwrap();
    assert_eq!(
        config["provider"], "gemini",
        "a concurrent browser update lost the provider update"
    );
    assert_eq!(
        config["browser"], binary,
        "a concurrent provider update lost the browser update"
    );
    assert_eq!(config["keep"].as_str().unwrap().len(), padding.len());
}
