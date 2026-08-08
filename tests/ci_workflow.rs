fn validate_windows_ci_contract(workflow: &str) -> Result<(), String> {
    let mut lines = workflow.lines();
    let header = "  windows-installer:";
    lines
        .find(|line| *line == header)
        .ok_or_else(|| "missing windows-installer job".to_string())?;
    let job: Vec<&str> = lines
        .take_while(|line| line.trim().is_empty() || line.starts_with("    "))
        .collect();

    if !job
        .iter()
        .any(|line| line.trim() == "runs-on: windows-latest")
    {
        return Err("windows-installer must use a Windows runner".to_string());
    }

    let rust = job
        .iter()
        .position(|line| line.trim() == "- uses: dtolnay/rust-toolchain@stable")
        .ok_or_else(|| "the Windows job must install Rust".to_string())?;
    let tests = job
        .iter()
        .position(|line| line.trim() == "- run: cargo test --locked")
        .ok_or_else(|| "the Windows job must run the locked Rust test suite".to_string())?;
    if rust >= tests {
        return Err("the Windows job must install Rust before running tests".to_string());
    }

    Ok(())
}

const CLIPBOARD_CONTRACT_ITEMS: [&str; 5] = [
    "fn the_clipboard_transaction_is_exclusive_across_processes()",
    "fn clipboard_lock_rejects_a_leaf_symlink_swapped_in_after_inspection()",
    "fn the_clipboard_lock_is_held_for_the_whole_transaction()",
    "fn the_clipboard_lock_is_held_continuously_not_re_taken_per_step()",
    "fn lock_clipboard_in(dir: &Path, wait: Duration)",
];

fn validate_item_is_compiled_on_windows(source: &str, item: &str) -> Result<(), String> {
    let lines: Vec<&str> = source.lines().collect();
    let matches: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| line.trim_start().starts_with(item).then_some(index))
        .collect();
    let [item_line] = matches.as_slice() else {
        return Err(format!(
            "expected exactly one definition of {item}, found {}",
            matches.len()
        ));
    };

    let mut cursor = *item_line;
    while cursor > 0 {
        while cursor > 0 {
            let line = lines[cursor - 1].trim();
            if line.is_empty() || line.starts_with("//") {
                cursor -= 1;
            } else {
                break;
            }
        }
        if cursor == 0 || !lines[cursor - 1].trim_end().ends_with(']') {
            break;
        }

        let end = cursor - 1;
        let mut start = end;
        let mut bracket_depth = 0isize;
        loop {
            let line = lines[start];
            bracket_depth += line.chars().filter(|character| *character == ']').count() as isize;
            bracket_depth -= line.chars().filter(|character| *character == '[').count() as isize;
            let compact: String = line
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            if bracket_depth == 0 && compact.starts_with("#[") {
                break;
            }
            if start == 0 {
                return Err(format!("could not parse outer attributes for {item}"));
            }
            start -= 1;
        }

        let attribute: String = lines[start..=end].join("\n");
        let compact: String = attribute
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        let supported_desktops = "#[cfg(any(unix,target_os=\"windows\"))]";
        if compact.starts_with("#[cfg_attr(")
            || (compact.starts_with("#[cfg(") && compact != supported_desktops)
        {
            return Err(format!(
                "{item} has a conditional attribute that can exclude Windows: {attribute}"
            ));
        }
        cursor = start;
    }

    Ok(())
}

#[test]
fn windows_ci_runs_locked_rust_tests() {
    let workflow = include_str!("../.github/workflows/ci.yml");
    validate_windows_ci_contract(workflow).expect("CI should exercise Rust on Windows");
}

#[test]
fn windows_ci_contract_rejects_a_non_windows_runner() {
    let workflow = include_str!("../.github/workflows/ci.yml");
    let mutant = workflow.replacen("runs-on: windows-latest", "runs-on: ubuntu-latest", 1);
    assert!(
        mutant != workflow,
        "fixture drift: the production workflow no longer names windows-latest"
    );

    let error = validate_windows_ci_contract(&mutant)
        .expect_err("a Linux job was accepted as Windows runtime coverage");
    assert!(
        error.contains("Windows runner"),
        "unexpected error: {error}"
    );
}

#[test]
fn windows_rust_tests_exercise_the_clipboard_lock_contract() {
    let source = include_str!("../src/main.rs");

    for item in CLIPBOARD_CONTRACT_ITEMS {
        validate_item_is_compiled_on_windows(source, item).unwrap_or_else(|error| {
            panic!("Windows CI must compile every clipboard lock contract: {error}")
        });
    }
}

#[test]
fn clipboard_contract_guard_rejects_a_multiline_cfg_that_excludes_windows() {
    let source = include_str!("../src/main.rs").replace("\r\n", "\n");
    let item = CLIPBOARD_CONTRACT_ITEMS[0];
    let anchor = format!("    #[test]\n    {item}");
    let replacement = format!(
        "    #[cfg(\n        not(target_os = \"windows\")\n    )]\n    #[test]\n    {item}"
    );
    let mutant = source.replacen(&anchor, &replacement, 1);
    assert_ne!(
        mutant, source,
        "fixture drift: could not install cfg mutant"
    );

    let error = validate_item_is_compiled_on_windows(&mutant, item)
        .expect_err("a cfg attribute that excludes Windows was accepted");
    assert!(error.contains("#[cfg"), "unexpected error: {error}");
}

#[test]
fn clipboard_contract_guard_rejects_a_unix_only_race_test() {
    let source = include_str!("../src/main.rs").replace("\r\n", "\n");
    let item = CLIPBOARD_CONTRACT_ITEMS[1];
    let anchor = format!("    #[cfg(any(unix, target_os = \"windows\"))]\n    #[test]\n    {item}");
    let replacement = format!("    #[cfg(unix)]\n    #[test]\n    {item}");
    let mutant = source.replacen(&anchor, &replacement, 1);
    assert_ne!(
        mutant, source,
        "fixture drift: could not install Unix-only mutant"
    );

    let error = validate_item_is_compiled_on_windows(&mutant, item)
        .expect_err("a Unix-only race test was accepted as Windows coverage");
    assert!(
        error.contains("exclude Windows"),
        "unexpected error: {error}"
    );
}

#[test]
fn windows_clipboard_lock_open_does_not_follow_a_leaf_reparse_point() {
    let source = include_str!("../src/main.rs");

    assert!(
        source.contains("const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;"),
        "the Windows lock-file open must name the Win32 no-follow flag explicitly"
    );
    assert!(
        source.contains("use std::os::windows::fs::OpenOptionsExt;"),
        "the Windows lock-file open must use the standard-library OpenOptions extension"
    );
    assert!(
        source.contains(".custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)"),
        "the Windows lock-file handle can otherwise follow a leaf symlink swapped in after inspection"
    );
}
