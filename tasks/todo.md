# 2026-07-09 修正 WSL Chrome 路徑偵測

## Goal + Acceptance Criteria
- [x] 修正 `ask-bridge --verbose login` 在 WSL/Linux 只尋找 macOS Chrome 路徑的問題。
- [x] 在 Linux/WSL 中可偵測 `PATH` 內的 `google-chrome` / `google-chrome-stable`，並支援 `/usr/bin/google-chrome` 等常見路徑。
- [x] macOS 與 Windows 既有 Chrome 偵測行為不被破壞。
- [x] 加入可重現此路徑選擇行為的單元測試。
- [x] 通過 `cargo fmt --all -- --check` 與 Rust 編譯/測試驗證。

## Risk & Rollback
- Risk level: low
- Affected components: Chrome 啟動前的可執行檔路徑解析。
- Rollback strategy: revert `src/main.rs` 中 Chrome path resolver 相關變更。

## Dependencies & Environment
- Rust/Cargo local toolchain。
- Linux/WSL 目標環境需已安裝 Google Chrome，且 `google-chrome` 或 `google-chrome-stable` 可由 `PATH` 或常見絕對路徑找到。

## Working Notes
- 現有 `find_chrome_path` 對 `#[cfg(not(target_os = "windows"))]` 一律檢查 `/Applications/Google Chrome.app/...`，導致 Linux/WSL 誤報 macOS 路徑。
- `install.sh` 已知道 Linux 應檢查 `google-chrome` 或 `google-chrome-stable`，runtime 偵測邏輯需要與此一致。

## Checklist
- [x] Review `tasks/lessons.md` if present
- [x] Locate existing implementation / patterns
- [x] Design minimal approach + key decisions
- [x] Implement smallest safe slice
- [x] Add/adjust tests
- [x] Run verification (format/tests/build)
- [x] Summarize changes + verification story
- [x] Record lessons if any correction/postmortem occurs (none needed)

## Results
- `src/main.rs` now keeps macOS detection on the macOS-only branch and adds Linux detection for `google-chrome` / `google-chrome-stable` via `PATH`, then common absolute paths including `/usr/bin/google-chrome`.
- `Makefile install-browser` now handles Linux separately instead of applying macOS-only Chrome detection to every Unix-like OS.
- Added unit coverage for Linux Chrome path lookup from `PATH`, fallback candidates, and missing Chrome.
- Verification:
  - `cargo fmt --all -- --check` passed.
  - `cargo test` initially failed on `G:` because only about 768 KB was free (`os error 112` / no space on device).
  - Windows-hosted verification passed with `CARGO_TARGET_DIR=%TEMP%\ask-bridge-target cargo test` (`21 passed`).
  - WSL/Linux verification passed with `CARGO_TARGET_DIR=/mnt/c/Users/wakau/AppData/Local/Temp/ask-bridge-target-wsl cargo test` (`21 passed`).
- Manual WSL Chrome launch was not verified in this environment because `Ubuntu-24.04` reports `google-chrome: command not found`; the user's reported `/usr/bin/google-chrome` path is covered by the new Linux fallback list.

---

# 2026-07-09 bump-and-release 0.1.4

## Goal + Acceptance Criteria
- [ ] Release patch version `0.1.4` for the WSL/Linux Chrome path fix.
- [ ] Keep the required 6 version locations synchronized: `Cargo.toml`, `package.json`, `src/main.rs`, `install.ps1`, `install.sh`, `scripts/ask.sh`.
- [ ] Update `Cargo.lock` through Cargo verification.
- [ ] Update `CHANGELOG.md` with the release entry.
- [ ] Commit version bump, create annotated tag `v0.1.4`, push branch and tag.

## Risk & Rollback
- Risk level: low
- Affected components: package metadata, installer download version, CLI version display, changelog.
- Rollback strategy: revert the version bump commit and delete `v0.1.4` locally/remotely if the release must be withdrawn.

## Dependencies & Environment
- Cargo and npm available locally.
- `G:` has insufficient free space for Cargo target output; use `%TEMP%` / `/mnt/c/...` target directories for heavy Cargo commands.
- Git remote is `origin https://github.com/doggy8088/ask-bridge.git`.

## Working Notes
- Patch bump is appropriate because the preceding change is a bug fix without breaking API/CLI behavior.
- Existing WSL Chrome fix was committed separately as `94c1912` before release version changes.

## Checklist
- [x] Analyze bump type
- [x] Update version files
- [x] Run verification
- [ ] Commit release bump
- [ ] Create and push tag
- [ ] Summarize release outcome

## Results
- Synchronized version `0.1.4` in `Cargo.toml`, `package.json`, `src/main.rs`, `install.ps1`, `install.sh`, and `scripts/ask.sh`.
- Updated `Cargo.lock` through `cargo check`.
- Added `CHANGELOG.md` entry for `0.1.4`.
- Verification passed:
  - `CARGO_TARGET_DIR=%TEMP%\ask-bridge-target cargo check`
  - `cargo fmt --all -- --check`
  - `CARGO_TARGET_DIR=%TEMP%\ask-bridge-target cargo test` (`21 passed`)
  - `CARGO_TARGET_DIR=/mnt/c/Users/wakau/AppData/Local/Temp/ask-bridge-target-wsl cargo test` (`21 passed`)
  - `npm test` (`4 passed`)
