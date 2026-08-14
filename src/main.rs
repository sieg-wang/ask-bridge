mod markdown_output;

use base64::{Engine as _, engine::general_purpose};
use clap::{ArgAction, CommandFactory, Parser, Subcommand, ValueEnum};
use markdown_output::MarkdownOutput;
use mcp_cli::{McpClient, McpConnection, ServerConfig, StdioClient};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::io::{self, IsTerminal, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

const ASK_BRIDGE_CHROME_MARKER: &str = "--ask-bridge-instance";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginState {
    LoggedIn,
    LoggedOut,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct LoginSignals {
    account: bool,
    auth_control: bool,
    auth_path: bool,
    composer: bool,
    stable: bool,
}

impl LoginSignals {
    fn state(self, provider: Provider) -> LoginState {
        if self.auth_path {
            LoginState::LoggedOut
        } else if self.account {
            LoginState::LoggedIn
        } else if !self.stable {
            LoginState::Unknown
        } else if self.auth_control {
            LoginState::LoggedOut
        } else if self.composer && provider == Provider::ChatGpt {
            LoginState::LoggedIn
        } else {
            LoginState::Unknown
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Provider {
    #[value(name = "chatgpt")]
    ChatGpt,
    #[value(name = "gemini")]
    Gemini,
    #[value(name = "claude")]
    Claude,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConversationIdentity {
    provider: Provider,
    route: ConversationRoute,
    id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ConversationRoute {
    /// The provider's standard conversation route.
    Root,
    /// ChatGPT's documented custom-GPT route: `/g/<gpt-id>/c/<conversation-id>`.
    ChatGptCustomGpt(String),
    /// Gemini's numeric multi-account selector: `/u/<account-index>/app/<id>`.
    /// An explicitly requested selector is part of the safety boundary: the
    /// landing page must not silently drift to another signed-in account.
    GeminiAccount(String),
}

impl ConversationIdentity {
    fn matches_live(&self, live: &Self) -> bool {
        if self.provider != live.provider || self.id != live.id {
            return false;
        }

        match (&self.route, &live.route) {
            (ConversationRoute::Root, ConversationRoute::GeminiAccount(_))
                if self.provider == Provider::Gemini =>
            {
                true
            }
            (expected, actual) => expected == actual,
        }
    }
}

impl Provider {
    fn from_config_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "chatgpt" | "chat-gpt" | "chat_gpt" => Some(Provider::ChatGpt),
            "gemini" => Some(Provider::Gemini),
            "claude" | "claude-ai" | "claude_ai" | "claudeai" => Some(Provider::Claude),
            _ => None,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Provider::ChatGpt => "ChatGPT",
            Provider::Gemini => "Gemini",
            Provider::Claude => "Claude",
        }
    }

    fn home_url(self) -> &'static str {
        match self {
            Provider::ChatGpt => "https://chatgpt.com/",
            Provider::Gemini => "https://gemini.google.com/app",
            Provider::Claude => "https://claude.ai/new",
        }
    }

    /// Registrable domain that identifies this provider's pages.
    fn primary_host(self) -> &'static str {
        match self {
            Provider::ChatGpt => "chatgpt.com",
            Provider::Gemini => "gemini.google.com",
            Provider::Claude => "claude.ai",
        }
    }

    /// Whether `url` is one of this provider's pages.
    ///
    /// Decided on the canonical host, never on a substring: `chatgpt.com` also
    /// appears in `https://chatgpt.com.evil.test/`, `https://evil.test/?next=
    /// chatgpt.com` and `https://chatgpt.com@evil.test/`, all of which are
    /// pages an attacker controls. Adopting one of those as the provider tab
    /// means selecting it and typing the prompt into a DOM that only has to
    /// imitate the provider's composer. The dot boundary is what makes the
    /// match safe: `evil.chatgpt.com` needs control of `chatgpt.com`'s DNS,
    /// while `chatgpt.com.evil.test` does not.
    ///
    /// The scheme test is upstream's (`10fbe91` made `from_url` reject
    /// `http://chatgpt.com/c/abc`); the canonical-host test is this fork's.
    /// Both are kept: upstream's exact-host list would reject `sora.chatgpt.com`
    /// and `chatgpt.com.` that this fork's tests pin as legitimate, and this
    /// fork's host rule alone would trust a plain-http origin.
    fn owns_url(self, url: &str) -> bool {
        let Some((scheme, _rest)) = url.split_once("://") else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("https") {
            return false;
        }
        match url_host(url) {
            Some(host) => host_is_within(&host, self.primary_host()),
            None => false,
        }
    }

    /// Hosts this provider's sign-in flow redirects through.
    ///
    /// A tab parked on one of these is debris from *our own* login redirect:
    /// when the session has expired the tab `--new` just opened lands here
    /// instead of on the provider. It is neither provider-owned nor blank, so
    /// without this list nothing ever closes it and every `--new` leaves one
    /// more behind.
    fn auth_hosts(self) -> &'static [&'static str] {
        match self {
            // Single purpose: reaching one of these means an ask-bridge login.
            Provider::ChatGpt => &["auth.openai.com", "auth0.openai.com"],
            // Shared infrastructure -- see `is_shared_auth_host`.
            Provider::Gemini | Provider::Claude => &["accounts.google.com"],
        }
    }

    /// Whether a tab parked on `url` is disposable login debris for *this*
    /// provider.
    ///
    /// The test is not "is this an auth host" but "is this a page that cannot
    /// be holding state the user cares about". `auth.openai.com` passes on the
    /// host alone: it exists only to sign in to ChatGPT. `accounts.google.com`
    /// does **not** -- it is the shared front door for every Google OAuth
    /// integration on the web, so the same host serves a third-party app's
    /// consent screen, an account chooser, a half-typed password and a 2FA
    /// prompt waiting on a phone tap. Closing those to save a tab would break
    /// this module's own rule that unrelated tabs are not ours to close.
    ///
    /// Google carries the destination in the URL, so ask for it: dispose of a
    /// shared auth host only when it says it is on its way back to this
    /// provider. No destination, or someone else's destination, means hands
    /// off -- at worst that leaves one tab, which is the safe direction.
    fn owns_auth_url(self, url: &str) -> bool {
        let Some(host) = url_host(url) else {
            return false;
        };
        if !self
            .auth_hosts()
            .iter()
            .any(|root| host_is_within(&host, root))
        {
            return false;
        }
        if is_single_purpose_auth_host(&host) {
            return true;
        }
        // Shared host (or one we have not vetted): it must say it is on its way
        // back to us.
        //
        // ASSUMPTION, not captured from a live flow: that this provider's OAuth
        // callback lives under its own primary host -- e.g. Anthropic's
        // registered `redirect_uri` being on `claude.ai`. The tests encode that
        // belief rather than an observed URL, so they cannot detect it being
        // wrong. Failure direction is safe (no disposal, one leaked tab). Swap
        // in a real captured URL next time a genuine logout happens.
        match auth_destination_host(url) {
            Some(dest) => host_is_within(&dest, self.primary_host()),
            None => false,
        }
    }

    fn from_url(url: &str) -> Option<Self> {
        [Provider::ChatGpt, Provider::Gemini, Provider::Claude]
            .into_iter()
            .find(|provider| provider.owns_url(url))
    }

    fn conversation_url_from_id(self, session_id: &str) -> String {
        match self {
            Provider::ChatGpt => format!("https://chatgpt.com/c/{session_id}"),
            Provider::Gemini => format!("https://gemini.google.com/app/{session_id}"),
            Provider::Claude => format!("https://claude.ai/chat/{session_id}"),
        }
    }

    /// Whether `url`'s origin is *exactly* this provider's conversation origin.
    ///
    /// Deliberately stricter than [`owns_url`](Self::owns_url), because the two
    /// answer different questions. `owns_url` classifies a page **found in the
    /// browser**: real provider tabs do live on sub-domains, and a lie there is
    /// caught by a second lock that asks the tab for its own `location.href`.
    /// This one classifies a URL **handed in on the command line** that the tool
    /// will navigate to and then type the user's prompt into -- nothing about it
    /// was observed first, and the live-URL check downstream can only confirm
    /// the tab stayed where this function already agreed to send it. So the
    /// dot boundary is wrong here: it accepts `https://evil.chatgpt.com/c/x`,
    /// which needs a DNS/sub-domain takeover rather than a domain registration,
    /// but is still not the provider.
    ///
    /// Equality, not the boundary, and on `Url`'s parsed host so the comparison
    /// sees what the browser would resolve: userinfo is not the host
    /// (`chatgpt.com@evil.test` is `evil.test`), ASCII case is already
    /// normalised away, and a trailing root dot is **not** -- so `chatgpt.com.`
    /// is rejected, which is also the functionally right answer: it is a
    /// separate cookie origin, so a session pinned there arrives logged out.
    ///
    /// The port is part of the origin and is therefore checked too. `Url` folds
    /// an explicitly written `:443` away, so `port()` returning `None` *is*
    /// "the effective port is https's default" -- `https://chatgpt.com:443/c/x`
    /// still passes, while `https://chatgpt.com:8443/c/x` is a different origin
    /// with different cookies and is refused. Without this the doc comment and
    /// the error message both said "exact origin" while the code compared only
    /// scheme and host.
    ///
    /// No provider is exempt: `www.chatgpt.com` (301) and `www.claude.ai` (301)
    /// redirect to the bare host, `chat.openai.com` (308) redirects to
    /// `chatgpt.com`, `sora.chatgpt.com` is a different product with no
    /// conversation path, and `gemini.google.com` is itself the canonical host.
    /// Checked by HEAD request on 2026-08-07 -- re-check before adding an
    /// exception rather than adding one on a guess.
    fn owns_session_origin(self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.host_str() == Some(self.primary_host())
            && url.port().is_none()
    }

    /// The provider whose conversation origin `url` is exactly, if any.
    fn from_session_url(url: &Url) -> Option<Self> {
        SESSION_PROVIDERS
            .into_iter()
            .find(|provider| provider.owns_session_origin(url))
    }

    fn conversation_identity(self, url: &Url) -> Option<ConversationIdentity> {
        if Self::from_session_url(url) != Some(self) {
            return None;
        }

        let mut path_segments = url.path_segments()?;
        let marker = match self {
            Provider::ChatGpt => "c",
            Provider::Gemini => "app",
            Provider::Claude => "chat",
        };
        let first = path_segments.next()?;
        let (route, id) = if first == marker {
            (ConversationRoute::Root, path_segments.next()?)
        } else if self == Provider::ChatGpt && first == "g" {
            let gpt_id = path_segments.next()?;
            if gpt_id.is_empty() || path_segments.next() != Some("c") {
                return None;
            }
            (
                ConversationRoute::ChatGptCustomGpt(gpt_id.to_string()),
                path_segments.next()?,
            )
        } else if self == Provider::Gemini && first == "u" {
            let account_index = path_segments.next()?;
            if account_index.is_empty()
                || !account_index.bytes().all(|byte| byte.is_ascii_digit())
                || path_segments.next() != Some(marker)
            {
                return None;
            }
            (
                ConversationRoute::GeminiAccount(account_index.to_string()),
                path_segments.next()?,
            )
        } else {
            return None;
        };
        if id.is_empty() || path_segments.next().is_some() {
            return None;
        }

        Some(ConversationIdentity {
            provider: self,
            route,
            id: id.to_string(),
        })
    }

    fn owns_conversation_url(self, url: &Url) -> bool {
        self.conversation_identity(url).is_some()
    }

    fn ready_check_js(self) -> &'static str {
        match self {
            Provider::ChatGpt => r#"() => document.getElementById('prompt-textarea') !== null"#,
            Provider::Gemini => {
                r#"() => {
                    return document.querySelector('div[role="textbox"][aria-label*="Gemini"]') !== null ||
                           document.querySelector('rich-textarea [contenteditable="true"]') !== null ||
                           document.querySelector('.ql-editor[contenteditable="true"]') !== null ||
                           document.querySelector('a[href*="accounts.google.com"]') !== null ||
                           /Sign in|登入/.test(document.body.innerText || '');
                }"#
            }
            Provider::Claude => {
                r#"() => {
                    return document.querySelector('div[contenteditable="true"][data-testid="chat-input"]') !== null ||
                           document.querySelector('div[contenteditable="true"].ProseMirror') !== null ||
                           document.querySelector('[data-testid="login-with-google"]') !== null ||
                           window.location.pathname.startsWith('/login') ||
                           /Sign in|登入/.test(document.body.innerText || '');
                }"#
            }
        }
    }

    fn login_signals_js(self) -> &'static str {
        match self {
            Provider::ChatGpt => {
                r#"async () => {
                    const isVisible = (el) => {
                        if (!el) return false;
                        const style = window.getComputedStyle(el);
                        const rect = el.getBoundingClientRect();
                        return style.display !== 'none' &&
                            style.visibility !== 'hidden' &&
                            style.opacity !== '0' &&
                            rect.width > 0 &&
                            rect.height > 0;
                    };

                    const textFor = (el) => [
                        el.getAttribute('aria-label'),
                        el.getAttribute('title'),
                        el.textContent
                    ].filter(Boolean).join(' ').trim();

                    const readSignals = () => {
                        const visibleAuthButton = Array.from(document.querySelectorAll('a, button'))
                            .some((el) => {
                                if (!isVisible(el)) return false;
                                const text = textFor(el);
                                return /^(log in|login|sign in|sign up|登入|登錄|登录|註冊|注册)$/i.test(text);
                            });

                        const composer = document.querySelector('#prompt-textarea') ||
                            document.querySelector('[data-testid="composer-text-input"]') ||
                            document.querySelector('textarea[placeholder*="Message"]') ||
                            document.querySelector('textarea[placeholder*="訊息"]') ||
                            document.querySelector('[contenteditable="true"]');

                        const accountMenu = document.querySelector('[data-testid="profile-button"]') ||
                            document.querySelector('[data-testid="account-menu-button"]') ||
                            document.querySelector('[data-testid="user-menu-button"]') ||
                            document.querySelector('button[aria-label*="Profile"]') ||
                            document.querySelector('button[aria-label*="profile"]') ||
                            document.querySelector('button[aria-label*="Account"]') ||
                            document.querySelector('button[aria-label*="account"]') ||
                            document.querySelector('button[aria-label*="User"]') ||
                            document.querySelector('button[aria-label*="user"]') ||
                            document.querySelector('button[aria-label*="帳戶"]') ||
                            document.querySelector('button[aria-label*="使用者"]');

                        return {
                            account: isVisible(accountMenu),
                            auth_control: Boolean(visibleAuthButton),
                            auth_path: /\/(auth|login|signup)(\/|$)/i.test(window.location.pathname),
                            composer: isVisible(composer)
                        };
                    };

                    let signals = readSignals();
                    let signature = JSON.stringify(signals);
                    const startedAt = Date.now();
                    let stableSince = startedAt;
                    let stable = false;
                    const earliestDecision = startedAt + 2000;
                    const deadline = Date.now() + 5000;
                    while (!signals.account && !signals.auth_path && Date.now() < deadline) {
                        await new Promise((resolve) => setTimeout(resolve, 250));
                        const nextSignals = readSignals();
                        const nextSignature = JSON.stringify(nextSignals);
                        if (nextSignature !== signature) {
                            signature = nextSignature;
                            stableSince = Date.now();
                        }
                        signals = nextSignals;
                        if (Date.now() >= earliestDecision && Date.now() - stableSince >= 750) {
                            stable = true;
                            break;
                        }
                    }

                    return { ...signals, stable };
                }"#
            }
            Provider::Gemini => {
                r#"() => {
                    const isVisible = (el) => {
                        if (!el) return false;
                        const style = window.getComputedStyle(el);
                        const rect = el.getBoundingClientRect();
                        return style.display !== 'none' &&
                            style.visibility !== 'hidden' &&
                            style.opacity !== '0' &&
                            rect.width > 0 &&
                            rect.height > 0;
                    };
                    const composer = document.querySelector('div[role="textbox"][aria-label*="Gemini"]') ||
                        document.querySelector('rich-textarea [contenteditable="true"]') ||
                        document.querySelector('.ql-editor[contenteditable="true"]');
                    const accountEl = document.querySelector('a[href*="accounts.google.com/SignOutOptions"]') ||
                        document.querySelector('a[aria-label*="Google 帳戶"]') ||
                        document.querySelector('a[aria-label*="Google Account"]');
                    const hasAccount = accountEl && (accountEl.href?.includes('SignOutOptions') || accountEl.closest('header') !== null);
                    const signIn = Array.from(document.querySelectorAll('a, button'))
                        .some((el) => isVisible(el) && /Sign in|登入/.test([
                                el.getAttribute('aria-label'),
                                el.textContent
                            ].filter(Boolean).join(' ')));
                    const authPath = /\/(auth|login|signin|signup)(\/|$)/i.test(window.location.pathname);
                    return {
                        account: Boolean(hasAccount),
                        auth_control: Boolean(signIn),
                        auth_path: authPath,
                        composer: Boolean(composer),
                        stable: true
                    };
                }"#
            }
            Provider::Claude => {
                r#"() => {
                    const isVisible = (el) => {
                        if (!el) return false;
                        const style = window.getComputedStyle(el);
                        const rect = el.getBoundingClientRect();
                        return style.display !== 'none' &&
                            style.visibility !== 'hidden' &&
                            style.opacity !== '0' &&
                            rect.width > 0 &&
                            rect.height > 0;
                    };
                    const composer = document.querySelector('div[contenteditable="true"][data-testid="chat-input"]') ||
                        document.querySelector('div[contenteditable="true"].ProseMirror');
                    const account = document.querySelector('[data-testid="user-menu-button"]') ||
                        document.querySelector('button[aria-label*="User menu"]') ||
                        document.querySelector('button[aria-label*="Account"]');
                    const signIn = document.querySelector('[data-testid="login-with-google"]') ||
                        Array.from(document.querySelectorAll('a, button'))
                            .find((el) => isVisible(el) && /^(log in|login|sign in|sign up|登入|註冊)$/i.test([
                                    el.getAttribute('aria-label'),
                                    el.textContent
                                ].filter(Boolean).join(' ').trim()));
                    const authPath = /^\/(login|signup|magic-link)(\/|$)/i.test(window.location.pathname);
                    return {
                        account: isVisible(account),
                        auth_control: Boolean(signIn),
                        auth_path: authPath,
                        composer: Boolean(composer),
                        stable: true
                    };
                }"#
            }
        }
    }

    fn assistant_selector(self) -> &'static str {
        match self {
            Provider::ChatGpt => "[data-message-author-role=\"assistant\"], .agent-turn",
            Provider::Gemini => "model-response",
            Provider::Claude => ".font-claude-response",
        }
    }

    fn latest_response_selector(self) -> &'static str {
        match self {
            Provider::ChatGpt => {
                "[data-message-author-role=\"assistant\"], .agent-turn, model-response, .model-response, [data-test-id*=\"response\"], [data-testid*=\"response\"]"
            }
            Provider::Gemini => "model-response",
            Provider::Claude => ".font-claude-response",
        }
    }

    fn response_content_selector(self) -> &'static str {
        match self {
            Provider::ChatGpt => "",
            Provider::Gemini => {
                "message-content, .markdown, structured-content-container.model-response-text"
            }
            Provider::Claude => ".standard-markdown, .font-claude-response-body",
        }
    }

    fn composer_selectors_json(self) -> &'static str {
        match self {
            Provider::ChatGpt => r##"["#prompt-textarea"]"##,
            Provider::Gemini => {
                r#"[
                    "div[role=\"textbox\"][aria-label*=\"Gemini\"]",
                    "rich-textarea [contenteditable=\"true\"]",
                    ".ql-editor[contenteditable=\"true\"]"
                ]"#
            }
            Provider::Claude => {
                r#"[
                    "div[contenteditable=\"true\"][data-testid=\"chat-input\"]",
                    "div[contenteditable=\"true\"].ProseMirror",
                    "div[aria-label*=\"Claude\"][contenteditable=\"true\"]"
                ]"#
            }
        }
    }

    fn send_button_selectors_json(self) -> &'static str {
        match self {
            Provider::ChatGpt => {
                r##"[
                    "[data-testid=\"send-button\"]",
                    "#composer-submit-button",
                    "button[aria-label*=\"Send\"]",
                    "button[aria-label*=\"傳送\"]",
                    "button[aria-label*=\"发送\"]"
                ]"##
            }
            Provider::Gemini => {
                r#"[
                    "button[aria-label=\"傳送訊息\"]",
                    "button[aria-label=\"Submit\"]",
                    "button[aria-label*=\"Send\"]",
                    "button[aria-label*=\"傳送\"]",
                    "button[aria-label*=\"提交\"]"
                ]"#
            }
            Provider::Claude => {
                r#"[
                    "button[aria-label=\"Send message\"]",
                    "button[aria-label*=\"Send\"]",
                    "button[aria-label*=\"傳送\"]"
                ]"#
            }
        }
    }

    fn stop_button_selectors_json(self) -> &'static str {
        match self {
            Provider::ChatGpt => {
                r##"[
                    "[data-testid=\"stop-button\"]",
                    "#composer-stop-button",
                    "button[aria-label=\"Stop generating\"]"
                ]"##
            }
            Provider::Gemini => {
                r#"[
                    "button[aria-label=\"停止回覆\"]",
                    "button[aria-label*=\"Stop\"]",
                    "button[aria-label*=\"停止\"]"
                ]"#
            }
            Provider::Claude => {
                r#"[
                    "button[aria-label=\"Stop response\"]",
                    "button[aria-label*=\"Stop\"]",
                    "button[aria-label*=\"停止\"]"
                ]"#
            }
        }
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Provider::ChatGpt => write!(f, "chatgpt"),
            Provider::Gemini => write!(f, "gemini"),
            Provider::Claude => write!(f, "claude"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReasoningRequest {
    ChatGptAuto,
    ChatGptInstant,
    ChatGptMedium,
    ChatGptHigh,
    GeminiExtended,
}

impl ReasoningRequest {
    fn target_aliases(self) -> &'static [&'static str] {
        match self {
            ReasoningRequest::ChatGptAuto => &["auto", "自動", "智慧"],
            ReasoningRequest::ChatGptInstant => &["instant", "即時"],
            ReasoningRequest::ChatGptMedium => &["medium", "中", "中等"],
            ReasoningRequest::ChatGptHigh => &["high", "高"],
            ReasoningRequest::GeminiExtended => &["extended thinking", "延伸思考"],
        }
    }

    fn verification_aliases(self) -> &'static [&'static str] {
        match self {
            ReasoningRequest::GeminiExtended => {
                &["extended thinking", "延伸思考", "pro extended", "pro 延伸"]
            }
            _ => self.target_aliases(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct SelectionPlan {
    model: Option<String>,
    reasoning: Option<ReasoningRequest>,
    used_legacy_model: bool,
}

fn normalize_option_label(value: &str) -> String {
    value
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|character| character.is_alphanumeric())
        .collect()
}

fn parse_chatgpt_reasoning(value: &str) -> Option<ReasoningRequest> {
    match normalize_option_label(value).as_str() {
        "auto" | "自動" | "智慧" => Some(ReasoningRequest::ChatGptAuto),
        "instant" | "即時" => Some(ReasoningRequest::ChatGptInstant),
        "medium" | "中" | "中等" => Some(ReasoningRequest::ChatGptMedium),
        "high" | "高" => Some(ReasoningRequest::ChatGptHigh),
        _ => None,
    }
}

fn parse_gemini_reasoning(value: &str) -> Option<ReasoningRequest> {
    match normalize_option_label(value).as_str() {
        "extended" | "extendedthinking" | "延伸思考" | "proextended" | "pro延伸" => {
            Some(ReasoningRequest::GeminiExtended)
        }
        _ => None,
    }
}

fn is_gemini_pro_model(model: &str) -> bool {
    let normalized = normalize_option_label(model);
    if normalized == "pro" {
        return true;
    }

    normalized.strip_suffix("pro").is_some_and(|version| {
        !version.is_empty() && version.chars().all(|character| character.is_ascii_digit())
    })
}

fn resolve_selection_plan(
    provider: Provider,
    model: Option<&str>,
    reasoning: Option<&str>,
) -> Result<SelectionPlan, String> {
    let raw_model = model.map(str::trim);
    if raw_model == Some("") {
        return Err("Empty model name".to_string());
    }
    let model = raw_model.map(str::to_string);

    let raw_reasoning = reasoning.map(str::trim);
    if raw_reasoning == Some("") {
        return Err("Empty reasoning value".to_string());
    }

    let explicit_reasoning = match (provider, raw_reasoning) {
        (_, None) => None,
        (Provider::ChatGpt, Some(value)) => Some(parse_chatgpt_reasoning(value).ok_or_else(|| {
            format!(
                "Unsupported ChatGPT reasoning '{value}'. Supported values: auto, instant, medium, high"
            )
        })?),
        (Provider::Gemini, Some(value)) => Some(parse_gemini_reasoning(value).ok_or_else(|| {
            format!("Unsupported Gemini reasoning '{value}'. Supported value: extended")
        })?),
        (Provider::Claude, Some(_)) => {
            return Err(
                "Claude does not support --reasoning; use --model for Sonnet, Opus, or Haiku"
                    .to_string(),
            );
        }
    };

    let legacy_reasoning = match (provider, model.as_deref()) {
        (Provider::ChatGpt, Some(value)) => parse_chatgpt_reasoning(value),
        (Provider::Gemini, Some(value)) => parse_gemini_reasoning(value),
        (Provider::Claude, _) | (_, None) => None,
    };

    if explicit_reasoning.is_some() && legacy_reasoning.is_some() {
        return Err(
            "A reasoning-like --model value cannot be combined with --reasoning; move the reasoning value to --reasoning"
                .to_string(),
        );
    }

    let (model, reasoning, used_legacy_model) = if let Some(legacy) = legacy_reasoning {
        (None, Some(legacy), true)
    } else {
        (model, explicit_reasoning, false)
    };

    if provider == Provider::Gemini
        && reasoning == Some(ReasoningRequest::GeminiExtended)
        && model
            .as_deref()
            .is_some_and(|value| !is_gemini_pro_model(value))
    {
        return Err(
            "Gemini Extended Thinking is incompatible with non-Pro models; omit --model or select a Pro model"
                .to_string(),
        );
    }

    Ok(SelectionPlan {
        model,
        reasoning,
        used_legacy_model,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ChatGptAgentPrompt<'a> {
    agent_mention: &'a str,
    body: &'a str,
}

fn parse_chatgpt_agent_prompt(prompt: &str) -> Option<ChatGptAgentPrompt<'_>> {
    let rest = prompt.strip_prefix('@')?;
    let mut agent_chars = 0usize;

    for (idx, ch) in rest.char_indices() {
        if ch.is_whitespace() {
            if agent_chars == 0 || agent_chars > 10 {
                return None;
            }

            let body = rest[idx + ch.len_utf8()..].trim_start_matches(char::is_whitespace);
            if body.is_empty() {
                return None;
            }

            return Some(ChatGptAgentPrompt {
                agent_mention: &prompt[..idx + 1],
                body,
            });
        }

        agent_chars += 1;
        if agent_chars > 10 {
            return None;
        }
    }

    None
}

#[derive(Parser)]
#[command(name = "ask-bridge")]
#[command(version = "0.2.10")]
#[command(disable_version_flag = true)]
#[command(about = "AI browser CLI - Ask ChatGPT, Gemini or Claude from your Terminal with your subscription", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// The prompt to send to the selected provider.
    /// If standard input is piped and this value is present, they are combined as:
    /// `prompt + "\\n\\n" + stdin`.
    prompt: Option<String>,

    /// AI provider to automate. Overrides ~/.config/ask-bridge/config.json.
    #[arg(long, short = 'p', value_enum, global = true)]
    provider: Option<Provider>,

    /// Chromium-based browser to automate: an executable path or a macOS .app
    /// bundle (e.g. "/Applications/Brave Origin.app"). Overrides the "browser"
    /// field in ~/.config/ask-bridge/config.json. Defaults to Google Chrome.
    #[arg(long, value_name = "PATH", global = true)]
    browser: Option<String>,

    /// Run Chrome in headless mode. Defaults to true.
    #[arg(long, require_equals = true, num_args = 0..=1, default_value = "true", default_missing_value = "true")]
    headless: bool,

    /// Create a brand new provider session in a new tab, closing this provider's previous tabs, blank tabs and tabs left on its sign-in host. Other providers' tabs and unrelated sites' tabs are preserved.
    #[arg(long, default_value_t = false)]
    new: bool,

    /// Resume an existing conversation by provider session ID or full conversation URL.
    #[arg(
        long = "session",
        visible_aliases = ["session-id", "session-url"],
        value_name = "URL_OR_ID",
        conflicts_with = "new"
    )]
    session: Option<String>,

    /// Print version information.
    #[arg(
        long = "version",
        short = 'v',
        short_alias = 'V',
        action = ArgAction::Version
    )]
    _version: (),

    /// Print verbose debugging status messages.
    #[arg(long, default_value_t = false)]
    verbose: bool,

    /// Write the final response in Markdown format to the specified file.
    // Not a doc comment on purpose: clap prints those in `--help`, and this is
    // a note to maintainers, not to users. Deliberately not an Option<String> —
    // MarkdownOutput keeps the path private to `markdown_output`, so this field
    // cannot be handed to a file-writing call anywhere in main.rs. See that
    // module's header for what that does and does not guarantee.
    #[arg(long, short, value_name = "FILE")]
    output: Option<MarkdownOutput>,

    /// Write the downloaded images to the specified folder or file path.
    #[arg(long, short = 'i', value_name = "IMAGE_PATH")]
    image_output: Option<String>,

    /// Attach one or more local image files to the prompt (can be specified multiple times).
    #[arg(long = "image", value_name = "IMAGE_FILE", num_args = 1)]
    images: Vec<String>,

    /// Attach one or more local document files (PDF, Word, Excel, text, etc.) to the prompt
    /// (can be specified multiple times).
    #[arg(long = "file", value_name = "FILE", num_args = 1)]
    files: Vec<String>,

    /// Maximum time in seconds to wait for the provider response.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    timeout: u64,

    /// Switch the provider model before sending the prompt.
    /// Match the primary menu label case- and punctuation-insensitively;
    /// subtitles and badges are ignored.
    #[arg(long = "model", value_name = "MODEL")]
    model: Option<String>,

    /// Select provider-specific reasoning separately from the model.
    /// ChatGPT: auto, instant, medium, high. Gemini: extended. Claude: unsupported.
    #[arg(long = "reasoning", value_name = "REASONING")]
    reasoning: Option<String>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Open Chrome browser, optionally navigate to a URL, and copy the latest response
    #[command(hide = true)]
    Open {
        /// Optional conversation URL to open before copying the latest response.
        url: Option<String>,
    },
    /// Retrieve the latest response from the selected provider (defaults to headless)
    #[command(hide = true)]
    Get {
        /// Optional conversation URL to fetch before copying the latest response.
        url: Option<String>,
        /// Print verbose debugging status messages.
        #[arg(long, default_value_t = false)]
        verbose: bool,
    },
    /// Open Chrome browser and wait for manual login
    Login,
    /// Close the managed Chrome browser instance
    Close,
    /// Set or show the global default provider and browser used when
    /// --provider / --browser are not specified.
    Config,
    /// Reinstall ask-bridge using the recommended README installation command
    Update,
    /// Dump the current browser tab HTML for debugging
    #[command(hide = true)]
    Dump,
    /// Take a screenshot of the current browser tab for debugging
    #[command(hide = true)]
    Screenshot,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AppConfig {
    provider: Option<String>,
    browser: Option<String>,
}

fn config_file_path() -> Result<PathBuf, String> {
    let mut config_path = home::home_dir().ok_or("Could not locate home directory")?;
    config_path.push(".config/ask-bridge/config.json");
    Ok(config_path)
}

fn parse_configured_provider(content: &str) -> Result<Option<Provider>, String> {
    let config: AppConfig =
        serde_json::from_str(content).map_err(|e| format!("Failed to parse config.json: {}", e))?;

    match config.provider {
        Some(provider) => Provider::from_config_value(&provider)
            .map(Some)
            .ok_or_else(|| format!("Invalid provider in config.json: {}", provider)),
        None => Ok(None),
    }
}

fn load_configured_provider() -> Result<Option<Provider>, String> {
    let config_path = config_file_path()?;
    if !config_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&config_path).map_err(|e| {
        format!(
            "Failed to read config file {}: {}",
            config_path.to_string_lossy(),
            e
        )
    })?;

    parse_configured_provider(&content).map_err(|e| {
        format!(
            "{}. Expected format: {{\"provider\":\"chatgpt\"}} or {{\"provider\":\"gemini\"}}",
            e
        )
    })
}

fn effective_provider(
    cli_provider: Option<Provider>,
    configured_provider: Option<Provider>,
) -> Provider {
    cli_provider
        .or(configured_provider)
        .unwrap_or(Provider::ChatGpt)
}

fn resolve_provider_with<F>(
    cli_provider: Option<Provider>,
    load_provider: F,
) -> Result<Provider, String>
where
    F: FnOnce() -> Result<Option<Provider>, String>,
{
    if let Some(provider) = cli_provider {
        return Ok(provider);
    }

    Ok(effective_provider(None, load_provider()?))
}

fn resolve_provider(cli_provider: Option<Provider>) -> Result<Provider, String> {
    resolve_provider_with(cli_provider, load_configured_provider)
}

fn parse_configured_browser(content: &str) -> Result<Option<String>, String> {
    let config: AppConfig =
        serde_json::from_str(content).map_err(|e| format!("Failed to parse config.json: {}", e))?;
    Ok(config
        .browser
        .map(|b| b.trim().to_string())
        .filter(|b| !b.is_empty()))
}

fn load_configured_browser() -> Result<Option<String>, String> {
    let config_path = config_file_path()?;
    if !config_path.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&config_path).map_err(|e| {
        format!(
            "Failed to read config file {}: {}",
            config_path.to_string_lossy(),
            e
        )
    })?;

    parse_configured_browser(&content)
}

/// Resolve a browser value (an executable path or a macOS `.app` bundle) into a
/// concrete executable path. Errors if it cannot be resolved to an executable file
/// so a misconfigured browser fails loudly instead of silently using Chrome.
/// True if `path` is a regular file with an executable bit set. On non-unix the
/// executable bit is unavailable, so it degrades to "is a regular file".
fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// First executable file inside `dir` in sorted (deterministic) order, skipping
/// dotfiles like `.DS_Store`. Used as the fallback when a bundle's executable
/// name doesn't match the bundle name.
fn first_executable_in_dir(dir: &Path) -> Option<String> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| !n.starts_with('.'))
                .unwrap_or(false)
        })
        .collect();
    entries.sort();
    entries
        .into_iter()
        .find(|p| is_executable_file(p))
        .map(|p| p.to_string_lossy().to_string())
}

fn resolve_browser_binary(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("Configured browser value is empty.".to_string());
    }

    let without_slash = trimmed.trim_end_matches('/');
    // `.app` is matched case-insensitively: the default macOS volume is
    // case-insensitive, so "Foo.APP" and "Foo.app" name the same bundle.
    let is_app_bundle = Path::new(without_slash)
        .extension()
        .map(|ext| ext.eq_ignore_ascii_case("app"))
        .unwrap_or(false);
    if is_app_bundle {
        let app_dir = Path::new(without_slash);
        if !app_dir.exists() {
            return Err(format!(
                "Browser bundle not found at '{}'. Provide an installed .app bundle or an executable path.",
                trimmed
            ));
        }
        let macos_dir = app_dir.join("Contents/MacOS");
        // macOS convention: the executable is the bundle name minus ".app"
        // (e.g. "Brave Origin.app" -> "Brave Origin"). Fall back to the first
        // executable inside Contents/MacOS if that convention does not hold.
        if let Some(stem) = app_dir.file_stem().and_then(|s| s.to_str()) {
            let candidate = macos_dir.join(stem);
            if is_executable_file(&candidate) {
                return Ok(candidate.to_string_lossy().to_string());
            }
        }
        if let Some(exe) = first_executable_in_dir(&macos_dir) {
            return Ok(exe);
        }
        return Err(format!(
            "No executable found inside '{}'. Is '{}' a valid Chromium browser bundle?",
            macos_dir.to_string_lossy(),
            trimmed
        ));
    }

    let path = Path::new(trimmed);
    if path.is_file() {
        if is_executable_file(path) {
            return Ok(trimmed.to_string());
        }
        return Err(format!(
            "Configured browser file at '{}' is not executable.",
            trimmed
        ));
    }
    if path.is_dir() {
        return Err(format!(
            "'{}' is a directory, not an executable. Point --browser / config \"browser\" at a browser executable or a macOS .app bundle.",
            trimmed
        ));
    }

    Err(format!(
        "Configured browser not found at '{}'. Provide an executable path or a macOS .app bundle via --browser or the \"browser\" field in config.json.",
        trimmed
    ))
}

/// Select the raw browser value with CLI taking precedence over config. An
/// explicit `--browser` short-circuits config loading, mirroring `--provider`.
fn select_browser_value_with<F>(
    cli_browser: Option<String>,
    load_browser: F,
) -> Result<Option<String>, String>
where
    F: FnOnce() -> Result<Option<String>, String>,
{
    if let Some(browser) = cli_browser {
        return Ok(Some(browser));
    }
    load_browser()
}

/// Resolve the effective browser override to a concrete executable path.
/// Returns `None` when neither CLI nor config set one (caller falls back to the
/// auto-detected Chrome path).
fn resolve_browser_override(cli_browser: Option<String>) -> Result<Option<String>, String> {
    match select_browser_value_with(cli_browser, load_configured_browser)? {
        Some(value) => resolve_browser_binary(&value).map(Some),
        None => Ok(None),
    }
}

/// Merge `provider`/`browser` into an existing config JSON body, preserving any
/// fields not being changed so `config --provider` cannot wipe a saved `browser`
/// (and vice versa).
fn merged_config_json(
    existing: &str,
    provider: Option<&str>,
    browser: Option<&str>,
) -> Result<String, String> {
    let mut obj = if existing.trim().is_empty() {
        serde_json::Map::new()
    } else {
        match serde_json::from_str::<serde_json::Value>(existing)
            .map_err(|e| format!("Failed to parse existing config.json: {}", e))?
        {
            serde_json::Value::Object(map) => map,
            // A valid-but-non-object body (e.g. hand-edited to `[]`) would be
            // silently discarded by unwrap_or_default(), wiping saved fields;
            // fail loud instead so the merge-preserving guarantee holds.
            _ => return Err("Existing config.json is not a JSON object.".to_string()),
        }
    };

    if let Some(provider) = provider {
        obj.insert(
            "provider".to_string(),
            serde_json::Value::String(provider.to_string()),
        );
    }
    if let Some(browser) = browser {
        obj.insert(
            "browser".to_string(),
            serde_json::Value::String(browser.to_string()),
        );
    }

    serde_json::to_string_pretty(&serde_json::Value::Object(obj))
        .map_err(|e| format!("Failed to serialize config: {}", e))
}

fn write_global_config(provider: Option<Provider>, browser: Option<&str>) -> Result<(), String> {
    let config_path = config_file_path()?;
    write_global_config_at(&config_path, provider, browser)
}

fn write_global_config_at(
    config_path: &Path,
    provider: Option<Provider>,
    browser: Option<&str>,
) -> Result<(), String> {
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create config directory {}: {}",
                parent.to_string_lossy(),
                e
            )
        })?;
    }

    let config_name = config_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            format!(
                "Config path has no valid file name: {}",
                config_path.to_string_lossy()
            )
        })?;
    let lock_path = config_path.with_file_name(format!(".{config_name}.lock"));
    match std::fs::symlink_metadata(&lock_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "Refusing to use config lock through a symbolic link: {}",
                lock_path.to_string_lossy()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Failed to inspect config lock {}: {}",
                lock_path.to_string_lossy(),
                error
            ));
        }
    }
    let mut lock_options = std::fs::OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        lock_options.custom_flags(libc::O_NOFOLLOW);
    }
    let config_lock = lock_options.open(&lock_path).map_err(|error| {
        format!(
            "Failed to open config lock {}: {}",
            lock_path.to_string_lossy(),
            error
        )
    })?;
    if !config_lock
        .metadata()
        .map_err(|error| {
            format!(
                "Failed to inspect opened config lock {}: {}",
                lock_path.to_string_lossy(),
                error
            )
        })?
        .file_type()
        .is_file()
    {
        return Err(format!(
            "Config lock is not a regular file: {}",
            lock_path.to_string_lossy()
        ));
    }
    config_lock.lock().map_err(|error| {
        format!(
            "Failed to lock config file {}: {}",
            config_path.to_string_lossy(),
            error
        )
    })?;

    match std::fs::symlink_metadata(config_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "Refusing to write config file through a symbolic link: {}",
                config_path.to_string_lossy()
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Failed to inspect existing config file {}: {}",
                config_path.to_string_lossy(),
                error
            ));
        }
    }

    // Only a missing file means "start fresh". Any other read error (permission
    // bits, transient I/O on a cloud-backed home dir, invalid UTF-8) must fail
    // loud — treating it as empty would rewrite the file and drop the other
    // field, defeating the merge-preserving guarantee.
    let existing = match std::fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "Failed to read existing config file {}: {}",
                config_path.to_string_lossy(),
                e
            ));
        }
    };
    let provider_str = provider.map(|p| p.to_string());
    let content = merged_config_json(&existing, provider_str.as_deref(), browser)?;
    let parent = config_path.parent().ok_or_else(|| {
        format!(
            "Config path has no parent: {}",
            config_path.to_string_lossy()
        )
    })?;
    let mut staged = tempfile::Builder::new()
        .prefix(".config.json.tmp.")
        .tempfile_in(parent)
        .map_err(|error| {
            format!(
                "Failed to create staging file for {}: {}",
                config_path.to_string_lossy(),
                error
            )
        })?;
    staged
        .write_all(format!("{}\n", content).as_bytes())
        .and_then(|()| staged.flush())
        .and_then(|()| staged.as_file().sync_all())
        .map_err(|error| {
            format!(
                "Failed to stage config file {}: {}",
                config_path.to_string_lossy(),
                error
            )
        })?;
    // The staging file is created 0600; carry the existing config's mode over
    // so the atomic replace does not silently lock out group/other readers
    // that could read the file before. A missing file keeps the staging
    // default. (Symlinks were already rejected above, so this reads the
    // regular file itself.)
    #[cfg(unix)]
    match std::fs::metadata(config_path) {
        Ok(metadata) => {
            staged
                .as_file()
                .set_permissions(metadata.permissions())
                .map_err(|error| {
                    format!(
                        "Failed to preserve permissions of config file {}: {}",
                        config_path.to_string_lossy(),
                        error
                    )
                })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Failed to read permissions of config file {}: {}",
                config_path.to_string_lossy(),
                error
            ));
        }
    }
    staged.persist(config_path).map_err(|error| {
        format!(
            "Failed to atomically replace config file {}: {}",
            config_path.to_string_lossy(),
            error.error
        )
    })?;

    Ok(())
}

fn run_config_command(
    cli_provider: Option<Provider>,
    cli_browser: Option<String>,
) -> Result<(), String> {
    if cli_provider.is_some() || cli_browser.is_some() {
        if let Some(browser) = &cli_browser {
            // Fail loudly at set-time if the path can't be resolved, instead of
            // silently persisting a typo that breaks every later run. The
            // ORIGINAL value (e.g. the .app path) is stored, not the resolved
            // binary, so bundle-internal layout changes still work later.
            resolve_browser_binary(browser)?;
        }
        write_global_config(cli_provider, cli_browser.as_deref())?;
        let config_path = config_file_path()?;
        if let Some(provider) = cli_provider {
            println!(
                "Set default provider to '{}' in {}",
                provider,
                config_path.to_string_lossy()
            );
        }
        if let Some(browser) = &cli_browser {
            println!(
                "Set default browser to '{}' in {}",
                browser,
                config_path.to_string_lossy()
            );
        }
        return Ok(());
    }

    let config_path = config_file_path()?;
    match load_configured_provider()? {
        Some(provider) => println!("Current default provider: {}", provider),
        None => {
            println!("No default provider configured.");
            println!("The effective provider is ChatGPT.");
        }
    }
    match load_configured_browser()? {
        Some(browser) => println!("Current default browser: {}", browser),
        None => println!("No default browser configured (using auto-detected Google Chrome)."),
    }
    if config_path.exists() {
        println!("Config file: {}", config_path.to_string_lossy());
    } else {
        println!(
            "Config file not created yet: {}",
            config_path.to_string_lossy()
        );
    }
    println!("Set default provider with: ask-bridge config --provider <chatgpt|gemini|claude>");
    println!("Set default browser with:  ask-bridge config --browser <path-or-.app>");
    Ok(())
}

/// The shell `ask-bridge update` runs on macOS/Linux.
///
/// The installer is downloaded to a file and *then* executed, never piped.
/// `curl ... | bash` hands the shell whatever arrived: a connection that drops
/// half way through is executed as far as it got, and the pipeline's exit status
/// is bash's, not curl's -- so a half-installed binary reports success. With
/// `set -e` and a file, the failed download is the failure.
///
/// What the installer then downloads is verified against the SHA-256 the release
/// workflow publishes beside it (`verify_release_checksum` in install.sh). The
/// installer script itself is still fetched from a mutable branch over TLS
/// alone; see `tests/installer_integrity.rs` for what is and is not covered.
#[cfg(not(target_os = "windows"))]
const UNIX_UPDATE_SHELL_COMMAND: &str = concat!(
    "set -e\n",
    "tmp=$(mktemp -d)\n",
    "trap 'rm -rf \"$tmp\"' EXIT\n",
    "curl -fsSL https://raw.githubusercontent.com/doggy8088/ask-bridge/main/install.sh",
    " -o \"$tmp/install.sh\"\n",
    "bash \"$tmp/install.sh\"\n",
);

fn run_update_command() -> Result<(), String> {
    println!("Running ask-bridge update via official installer...");
    println!("Progress: downloading installer and updating binary.");

    #[cfg(target_os = "windows")]
    let status = {
        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to locate current executable path: {}", e))?;
        let update_exe = current_exe
            .parent()
            .ok_or_else(|| "Failed to determine ask-bridge executable directory".to_string())?
            .join("ask-bridge-update.exe");

        if update_exe.exists() {
            let child = Command::new(update_exe)
                .arg(format!("--parent-pid={}", std::process::id()))
                .arg("--wait-seconds=30")
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("Failed to launch ask-bridge-update.exe: {}", e))?;
            println!("Progress: updater started with PID {}.", child.id());
            println!("Progress: update command is running in background.");
            return Ok(());
        }

        println!("ask-bridge-update.exe not found. Falling back to inline installer.");
        Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "irm https://raw.githubusercontent.com/doggy8088/ask-bridge/main/install.ps1 | iex",
            ])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|e| format!("Failed to run Windows update command: {}", e))?
    };

    #[cfg(not(target_os = "windows"))]
    let status = Command::new("sh")
        .args(["-c", UNIX_UPDATE_SHELL_COMMAND])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("Failed to run macOS/Linux update command: {}", e))?;

    if status.success() {
        println!("Progress: update command completed.");
        Ok(())
    } else {
        Err(format!("Update command failed with exit status {}", status))
    }
}

struct Page {
    id: usize,
    /// The tab's URL, or `None` when its listing line could not be read back
    /// unambiguously (see [`page_url_from_label`]).
    ///
    /// `None` means "unknown", not "blank": a tab we cannot name is not this
    /// provider's, is not disposable debris, and is not a blank tab to
    /// navigate. Every consumer has to say which of those it means, which is
    /// why this is an `Option` rather than a sentinel string -- a sentinel
    /// would silently take whichever branch it happened to fall through to.
    url: Option<String>,
    selected: bool,
}

fn unique_new_page_id(before: &[Page], after: &[Page]) -> Result<usize, String> {
    let new_page_ids: Vec<usize> = after
        .iter()
        .filter(|candidate| !before.iter().any(|page| page.id == candidate.id))
        .map(|page| page.id)
        .collect();

    match new_page_ids.as_slice() {
        [page_id] => Ok(*page_id),
        [] => {
            Err("Could not identify the newly opened tab; existing tabs were preserved".to_string())
        }
        _ => Err(format!(
            "Could not uniquely identify the newly opened tab (new page IDs: {:?}); existing tabs were preserved",
            new_page_ids
        )),
    }
}

/// The providers a `--session` URL may name, in the order the host error lists
/// them. Shared by the rule and its message so a fourth provider cannot make the
/// message lie.
const SESSION_PROVIDERS: [Provider; 3] = [Provider::ChatGpt, Provider::Gemini, Provider::Claude];

fn resolve_session_target(
    selected_provider: Provider,
    provider_was_explicit: bool,
    session: &str,
) -> Result<(Provider, String), String> {
    let session = session.trim();
    if session.is_empty() {
        return Err("Session ID or URL cannot be empty".to_string());
    }

    if let Ok(url) = Url::parse(session) {
        // Exact origin, not the sub-domain rule tab identity uses -- see
        // `Provider::owns_session_origin` for why the two differ.
        let session_provider = Provider::from_session_url(&url).ok_or_else(|| {
            let hosts: Vec<&str> = SESSION_PROVIDERS
                .iter()
                .map(|provider| provider.primary_host())
                .collect();
            format!(
                "Session URL must use https on the default port and its host \
                 must be exactly one of: {} (a sub-domain, a trailing dot, a \
                 userinfo prefix, or a non-default port is a different origin \
                 and is rejected)",
                hosts.join(", ")
            )
        })?;
        if !session_provider.owns_conversation_url(&url) {
            return Err(format!(
                "URL is not a supported {} conversation URL",
                session_provider.display_name()
            ));
        }
        if provider_was_explicit && session_provider != selected_provider {
            return Err(format!(
                "Session URL belongs to {}, but --provider selected {}",
                session_provider.display_name(),
                selected_provider.display_name()
            ));
        }

        return Ok((session_provider, url.to_string()));
    }

    if session.len() > 256
        || !session
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(
            "Session ID may contain only ASCII letters, digits, hyphens, and underscores"
                .to_string(),
        );
    }

    Ok((
        selected_provider,
        selected_provider.conversation_url_from_id(session),
    ))
}

/// Canonical lowercase host of an absolute http(s) URL, or `None` when the URL
/// is not http(s) or carries no host.
///
/// Userinfo is discarded the way a browser resolves it: in
/// `https://chatgpt.com@evil.test/` the host is `evil.test`, so anything that
/// decides trust from this function cannot be fooled by a domain parked in the
/// userinfo. Ports, a trailing root dot and letter case are normalised away.
/// Whether `host` is `root` or a sub-domain of it, matched on the dot boundary.
///
/// The boundary is what makes the match safe: `evil.chatgpt.com` requires
/// control of `chatgpt.com`'s DNS, while `chatgpt.com.evil.test` does not.
fn host_is_within(host: &str, root: &str) -> bool {
    match host.strip_suffix(root) {
        Some(prefix) => prefix.is_empty() || prefix.ends_with('.'),
        None => false,
    }
}

/// Whether `host` serves exactly one destination, so that arriving at it is
/// itself proof of whose login it is.
///
/// `true` means the host alone authorises disposal. `false` means "not vetted,
/// treat as shared infrastructure" and the caller must check the destination --
/// so the default for anything unlisted is the safe one. The inverse spelling
/// (enumerate the *shared* hosts, let everything else through on the host
/// alone) fails open at the extension point: any host that enters some
/// provider's [`Provider::auth_hosts`] without also being added here would
/// silently inherit the host-only rule and start closing strangers' tabs. That
/// covers more than a new provider -- an *existing* provider gaining an auth
/// host (OpenAI adding Microsoft SSO would put `login.microsoftonline.com` into
/// `ChatGpt.auth_hosts()`), or a host being dropped from the list below while
/// still listed as some provider's auth host, reach it too.
///
/// Sub-domain matching, not equality: `sub.auth.openai.com` is still
/// single-purpose. Equality here would silently demote it to needing a
/// destination it does not carry.
fn is_single_purpose_auth_host(host: &str) -> bool {
    SINGLE_PURPOSE_AUTH_HOSTS
        .iter()
        .any(|root| host_is_within(host, root))
}

/// Vetted single-destination auth hosts -- see [`is_single_purpose_auth_host`]
/// for why this is an allow-list rather than a deny-list.
const SINGLE_PURPOSE_AUTH_HOSTS: [&str; 2] = ["auth.openai.com", "auth0.openai.com"];

/// Query parameters that carry a sign-in destination, in decreasing order of
/// authority. The order is what the lookup iterates, so a low-fidelity signal
/// can never outrank an authoritative one just by appearing earlier in the
/// query string.
///
/// `redirect_uri` is where OAuth *must* put the callback (it is a required
/// parameter of Google's authorization endpoint), so it is the most reliable.
/// `continue`/`followup` carry classic sign-in destinations. `service` is
/// usually a bare service code (`lso`, `mail`, `cl`) rather than a URL, so it
/// is last and normally yields no host at all.
const AUTH_DESTINATION_KEYS: [&str; 4] = ["redirect_uri", "continue", "followup", "service"];

/// Host of the destination a shared sign-in URL says it is heading to, or
/// `None` when it does not say.
///
/// Only the parameters in [`AUTH_DESTINATION_KEYS`] are consulted. Reading a
/// destination out of *any* parameter would let a crafted link nominate one
/// through a field the login flow never uses.
fn auth_destination_host(url: &str) -> Option<String> {
    // Cut the fragment first: a `?` that appears inside a fragment starts no
    // query, so splitting on `?` before `#` would read the wrong string.
    let url = url.split('#').next().unwrap_or("");
    let query = url.split_once('?').map(|(_, q)| q)?;
    for key in AUTH_DESTINATION_KEYS {
        for pair in query.split('&') {
            let Some((found, value)) = pair.split_once('=') else {
                continue;
            };
            if found != key {
                continue;
            }
            if let Some(host) = url_host(&percent_decode(value)) {
                return Some(host);
            }
        }
    }
    None
}

/// Minimal `application/x-www-form-urlencoded` value decoder: `%XX` escapes and
/// `+` as space. Invalid escapes are left verbatim -- this feeds a host check
/// that fails closed, so a malformed value simply does not match.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn url_host(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    // A backslash terminates the authority in browsers just like a slash does.
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority,
    };
    let host = match authority.strip_prefix('[') {
        // IPv6 literal: the host ends at ']', a ':' inside it is not a port.
        Some(inside) => inside.split(']').next().unwrap_or(""),
        None => authority.split(':').next().unwrap_or(""),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

#[derive(Clone, Copy, Debug)]
struct PageLoginState {
    id: usize,
    selected: bool,
    login_state: LoginState,
}

fn preferred_provider_page_id(pages: &[PageLoginState]) -> Option<usize> {
    pages
        .iter()
        .find(|page| page.login_state == LoginState::LoggedIn)
        .or_else(|| pages.iter().find(|page| page.selected))
        .or_else(|| pages.first())
        .map(|page| page.id)
}

fn parse_node_version(output: &str) -> Option<(u64, u64, u64)> {
    let version = output.trim().strip_prefix('v').unwrap_or(output.trim());
    let core = version.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next()?.parse().ok()?;

    if parts.next().is_some() {
        return None;
    }

    Some((major, minor, patch))
}

fn validate_node_version_output(output: &str) -> Result<(), String> {
    let version = parse_node_version(output).ok_or_else(|| {
        format!(
            "Could not parse Node.js version from '{}'. Install a current Node.js LTS release and retry.",
            output.trim()
        )
    })?;
    let (major, minor, patch) = version;
    let supported = (major == 20 && (minor, patch) >= (19, 0))
        || (major == 22 && (minor, patch) >= (12, 0))
        || major >= 23;

    if supported {
        return Ok(());
    }

    Err(format!(
        "Node.js v{major}.{minor}.{patch} is not supported by {MCP_PACKAGE_SPEC}. Supported versions are ^20.19.0, ^22.12.0, or >=23.0.0. Install a current Node.js LTS release, reopen the terminal, and retry."
    ))
}

fn check_node_runtime() -> Result<(), String> {
    let output = Command::new("node")
        .arg("--version")
        .output()
        .map_err(|e| {
            format!(
                "Failed to run 'node --version': {e}. Install Node.js and ensure it is available in PATH."
            )
        })?;

    if !output.status.success() {
        return Err(format!(
            "'node --version' exited with status {}. Install a current Node.js LTS release and retry.",
            output.status
        ));
    }

    validate_node_version_output(&String::from_utf8_lossy(&output.stdout))
}

/// Pinned chrome-devtools-mcp package spec. `@latest` would make every npx
/// spawn re-resolve the dist-tag against the npm registry, which was observed
/// stalling; with mcp-cli's timeout-less request wait that hung whole runs
/// (2026-07-11). Bump this version deliberately and re-run the e2e check.
const MCP_PACKAGE_SPEC: &str = "chrome-devtools-mcp@1.5.0";

fn build_chrome_devtools_server_config(
    quiet_mcp: bool,
    headless: bool,
    log_path: &str,
    is_windows: bool,
) -> Value {
    let mut mcp_args = vec![
        "-y".to_string(),
        MCP_PACKAGE_SPEC.to_string(),
        "--browser-url=http://127.0.0.1:9223".to_string(),
    ];
    if quiet_mcp {
        mcp_args.push("--no-usage-statistics".to_string());
        mcp_args.push("--no-performance-crux".to_string());
    }
    if headless {
        mcp_args.push("--headless".to_string());
    }
    mcp_args.push("--logFile".to_string());
    mcp_args.push(log_path.to_string());

    let mut chrome_devtools_server = serde_json::json!({
        "command": if is_windows { "npx.cmd" } else { "npx" },
        "args": mcp_args
    });

    if quiet_mcp {
        chrome_devtools_server["env"] = serde_json::json!({
            "NPM_CONFIG_LOGLEVEL": "error",
            "NPM_CONFIG_PROGRESS": "false",
            "NPM_CONFIG_FUND": "false",
            "NPM_CONFIG_AUDIT": "false",
            "NPM_CONFIG_FUNDING": "0",
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "NO_COLOR": "1",
            "CI": "1",
            "NODE_NO_WARNINGS": "1"
        });
    }

    chrome_devtools_server
}

fn write_mcp_config(quiet_mcp: bool, headless: bool) -> Result<String, String> {
    let mut config_dir = home::home_dir().ok_or("Could not locate home directory")?;
    config_dir.push(".config/ask-bridge");
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;

    let log_path = config_dir
        .join("chrome-devtools-mcp.log")
        .to_string_lossy()
        .to_string();

    config_dir.push("mcp_servers.json");
    let config_path = config_dir.to_string_lossy().to_string();

    let chrome_devtools_server = build_chrome_devtools_server_config(
        quiet_mcp,
        headless,
        &log_path,
        cfg!(target_os = "windows"),
    );

    let config_content = serde_json::json!({
        "mcpServers": {
            "chrome-devtools": chrome_devtools_server
        }
    });

    let content_str = serde_json::to_string_pretty(&config_content).map_err(|e| e.to_string())?;

    std::fs::write(&config_path, content_str)
        .map_err(|e| format!("Failed to write mcp_servers.json: {}", e))?;

    Ok(config_path)
}

fn chrome_profile_path() -> Result<String, String> {
    let mut profile_dir = home::home_dir().ok_or("Could not locate home directory")?;
    profile_dir.push(".config/ask-bridge/chrome-profile");
    std::fs::create_dir_all(&profile_dir)
        .map_err(|e| format!("Failed to create chrome profile directory: {}", e))?;

    Ok(profile_dir.to_string_lossy().to_string())
}

fn chrome_pid_path() -> Result<PathBuf, String> {
    let mut path = home::home_dir().ok_or("Could not locate home directory")?;
    path.push(".config/ask-bridge/chrome.pid");
    Ok(path)
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct ChromeProcessRecord {
    pid: u32,
    #[serde(default)]
    browser_id: Option<String>,
}

fn parse_chrome_process_record(content: &str) -> Option<ChromeProcessRecord> {
    serde_json::from_str(content).ok().or_else(|| {
        content
            .trim()
            .parse::<u32>()
            .ok()
            .map(|pid| ChromeProcessRecord {
                pid,
                browser_id: None,
            })
    })
}

fn write_chrome_process_record(record: &ChromeProcessRecord) -> Result<(), String> {
    let path = chrome_pid_path()?;
    let content = serde_json::to_string(record)
        .map_err(|e| format!("Failed to serialize Chrome process record: {}", e))?;
    std::fs::write(&path, content).map_err(|e| format!("Failed to write {}: {}", path.display(), e))
}

fn read_chrome_process_record() -> Option<ChromeProcessRecord> {
    let path = chrome_pid_path().ok()?;
    let content = std::fs::read_to_string(path).ok()?;
    parse_chrome_process_record(&content)
}

fn read_chrome_pid() -> Option<String> {
    read_chrome_process_record().map(|record| record.pid.to_string())
}

fn remove_chrome_pid_file() -> Result<(), String> {
    let path = chrome_pid_path()?;
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Failed to remove {}: {}", path.display(), e)),
    }
}

fn browser_id_from_websocket_url(url: &str) -> Option<String> {
    const LOOPBACK_PREFIXES: &[&str] = &[
        "ws://127.0.0.1:9223/devtools/browser/",
        "ws://localhost:9223/devtools/browser/",
        "ws://[::1]:9223/devtools/browser/",
    ];
    let id = LOOPBACK_PREFIXES
        .iter()
        .find_map(|prefix| url.strip_prefix(prefix))?
        .trim();
    (!id.is_empty() && !id.contains(['/', '?', '#'])).then(|| id.to_string())
}

fn browser_id_from_version_response(response: &str) -> Option<String> {
    if !http_response_is_complete(response.as_bytes()) {
        return None;
    }
    let (headers, body) = response.split_once("\r\n\r\n")?;
    let status = headers.lines().next()?;
    let mut status_parts = status.split_whitespace();
    if !status_parts.next()?.starts_with("HTTP/") || status_parts.next()? != "200" {
        return None;
    }
    let body = body.trim();
    let version: Value = serde_json::from_str(body).ok()?;
    let websocket_url = version.get("webSocketDebuggerUrl")?.as_str()?;
    browser_id_from_websocket_url(websocket_url)
}

fn http_response_is_complete(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let Ok(headers) = std::str::from_utf8(&response[..header_end]) else {
        return false;
    };
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });

    content_length
        .and_then(|content_length| body_start.checked_add(content_length))
        .map(|response_length| response.len() >= response_length)
        .unwrap_or(false)
}

fn debug_browser_id() -> Option<String> {
    const MAX_RESPONSE_SIZE: usize = 64 * 1024;
    const TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

    let mut stream = TcpStream::connect("127.0.0.1:9223").ok()?;
    let timeout = Some(Duration::from_millis(500));
    stream.set_read_timeout(timeout).ok()?;
    stream.set_write_timeout(timeout).ok()?;
    stream
        .write_all(
            b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1:9223\r\nConnection: close\r\n\r\n",
        )
        .ok()?;

    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    let deadline = Instant::now() + TOTAL_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            break;
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                response
                    .len()
                    .checked_add(bytes_read)
                    .filter(|length| *length <= MAX_RESPONSE_SIZE)
                    .map(|_| ())?;
                response.extend_from_slice(&buffer[..bytes_read]);
                if http_response_is_complete(&response) {
                    break;
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(_) => return None,
        }
    }

    if !http_response_is_complete(&response) {
        return None;
    }
    let response = String::from_utf8(response).ok()?;
    browser_id_from_version_response(&response)
}

fn build_chrome_process_record(
    listener_pids: &[String],
    browser_id: Option<&str>,
) -> Option<ChromeProcessRecord> {
    if listener_pids.len() != 1 {
        return None;
    }
    Some(ChromeProcessRecord {
        pid: listener_pids.first()?.parse::<u32>().ok()?,
        browser_id: Some(browser_id?.to_string()),
    })
}

#[cfg(any(target_os = "linux", test))]
const LINUX_CHROME_COMMANDS: &[&str] = &["google-chrome", "google-chrome-stable"];

#[cfg(any(target_os = "linux", test))]
fn first_existing_path(paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find(|path| is_executable_file(Path::new(path)))
        .map(|path| (*path).to_string())
}

#[cfg(any(target_os = "linux", test))]
fn find_command_in_path(command: &str, path_env: Option<&std::ffi::OsStr>) -> Option<String> {
    let path_env = path_env?;

    std::env::split_paths(path_env)
        .map(|dir| dir.join(command))
        .find(|path| is_executable_file(path))
        .map(|path| path.to_string_lossy().to_string())
}

#[cfg(any(target_os = "linux", test))]
fn find_chrome_command_in_path(path_env: Option<&std::ffi::OsStr>) -> Option<String> {
    LINUX_CHROME_COMMANDS
        .iter()
        .find_map(|command| find_command_in_path(command, path_env))
}

#[cfg(any(target_os = "linux", test))]
fn find_linux_chrome_path(
    path_env: Option<&std::ffi::OsStr>,
    path_candidates: &[&str],
) -> Option<String> {
    find_chrome_command_in_path(path_env).or_else(|| first_existing_path(path_candidates))
}

fn find_chrome_path() -> Result<String, String> {
    #[cfg(target_os = "windows")]
    {
        // 1. Program Files
        if let Ok(pf) = std::env::var("ProgramFiles") {
            let path = format!(r"{}\Google\Chrome\Application\chrome.exe", pf);
            if std::path::Path::new(&path).exists() {
                return Ok(path);
            }
        } else {
            let path = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
            if std::path::Path::new(path).exists() {
                return Ok(path.to_string());
            }
        }

        // 2. Program Files (x86)
        if let Ok(pf86) = std::env::var("ProgramFiles(x86)") {
            let path = format!(r"{}\Google\Chrome\Application\chrome.exe", pf86);
            if std::path::Path::new(&path).exists() {
                return Ok(path);
            }
        } else {
            let path = r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe";
            if std::path::Path::new(path).exists() {
                return Ok(path.to_string());
            }
        }

        // 3. LocalAppData
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let path = format!(r"{}\Google\Chrome\Application\chrome.exe", local_app_data);
            if std::path::Path::new(&path).exists() {
                return Ok(path);
            }
        }

        Err("Google Chrome was not found in standard Windows installation paths. Please install Google Chrome.".to_string())
    }

    #[cfg(target_os = "macos")]
    {
        let path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
        if std::path::Path::new(path).exists() {
            Ok(path.to_string())
        } else {
            Err("Google Chrome not found at /Applications/Google Chrome.app".to_string())
        }
    }

    #[cfg(target_os = "linux")]
    {
        const LINUX_CHROME_PATHS: &[&str] = &[
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/local/bin/google-chrome",
            "/usr/local/bin/google-chrome-stable",
            "/opt/google/chrome/google-chrome",
        ];

        let path_env = std::env::var_os("PATH");
        find_linux_chrome_path(path_env.as_deref(), LINUX_CHROME_PATHS).ok_or_else(|| {
            "Google Chrome was not found in PATH or standard Linux installation paths. Please install Google Chrome or add google-chrome to PATH.".to_string()
        })
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err("Google Chrome auto-detection is not supported on this operating system. Please use macOS, Windows, or Linux.".to_string())
    }
}

/// Lexical part of [`app_bundle_from_binary`]. Components are matched
/// case-insensitively to stay consistent with `resolve_browser_binary` (the
/// default macOS volume is case-insensitive, so "Foo.APP/contents/macos" names
/// the same bundle).
#[cfg(any(target_os = "macos", test))]
fn app_bundle_from_binary_lexical(binary: &str) -> Option<String> {
    let macos_dir = Path::new(binary).parent()?;
    if !macos_dir
        .file_name()?
        .to_str()?
        .eq_ignore_ascii_case("MacOS")
    {
        return None;
    }
    let contents = macos_dir.parent()?;
    if !contents
        .file_name()?
        .to_str()?
        .eq_ignore_ascii_case("Contents")
    {
        return None;
    }
    let app = contents.parent()?;
    let is_app = app
        .extension()
        .map(|ext| ext.eq_ignore_ascii_case("app"))
        .unwrap_or(false);
    if is_app {
        Some(app.to_str()?.to_string())
    } else {
        None
    }
}

/// If `binary` is the executable inside a macOS `.app` bundle
/// (…/Foo.app/Contents/MacOS/<exe>), return the `.app` bundle path. Used to launch
/// the browser via `open -g` (background, no focus steal) instead of exec'ing the
/// binary directly, which macOS foregrounds/activates on launch. Falls back to the
/// canonicalized path so a symlink to a bundle binary is still recognized.
#[cfg(any(target_os = "macos", test))]
fn app_bundle_from_binary(binary: &str) -> Option<String> {
    app_bundle_from_binary_lexical(binary).or_else(|| {
        let real = std::fs::canonicalize(binary).ok()?;
        app_bundle_from_binary_lexical(real.to_str()?)
    })
}

/// Arguments for `open` to launch a browser bundle. `-g` (do not bring to
/// foreground) is applied only in headless mode: the login flow needs a window
/// the user can actually see and focus.
#[cfg(any(target_os = "macos", test))]
fn open_launch_args(app: &str, headless: bool, browser_args: &[String]) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    if headless {
        v.push("-g".to_string());
    }
    v.push("-n".to_string());
    v.push("-a".to_string());
    v.push(app.to_string());
    v.push("--args".to_string());
    v.extend(browser_args.iter().cloned());
    v
}

/// Run a launcher (normally `open`) and report whether it succeeded.
/// Ok(true) = launched; Ok(false) = launcher exited non-zero (caller should fall
/// back to a direct spawn); Err = the launcher itself could not be executed.
fn run_launcher(launcher: &str, args: &[String]) -> Result<bool, String> {
    let status = Command::new(launcher)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("Failed to run launcher '{}': {}", launcher, e))?;
    Ok(status.success())
}

/// Iterations (x100ms) to wait for the browser to bind the debug port. Generous:
/// `open` + LaunchServices + a post-auto-update Gatekeeper scan can take well
/// over 5s on a cold start.
const PORT_WAIT_ITERS: u32 = 200; // 20s
/// Iterations (x100ms) the hide thread waits for the debug-port PID before
/// giving up. Must be >= PORT_WAIT_ITERS so a slow-but-successful launch is
/// still hidden.
const HIDE_PID_WAIT_ITERS: u32 = 220; // 22s

fn start_chrome_if_needed(
    headless: bool,
    verbose: bool,
    browser_override: Option<&str>,
) -> Result<(), String> {
    let profile_path = chrome_profile_path()?;

    if TcpStream::connect("127.0.0.1:9223").is_ok() {
        let snapshot = inspect_chrome_debug_port(&profile_path);
        if debug_listener_scope_is_unambiguous(&snapshot.listener_pids)
            && chrome_record_matches_current(
                snapshot.record.as_ref(),
                snapshot.browser_id.as_deref(),
                &snapshot.listener_pids,
            )
        {
            if headless {
                // Force hide any existing background Chrome PIDs asynchronously just in case they are currently visible
                #[cfg(target_os = "macos")]
                {
                    let pids = snapshot.ask_pids.clone();
                    thread::spawn(move || {
                        for pid_str in pids {
                            if let Ok(pid) = pid_str.parse::<u32>() {
                                let script = format!(
                                    "tell application \"System Events\" to set visible of first application process whose unix id is {} to false",
                                    pid
                                );
                                let _ = Command::new("osascript").arg("-e").arg(&script).status();
                            }
                        }
                    });
                }
            }
            // A --browser/config override only takes effect on a fresh launch;
            // if a *different* browser already owns the debug port we reuse it,
            // so tell the user why their override appears to do nothing.
            if let Some(override_path) = browser_override {
                let running_matches = snapshot
                    .ask_pids
                    .iter()
                    .filter_map(|pid| process_command(pid))
                    .any(|cmd| command_uses_browser(&cmd, override_path));
                if !running_matches {
                    eprintln!(
                        "Note: an ask-bridge browser is already running on port 9223 with a different binary than the configured '{}'; reusing the running one. Run `ask-bridge close` first to switch browsers.",
                        override_path
                    );
                }
            }
            if verbose && headless && !is_debug_chrome_background(&profile_path) {
                println!(
                    "Reusing existing ask-bridge Chrome on port 9223. Run `ask-bridge close` if you want to restart it in background mode."
                );
            }
            return Ok(());
        }

        if debug_listener_scope_is_unambiguous(&snapshot.listener_pids)
            && !snapshot.ask_pids.is_empty()
            && build_chrome_process_record(&snapshot.listener_pids, snapshot.browser_id.as_deref())
                .is_some()
        {
            if let Some(record) =
                build_chrome_process_record(&snapshot.listener_pids, snapshot.browser_id.as_deref())
            {
                write_chrome_process_record(&record).map_err(|error| {
                    format!("Failed to update Chrome process record: {}", error)
                })?;
            }
            if verbose {
                println!("Reusing the existing ask-bridge Chrome on port 9223.");
            }
            return Ok(());
        }

        return Err(
            "Port 9223 is already used by a non-ask Chrome process. Stop it or use a different debugging port."
                .to_string(),
        );
    }

    if verbose {
        println!(
            "Chrome is not running on port 9223. Starting Chrome with remote debugging (headless: {})...",
            headless
        );
    }

    // An explicit override (already resolved to a concrete executable) wins;
    // otherwise fall back to auto-detecting Google Chrome.
    let chrome_path = match browser_override {
        Some(path) => path.to_string(),
        None => find_chrome_path()?,
    };
    let _ = remove_chrome_pid_file();

    // Suppress the "didn't shut down correctly / restore?" bubble with the
    // launch flag below. Do not rewrite Preferences here: a just-killed browser
    // may still publish a newer file after port 9223 closes, and replacing that
    // successor would lose unrelated settings.

    let mut args: Vec<String> = vec![
        "--remote-debugging-port=9223".to_string(),
        format!("--user-data-dir={}", profile_path),
        ASK_BRIDGE_CHROME_MARKER.to_string(),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        // Suppress the crash-restore prompt without mutating Preferences.
        "--hide-crash-restore-bubble".to_string(),
    ];
    if headless {
        args.push("--ask-bridge-background".to_string());
        args.push("--disable-blink-features=AutomationControlled".to_string());
        args.push("--window-size=1440,1200".to_string());
        args.push("--window-position=-2000,-2000".to_string());
    }

    // (A) On macOS, launch a `.app` bundle in the BACKGROUND via `open -g` so it
    // never activates/steals foreground (headless only — login needs a visible,
    // focusable window); `-n` forces a new instance on our dedicated profile even
    // if the same browser is the user's daily driver. Exec'ing the binary directly
    // (the fallback below) makes macOS foreground it.
    #[cfg(target_os = "macos")]
    let launched_via_open = match app_bundle_from_binary(&chrome_path) {
        Some(app) => {
            let open_args = open_launch_args(&app, headless, &args);
            match run_launcher("open", &open_args)? {
                true => true,
                false => {
                    // `open` ran but refused the launch (Gatekeeper, damaged or
                    // deleted bundle, LaunchServices error). Fall back to the
                    // direct spawn — a focus-stealing launch beats no launch —
                    // and say why instead of failing later with a port timeout.
                    eprintln!(
                        "Warning: `open` failed to launch '{}'; falling back to spawning the binary directly (window may steal focus). Run `open -n -a '{}'` manually to see why.",
                        app, app
                    );
                    false
                }
            }
        }
        None => false,
    };
    #[cfg(not(target_os = "macos"))]
    let launched_via_open = false;

    // With `open` the browser is detached — there is no child handle; the real
    // listener PID is recorded from the debug port below.
    let mut child_pid: Option<u32> = None;
    if !launched_via_open {
        let mut cmd = Command::new(&chrome_path);
        for a in &args {
            cmd.arg(a);
        }

        #[cfg(target_os = "windows")]
        {
            const DETACHED_PROCESS: u32 = 0x0000_0008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        }

        let child = cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("Failed to start browser '{}': {}", chrome_path, e))?;
        child_pid = Some(child.id());
    }

    if verbose {
        match child_pid {
            Some(pid) => println!(
                "Started ask-bridge Chrome PID {} with profile {}.",
                pid, profile_path
            ),
            None => println!(
                "Started ask-bridge browser via `open` with profile {}.",
                profile_path
            ),
        }
    }

    // (A) Hide the window as a secondary mitigation (the off-screen position is
    // clamped back on-screen by macOS). Re-keyed off the debug-port PID because
    // `open` detaches — its child PID is not the browser — and this also dampens
    // the per-CDP-command re-activation (chrome-devtools-mcp#1254) no flag fixes.
    #[cfg(target_os = "macos")]
    {
        if headless {
            let profile = profile_path.clone();
            thread::spawn(move || {
                for _ in 0..HIDE_PID_WAIT_ITERS {
                    let pids = ask_chrome_pids_on_debug_port(&profile);
                    if !pids.is_empty() {
                        for _ in 0..40 {
                            for pid in &pids {
                                if let Ok(p) = pid.parse::<u32>() {
                                    let script = format!(
                                        "tell application \"System Events\" to try\nset visible of first application process whose unix id is {} to false\nend try",
                                        p
                                    );
                                    let _ =
                                        Command::new("osascript").arg("-e").arg(&script).status();
                                }
                            }
                            thread::sleep(Duration::from_millis(50));
                        }
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            });
        }
    }

    // Wait for the browser to listen on port 9223 and prove that the listener
    // belongs to this launch. Generous budget: see PORT_WAIT_ITERS
    // (open/LaunchServices + post-update Gatekeeper scans).
    let mut last_identity_error = None;
    for _ in 0..PORT_WAIT_ITERS {
        if TcpStream::connect("127.0.0.1:9223").is_ok() {
            let snapshot = inspect_chrome_debug_port(&profile_path);
            if let Some(record) =
                build_chrome_process_record(&snapshot.listener_pids, snapshot.browser_id.as_deref())
            {
                if let Err(error) = write_chrome_process_record(&record) {
                    return Err(format!(
                        "Failed to record Chrome process identity: {}",
                        error
                    ));
                }
                if let Some(launcher_pid) = child_pid
                    && verbose
                    && record.pid != launcher_pid
                {
                    println!(
                        "Recorded actual Chrome listener PID {} (launcher PID {}).",
                        record.pid, launcher_pid
                    );
                }
                if verbose {
                    println!("Chrome started and listening on port 9223.");
                }
                return Ok(());
            }
            last_identity_error = Some(
                "Chrome did not expose a valid CDP browser identity on port 9223.".to_string(),
            );
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = remove_chrome_pid_file();
    match last_identity_error {
        Some(error) => Err(format!(
            "Failed to identify active Chrome listener: {}",
            error
        )),
        None => Err(format!(
            "Timed out waiting for browser '{}' to start on port 9223",
            chrome_path
        )),
    }
}

fn normalize_profile_match_text(value: &str) -> String {
    let normalized = value.replace('\\', "/").replace(['"', '\''], "");

    #[cfg(target_os = "windows")]
    {
        normalized.to_ascii_lowercase()
    }

    #[cfg(not(target_os = "windows"))]
    {
        normalized
    }
}

fn command_has_argument(command: &str, argument: &str) -> bool {
    command.match_indices(argument).any(|(start, matched)| {
        let before_is_boundary = start == 0
            || command[..start]
                .chars()
                .next_back()
                .map(char::is_whitespace)
                .unwrap_or(false);
        let end = start + matched.len();
        let after_is_boundary = end == command.len()
            || command[end..]
                .chars()
                .next()
                .map(char::is_whitespace)
                .unwrap_or(false);
        before_is_boundary && after_is_boundary
    })
}

fn command_uses_profile(command: &str, profile_path: &str) -> bool {
    let command = normalize_profile_match_text(command);
    let profile_path = normalize_profile_match_text(profile_path);

    command_has_argument(&command, &format!("--user-data-dir={}", profile_path))
        || command_has_argument(&command, &format!("--user-data-dir {}", profile_path))
}

fn command_identifies_ask_chrome(command: &str, profile_path: &str) -> bool {
    command_uses_profile(command, profile_path)
        || command_has_argument(command, ASK_BRIDGE_CHROME_MARKER)
}

fn find_ask_chrome_owner_pid_with<C, P>(
    listener_pid: &str,
    profile_path: &str,
    mut command_for: C,
    mut parent_for: P,
) -> Option<String>
where
    C: FnMut(&str) -> Option<String>,
    P: FnMut(&str) -> Option<String>,
{
    let mut current_pid = listener_pid.to_string();

    for _ in 0..16 {
        if command_for(&current_pid)
            .map(|command| command_identifies_ask_chrome(&command, profile_path))
            .unwrap_or(false)
        {
            return Some(current_pid);
        }

        let parent_pid = parent_for(&current_pid)?;
        if parent_pid.is_empty() || parent_pid == "0" || parent_pid == current_pid {
            return None;
        }
        current_pid = parent_pid;
    }

    None
}

fn chrome_record_matches_browser(record: &ChromeProcessRecord, browser_id: Option<&str>) -> bool {
    matches!(
        (record.browser_id.as_deref(), browser_id),
        (Some(recorded_id), Some(current_id)) if recorded_id == current_id
    )
}

fn chrome_record_matches_current(
    record: Option<&ChromeProcessRecord>,
    browser_id: Option<&str>,
    listener_pids: &[String],
) -> bool {
    record.is_some_and(|record| chrome_record_matches_browser(record, browser_id))
        && listener_pids.len() == 1
}

fn find_ask_chrome_owner_pids_with<C, P>(
    listener_pids: &[String],
    profile_path: &str,
    mut command_for: C,
    mut parent_for: P,
) -> Vec<String>
where
    C: FnMut(&str) -> Option<String>,
    P: FnMut(&str) -> Option<String>,
{
    let mut ask_pids = Vec::new();
    for listener_pid in listener_pids {
        let ask_pid = find_ask_chrome_owner_pid_with(
            listener_pid,
            profile_path,
            &mut command_for,
            &mut parent_for,
        );

        if let Some(ask_pid) = ask_pid
            && !ask_pids.contains(&ask_pid)
        {
            ask_pids.push(ask_pid);
        }
    }
    ask_pids
}

struct ChromeDebugSnapshot {
    listener_pids: Vec<String>,
    record: Option<ChromeProcessRecord>,
    browser_id: Option<String>,
    ask_pids: Vec<String>,
}

#[cfg(any(target_os = "windows", test))]
fn same_pid_set(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().all(|pid| right.contains(pid))
}

/// Return force-kill targets only when a fresh inspection proves that the
/// listener and ask-bridge owner identities are unchanged from the pre-TERM
/// snapshot. The pid sets were themselves proven by walking parents until the
/// command line carried the dedicated profile or the ask-bridge marker — that
/// identity needs no CDP. The CDP browser UUID is corroborating evidence only
/// when BOTH snapshots have one; a hung browser (CDP dead → `browser_id:
/// None`) is the very case the force branch exists for and must not be
/// blocked on it.
#[cfg(any(target_os = "windows", test))]
fn validated_force_kill_pids(
    initial: &ChromeDebugSnapshot,
    current: &ChromeDebugSnapshot,
) -> Option<Vec<String>> {
    if let (Some(initial_id), Some(current_id)) =
        (initial.browser_id.as_deref(), current.browser_id.as_deref())
        && initial_id != current_id
    {
        return None;
    }
    if !debug_listener_scope_is_unambiguous(&current.listener_pids)
        || current.ask_pids.is_empty()
        || !same_pid_set(&initial.listener_pids, &current.listener_pids)
        || !same_pid_set(&initial.ask_pids, &current.ask_pids)
    {
        return None;
    }
    Some(current.ask_pids.clone())
}

fn debug_listener_scope_is_unambiguous(listener_pids: &[String]) -> bool {
    listener_pids.len() <= 1
}

/// A fresh inspection that finds neither a port-9223 listener nor an
/// ask-bridge owner means the browser finished dying (e.g. just after the
/// last graceful-shutdown port poll): that is a SUCCESSFUL close, not an
/// identity failure. Callers must still confirm the probe itself ran (the
/// port really stopped accepting connections) before trusting this.
#[cfg(any(target_os = "windows", test))]
fn snapshot_shows_browser_gone(current: &ChromeDebugSnapshot) -> bool {
    current.listener_pids.is_empty() && current.ask_pids.is_empty()
}

fn inspect_chrome_debug_port(profile_path: &str) -> ChromeDebugSnapshot {
    let listener_pids = debug_port_listener_pids();
    let record = read_chrome_process_record();
    let browser_id = debug_browser_id();
    let ask_pids = find_ask_chrome_owner_pids_with(
        &listener_pids,
        profile_path,
        process_command,
        process_parent_pid,
    );
    ChromeDebugSnapshot {
        listener_pids,
        record,
        browser_id,
        ask_pids,
    }
}

/// Whether the running listener's command line refers to the given resolved
/// browser executable. Used to warn when a --browser/config override differs
/// from the browser already occupying the debug port.
fn command_uses_browser(command: &str, browser_path: &str) -> bool {
    let command = normalize_profile_match_text(command);
    let browser_path = normalize_profile_match_text(browser_path);
    !browser_path.is_empty() && command.contains(&browser_path)
}

/// Whether a single open tab is a "blank"/new-tab page that ask-bridge may
/// navigate directly instead of opening a new tab. Matches about:blank, the
/// Chrome new-tab-page marker, and browser-internal welcome/newtab pages
/// (chrome://, brave://, edge://, ...) — but NOT an ordinary http(s) URL whose
/// host merely starts with "newtab" (e.g. https://newtab.example.com).
fn is_blank_tab_url(url: &str) -> bool {
    if url == "about:blank" || url.contains("new-tab-page") {
        return true;
    }
    match url.split_once("://") {
        Some((scheme, rest)) if scheme != "http" && scheme != "https" => {
            rest.starts_with("newtab") || rest.starts_with("welcome")
        }
        _ => false,
    }
}

fn ask_chrome_pids_on_debug_port(profile_path: &str) -> Vec<String> {
    inspect_chrome_debug_port(profile_path).ask_pids
}

// `test` included so the platform-independent parser tests compile on non-Windows.
#[cfg(any(target_os = "windows", test))]
fn parse_windows_netstat_listener_pids(output: &str, port: u16) -> Vec<String> {
    let mut pids = Vec::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5
            || !fields[0].eq_ignore_ascii_case("TCP")
            || !fields[3].eq_ignore_ascii_case("LISTENING")
            || fields[1]
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
                != Some(port)
        {
            continue;
        }

        let pid = fields[4];
        if pid.chars().all(|character| character.is_ascii_digit())
            && !pids.iter().any(|existing| existing == pid)
        {
            pids.push(pid.to_string());
        }
    }
    pids
}

fn debug_port_listener_pids() -> Vec<String> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("netstat").args(["-ano", "-p", "tcp"]).output();

        match output {
            Ok(output) if output.status.success() => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                parse_windows_netstat_listener_pids(&stdout, 9223)
            }
            _ => Vec::new(),
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("lsof")
            .args(["-tiTCP:9223", "-sTCP:LISTEN"])
            .output();

        match output {
            Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        }
    }
}

// `test` included so the platform-independent parser tests compile on non-Windows.
#[cfg(any(target_os = "windows", test))]
fn parse_wmic_column_value(output: &str) -> Option<String> {
    let mut non_empty_lines = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty());
    non_empty_lines.next()?;
    non_empty_lines.next().map(str::to_string)
}

fn process_command(pid: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("wmic")
            .args([
                "process",
                "where",
                &format!("processid={}", pid),
                "get",
                "commandline",
            ])
            .output();

        if let Ok(out) = output
            && out.status.success()
        {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if let Some(command) = parse_wmic_column_value(&stdout) {
                return Some(command);
            }
        }

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "(Get-CimInstance Win32_Process -Filter 'ProcessId = {}').CommandLine",
                    pid
                ),
            ])
            .output();

        if let Ok(out) = output
            && out.status.success()
        {
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !stdout.is_empty() {
                return Some(stdout);
            }
        }

        None
    }

    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("ps")
            .args(["-p", pid, "-o", "command="])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

fn process_is_alive(pid: &str) -> Option<bool> {
    if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    #[cfg(target_os = "windows")]
    {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "$p = Get-Process -Id {} -ErrorAction SilentlyContinue; \
                     if ($null -eq $p) {{ [Console]::Write('missing') }} \
                     else {{ [Console]::Write('alive') }}",
                    pid
                ),
            ])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }
        match String::from_utf8_lossy(&output.stdout).trim() {
            "alive" => Some(true),
            "missing" => Some(false),
            _ => None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("ps")
            .args(["-p", pid, "-o", "pid="])
            .output()
            .ok()?;
        if !output.status.success() {
            return Some(false);
        }
        Some(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
    }
}

fn process_parent_pid(pid: &str) -> Option<String> {
    #[cfg(target_os = "windows")]
    {
        let output = Command::new("wmic")
            .args([
                "process",
                "where",
                &format!("processid={}", pid),
                "get",
                "parentprocessid",
            ])
            .output();

        if let Ok(out) = output
            && out.status.success()
            && let Some(parent_pid) = parse_wmic_column_value(&String::from_utf8_lossy(&out.stdout))
        {
            return Some(parent_pid);
        }

        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "(Get-CimInstance Win32_Process -Filter 'ProcessId = {}').ParentProcessId",
                    pid
                ),
            ])
            .output();

        if let Ok(out) = output
            && out.status.success()
        {
            let parent_pid = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !parent_pid.is_empty() {
                return Some(parent_pid);
            }
        }

        None
    }

    #[cfg(not(target_os = "windows"))]
    {
        let output = Command::new("ps")
            .args(["-p", pid, "-o", "ppid="])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let parent_pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if parent_pid.is_empty() {
            None
        } else {
            Some(parent_pid)
        }
    }
}

fn is_debug_chrome_background(profile_path: &str) -> bool {
    ask_chrome_pids_on_debug_port(profile_path)
        .iter()
        .any(|pid| {
            process_command(pid)
                .map(|cmd| cmd.contains("--ask-bridge-background"))
                .unwrap_or(false)
        })
}

fn ask_chrome_pids_are_gone_with<C, L>(
    pids: &[String],
    profile_path: &str,
    mut command_for: C,
    mut is_alive: L,
) -> bool
where
    C: FnMut(&str) -> Option<String>,
    L: FnMut(&str) -> Option<bool>,
{
    pids.iter().all(|pid| match command_for(pid) {
        Some(command) if !command.trim().is_empty() => {
            !command_identifies_ask_chrome(&command, profile_path)
        }
        // A command-line probe can fail or succeed without returning a usable
        // command because WMIC/PowerShell/ps is unavailable, denied, or
        // redacted. Treat the PID as gone only when a separate liveness probe
        // proves absence.
        Some(_) | None => matches!(is_alive(pid), Some(false)),
    })
}

/// Wait (bounded, iters x 100ms) until none of `pids` is running as ask
/// chrome. Returns true if they all exited (or were reused by unrelated
/// processes). Needed because a Chromium browser closes its debug port BEFORE
/// it finishes dying: if a relaunch races the dying process, the new instance
/// sees the old SingletonLock, forwards to it (activating its window — a
/// focus steal), exits, and nothing ever binds the port again.
fn wait_for_ask_chrome_pids_to_exit(pids: &[String], profile_path: &str, iters: u32) -> bool {
    for _ in 0..iters {
        if ask_chrome_pids_are_gone_with(pids, profile_path, process_command, process_is_alive) {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn require_ask_chrome_pids_to_exit(
    pids: &[String],
    profile_path: &str,
    iters: u32,
) -> Result<(), String> {
    if wait_for_ask_chrome_pids_to_exit(pids, profile_path, iters) {
        Ok(())
    } else {
        Err(format!(
            "Debug port closed, but browser process(es) {} are still running",
            pids.join(", ")
        ))
    }
}

fn close_ask_chrome_on_debug_port(profile_path: &str) -> Result<bool, String> {
    let snapshot = inspect_chrome_debug_port(profile_path);
    if snapshot.listener_pids.is_empty() {
        if TcpStream::connect("127.0.0.1:9223").is_ok() {
            return Err(
                "Port 9223 is active, but ask-bridge could not identify its listener process. No process was closed."
                    .to_string(),
            );
        }
        if let Err(_error) = remove_chrome_pid_file() {
            // ignore cleanup failure when port is already closed
        }
        return Ok(false);
    }
    if !debug_listener_scope_is_unambiguous(&snapshot.listener_pids) {
        return Err(
            "Multiple processes are listening on port 9223, so ask-bridge cannot safely determine which process to close. No process was closed."
                .to_string(),
        );
    }

    if snapshot.ask_pids.is_empty() {
        return Err(
            "Port 9223 is already used by a non-ask Chrome process. Stop it or use a different debugging port."
                .to_string(),
        );
    }

    for pid in &snapshot.ask_pids {
        #[cfg(target_os = "windows")]
        {
            let _ = Command::new("taskkill").args(["/PID", pid, "/T"]).status();
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = Command::new("kill").args(["-TERM", pid]).status();
        }
    }

    for _ in 0..50 {
        if TcpStream::connect("127.0.0.1:9223").is_err() {
            // Port closed is NOT process gone: wait for the PIDs to actually
            // exit so an immediate relaunch can't hit the old SingletonLock.
            require_ask_chrome_pids_to_exit(&snapshot.ask_pids, profile_path, 100)?;
            let _ = remove_chrome_pid_file();
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(100));
    }

    #[cfg(target_os = "windows")]
    {
        let current = inspect_chrome_debug_port(profile_path);
        if snapshot_shows_browser_gone(&current) {
            // Distinguish "probe ran, found nothing" (graceful exit finished
            // right after the last port poll — success) from "probe failed to
            // execute" (netstat/wmic unavailable while the port is still
            // wedged — error).
            if TcpStream::connect("127.0.0.1:9223").is_ok() {
                return Err(
                    "Port 9223 is still open, but its owner could not be re-identified; refusing to force-kill any PID."
                        .to_string(),
                );
            }
            require_ask_chrome_pids_to_exit(&snapshot.ask_pids, profile_path, 100)?;
            let _ = remove_chrome_pid_file();
            return Ok(true);
        }
        let force_kill_pids = validated_force_kill_pids(&snapshot, &current).ok_or_else(|| {
            "Browser identity changed while waiting for graceful shutdown; refusing to force-kill any PID."
                .to_string()
        })?;
        for pid in &force_kill_pids {
            let _ = Command::new("taskkill")
                .arg("/F")
                .arg("/PID")
                .arg(pid)
                .status();
        }

        for _ in 0..50 {
            if TcpStream::connect("127.0.0.1:9223").is_err() {
                require_ask_chrome_pids_to_exit(&force_kill_pids, profile_path, 100)?;
                let _ = remove_chrome_pid_file();
                return Ok(true);
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    Err("Timed out waiting for existing ask-bridge Chrome to stop".to_string())
}

static FORWARD_MCP_STDERR: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// One MCP session per run: a single long-lived chrome-devtools-mcp child plus
/// the tokio runtime that drives its background reader tasks.
///
/// Upstream called `McpClient::call_tool` per browser action, which spawns a
/// fresh `npx chrome-devtools-mcp` child for every single action (~50 per
/// query) and waits on its response without any timeout — one stalled npx
/// spawn hung the whole run forever (2026-07-11). Reusing one connection
/// removes the re-spawn churn; `MCP_CALL_TIMEOUT` turns any remaining stall
/// into a loud, bounded error (see `mcp_error_is_transport` for why the failed
/// call is not replayed).
struct McpSession {
    connection: McpConnection,
    runtime: tokio::runtime::Runtime,
    config_path: String,
}

static MCP_SESSION: std::sync::Mutex<Option<McpSession>> = std::sync::Mutex::new(None);

const MCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
const MCP_CALL_TIMEOUT: Duration = Duration::from_secs(90);
const MCP_CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

fn mcp_session_connect(config_path: &str) -> Result<McpSession, String> {
    let client = McpClient::load(Some(config_path))
        .map_err(|e| format!("Failed to load MCP config: {}", e))?;
    let server_config = client
        .server_config("chrome-devtools")
        .map_err(|e| format!("Missing chrome-devtools MCP server config: {}", e))?;
    // A multi-thread runtime with one worker keeps the connection's background
    // stdout/stderr reader tasks running between calls (a current-thread
    // runtime only makes progress inside block_on).
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create async runtime for MCP session: {}", e))?;
    let connection = runtime.block_on(async {
        // Connect the stdio transport directly: mcp-cli's default path first
        // tries its persistent daemon, which re-execs this binary with
        // `--daemon` — an entrypoint ask-bridge does not implement — so that
        // path can only ever fail and fall back.
        let connect_future = async {
            match &server_config {
                ServerConfig::Stdio(stdio_config) => {
                    StdioClient::connect("chrome-devtools", stdio_config)
                        .await
                        .map(McpConnection::Stdio)
                }
                _ => client.connect("chrome-devtools").await,
            }
        };
        match tokio::time::timeout(MCP_CONNECT_TIMEOUT, connect_future).await {
            Err(_) => Err(format!(
                "Failed to start chrome-devtools MCP server: timed out after {}s",
                MCP_CONNECT_TIMEOUT.as_secs()
            )),
            Ok(result) => {
                result.map_err(|e| format!("Failed to start chrome-devtools MCP server: {}", e))
            }
        }
    })?;
    Ok(McpSession {
        connection,
        runtime,
        config_path: config_path.to_string(),
    })
}

fn mcp_session_reset(slot: &mut Option<McpSession>) {
    if let Some(session) = slot.take() {
        let McpSession {
            connection,
            runtime,
            ..
        } = session;
        // Best-effort close (kills the child); if even that stalls, dropping
        // the runtime stops the background tasks and the orphaned child exits
        // on stdin EOF.
        let _ = runtime
            .block_on(async { tokio::time::timeout(MCP_CLOSE_TIMEOUT, connection.close()).await });
    }
}

fn mcp_session_call(
    slot: &mut Option<McpSession>,
    config_path: &str,
    tool: &str,
    args: Value,
) -> Result<Value, String> {
    let needs_connect = slot
        .as_ref()
        .map(|session| session.config_path != config_path)
        .unwrap_or(true);
    if needs_connect {
        mcp_session_reset(slot);
        *slot = Some(mcp_session_connect(config_path)?);
    }
    let session = slot.as_ref().expect("session connected above");
    session.runtime.block_on(async {
        match tokio::time::timeout(MCP_CALL_TIMEOUT, session.connection.call_tool(tool, args)).await
        {
            Err(_) => Err(format!(
                "MCP tool '{}' timed out after {}s",
                tool,
                MCP_CALL_TIMEOUT.as_secs()
            )),
            Ok(result) => result.map_err(|e| format!("mcp-cli library call failed: {}", e)),
        }
    })
}

/// Errors that mean the MCP transport itself is dead or wedged: our own
/// timeouts, or transport-level failures (dead child / closed pipes — exact
/// phrases from mcp-cli's StdioClient). These earn a session reset so the next
/// command starts clean. The failed call is deliberately NOT replayed: a
/// timed-out request may already have executed in the browser (replaying a
/// submit would double-post), and a fresh chrome-devtools-mcp child forgets
/// the selected page (a replay could act on the wrong tab). Application-level
/// tool errors (e.g. a JS exception from evaluate_script) propagate unchanged.
fn mcp_error_is_transport(message: &str) -> bool {
    let lower = message.to_lowercase();
    lower.contains("timed out")
        || lower.contains("failed to send request to process stdin")
        || lower.contains("server process exited unexpectedly")
        || lower.contains("stdio response receiver canceled")
        || lower.contains("failed to start chrome-devtools mcp server")
}

fn call_mcp_tool(config_path: &str, tool: &str, args: Value) -> Result<Value, String> {
    let _stderr_guard = if FORWARD_MCP_STDERR.load(std::sync::atomic::Ordering::Relaxed) {
        None
    } else {
        Some(
            gag::Gag::stderr()
                .map_err(|e| format!("Failed to suppress MCP stderr in quiet mode: {}", e))?,
        )
    };

    let mut slot = MCP_SESSION
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match mcp_session_call(&mut slot, config_path, tool, args) {
        Ok(value) => Ok(value),
        Err(error) => {
            if mcp_error_is_transport(&error) {
                mcp_session_reset(&mut slot);
                return Err(format!(
                    "{} (MCP session was reset; re-run the command)",
                    error
                ));
            }
            Err(error)
        }
    }
}

/// Extract the `## Pages` listing out of an MCP tool result. `list_pages`,
/// `new_page`, `select_page` and `close_page` all echo the current page list,
/// so every caller that needs page IDs goes through here.
fn pages_from_tool_result(res: &Value, context: &str) -> Result<Vec<Page>, String> {
    let text = res
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| format!("Invalid {} response structure: {:?}", context, res))?;
    Ok(parse_pages(text))
}

/// Schemes that can appear as a *whole tab's* URL with a raw space in them.
///
/// The list is what makes the ambiguity rule in [`page_url_from_label`] narrow
/// enough to be usable, so it is an allow-list of things a browser can actually
/// do, not of things a URL parser would tolerate. Three conditions have to hold
/// together: chrome-devtools-mcp can list a top-level document on the scheme,
/// its path is *opaque* (so the serialiser's C0-control set leaves SPACE
/// verbatim instead of writing `%20`), and its content is chosen by whoever
/// opened the tab rather than minted by the browser.
///
/// `data:` meets all three, and is the only scheme that does:
/// * `blob:` is a real top-level document URL, but the UA mints
///   `blob:<origin>/<uuid>` -- no caller input, no space.
/// * `about:` is likewise UA-minted (`about:blank`, `about:srcdoc`).
/// * `filesystem:` and `view-source:` wrap a *hierarchical* URL, which is
///   percent-encoded on the way in, so no raw space survives either.
/// * `mailto:` and `javascript:` never become a top-level document URL at all:
///   Chrome hands `mailto:` to an external protocol handler, and a
///   `javascript:` navigation replaces the document without changing its URL.
///
/// Excluding a scheme is not a hole. Whitespace-free candidates of *every*
/// scheme stay possible (see [`is_possible_page_url`]), so this list only
/// decides which lines are ambiguous; and if a scheme ever did reach a tab with
/// a space in it, [`verify_selected_page_is_provider`] asks the tab itself
/// before any prompt is typed.
const SPACE_BEARING_PAGE_SCHEMES: [&str; 1] = ["data"];

/// Whether `candidate` could be a value of `page.url()` at all -- i.e. whether
/// a browser could have put a tab on this exact string.
///
/// A URL starts with a scheme (`ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"`)
/// and, for everything outside [`SPACE_BEARING_PAGE_SCHEMES`], carries no
/// whitespace: SPACE is in the path, query and fragment percent-encode sets, so
/// `https://evil.test/a b` serialises as `a%20b`.
fn is_possible_page_url(candidate: &str) -> bool {
    let Some((scheme, _rest)) = candidate.split_once(':') else {
        return false;
    };
    let mut scheme_chars = scheme.chars();
    if !scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if !scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return false;
    }
    if candidate.chars().any(char::is_control) {
        return false;
    }
    if !candidate.chars().any(char::is_whitespace) {
        return true;
    }
    SPACE_BEARING_PAGE_SCHEMES
        .iter()
        .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
}

/// chrome-devtools-mcp renders a page as `<title> (<url>)` when the page has a
/// title and as a bare `<url>` when it does not (McpResponse.js:664).
///
/// Reading that back is guesswork: the separator is a bare ` (`, and both
/// halves are chosen by the page. So this returns a URL only when exactly one
/// reading of the line is possible, and `None` -- "this tab's URL is unknown"
/// -- otherwise. `None` is never "no provider matched but here is a string
/// anyway": see [`Page::url`] for what the callers owe it.
///
/// # Why "the trailing parenthesised group" was not enough
///
/// Taking the last ` (` rests on `page.url()` never containing one. That holds
/// wherever the serialiser percent-encodes SPACE, but not for a `data:` URL
/// (see [`SPACE_BEARING_PAGE_SCHEMES`]), so a `data:` page can put a literal
/// ` (` inside its own URL and decide what the trailing group is.
/// `data:text/html,<title>Free VPN</title>x (https://chatgpt.com/` renders as a
/// line whose trailing group is `https://chatgpt.com/`; that tab was then
/// adopted as the provider's, selected, and typed into.
///
/// # The rule
///
/// Every ` (`-to-final-`)` split is a possible reading, and so is the whole
/// line (an untitled page). Readings a browser could not have produced are
/// discarded. Exactly one survivor is the answer; zero or two or more means the
/// line is ambiguous and the tab is treated as unidentified.
///
/// A forgery always leaves **two** survivors, because the attacker's own
/// `data:` URL is itself always one of them -- it starts either at the line
/// start or at the ` (` the server put in front of it -- so it can never yield
/// a unique provider reading. Ordinary parenthesised titles are unaffected:
/// `Fix bug (error: undefined)` produces the candidate `error: undefined) (...`,
/// which has a space and a scheme that is not `data:`, so it is discarded and
/// the real URL is the only survivor.
fn page_url_from_label(label: &str) -> Option<&str> {
    let titled = label
        .strip_suffix(')')
        .into_iter()
        .flat_map(|inner| inner.match_indices(" (").map(|(at, _)| &inner[at + 2..]));
    let mut readings = std::iter::once(label)
        .chain(titled)
        .filter(|reading| is_possible_page_url(reading));
    match (readings.next(), readings.next()) {
        (Some(url), None) => Some(url),
        _ => None,
    }
}

/// Strip the trailing ` isolatedContext=<name>` marker that is appended after
/// `[selected]` (McpResponse.js:666).
///
/// This is not opt-in: chrome-devtools-mcp auto-discovers externally created
/// BrowserContexts and names them `isolated-context-<n>` (McpContext.js:513-519),
/// so a user opening one incognito window is enough to put the marker on a line.
/// Without stripping it, a titled provider page in that window parses to the
/// whole label and becomes invisible -- every run opens another tab and `--new`
/// can never close them.
///
/// The marker is honoured only when the entire tail is one space-free token.
/// Generated names never contain a space, but a hostile page *title* can embed
/// the literal marker; splitting on those would truncate the label back to
/// title text and hand host selection to the page again.
///
/// The space-free-token rule closes the *title* side only. A page whose **URL**
/// has an opaque path can still embed the marker there -- `data:text/html,x
/// isolatedContext=y` leaves the name `y)`, which is non-empty and space-free,
/// so the guard accepts it and truncates the label mid-URL. Nothing here can
/// tell that apart from a real marker; what stops it is that the truncated
/// remainder is no longer a readable line, so [`page_url_from_label`] reports
/// the tab as unidentified rather than reading the host out of the title. See
/// `known_gap_g3_url_can_forge_the_isolated_context_marker`.
fn strip_isolated_context_suffix(rest: &str) -> &str {
    match rest.rsplit_once(" isolatedContext=") {
        Some((head, name)) if !name.is_empty() && !name.contains(' ') => head.trim_end(),
        _ => rest,
    }
}

fn parse_pages(text: &str) -> Vec<Page> {
    let mut pages = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("##") {
            continue;
        }
        if let Some((id_str, rest)) = line.split_once(':') {
            let id = match id_str.trim().parse::<usize>() {
                Ok(id) => id,
                Err(_) => continue,
            };
            // Line grammar (McpResponse.js:666):
            //   <id>: <label>[ [selected]][ isolatedContext=<name>]
            // Peel the optional suffixes right to left, in that order.
            //
            // The space is part of the marker: upstream emits `' [selected]'`,
            // and `<label>` is `<title> (<url>)` or a bare URL, so it is never
            // empty and the space is always there. Matching the bare suffix
            // instead reads any URL that happens to end in those six characters
            // as a second selected page -- and since `created_page_id` treats
            // two claimants as "cannot identify", that is enough to abort an
            // otherwise uncontested run.
            let rest = strip_isolated_context_suffix(rest.trim());
            let (label, selected) = match rest.strip_suffix(" [selected]") {
                Some(label) => (label.trim(), true),
                None => (rest, false),
            };
            let url = page_url_from_label(label).map(str::to_string);
            pages.push(Page { id, url, selected });
        }
    }
    pages
}

fn parse_script_result(val: &Value) -> Result<Value, String> {
    let text = val
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| "Could not extract text field from evaluate_script result".to_string())?;

    let start_tag = "```json";

    if let Some(start_pos) = text.find(start_tag) {
        let json_start = start_pos + start_tag.len();
        let json_str = text[json_start..].trim_start();
        let mut values = serde_json::Deserializer::from_str(json_str).into_iter::<Value>();
        let parsed = values
            .next()
            .ok_or_else(|| "JSON parsing error: missing JSON value".to_string())?
            .map_err(|e| format!("JSON parsing error: {}", e))?;
        let remainder = json_str[values.byte_offset()..].trim_start();
        let after_fence = remainder
            .strip_prefix("```")
            .ok_or_else(|| "Could not find closing JSON fence in script result".to_string())?;
        if !matches!(after_fence.chars().next(), None | Some('\r') | Some('\n')) {
            return Err("Invalid closing JSON fence in script result".to_string());
        }
        return Ok(parsed);
    }

    Err("Could not find JSON fencing in script result".to_string())
}

/// The image bytes in a `take_screenshot` response, or why there are none.
///
/// `Err` is the point. `ask-bridge screenshot` exists to leave a file behind,
/// and its caller is a script that checks the exit status and then reads
/// `target/screenshot.png` back. Printing "no image" and exiting 0 makes that
/// script read whatever the *previous* run left there -- or nothing at all --
/// and call it this run's screenshot.
///
/// The error says what was wrong with the response and never quotes the
/// response: a screenshot reply is the base64 of a logged-in page, and it is
/// the last thing that should be echoed into a CI log.
fn screenshot_png_bytes(res: &Value) -> Result<Vec<u8>, String> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let mut images = 0usize;
    let mut last_error: Option<String> = None;
    if let Some(arr) = res.get("content").and_then(|c| c.as_array()) {
        for item in arr {
            let Some(data) = item
                .get("type")
                .filter(|t| t.as_str() == Some("image"))
                .and_then(|_| item.get("data"))
                .and_then(|d| d.as_str())
            else {
                continue;
            };
            images += 1;
            match STANDARD.decode(data.trim()) {
                Ok(bytes) => return Ok(bytes),
                Err(e) => last_error = Some(e.to_string()),
            }
        }
    }

    Err(match last_error {
        Some(e) => format!(
            "take_screenshot returned {} image item(s) and none of them decoded as base64: {}",
            images, e
        ),
        None => "take_screenshot returned no image content".to_string(),
    })
}

fn tool_text(val: &Value) -> Result<String, String> {
    val.get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("text"))
        .and_then(|t| t.as_str())
        .map(|text| text.to_string())
        .ok_or_else(|| format!("Could not extract text field from tool result: {:?}", val))
}

fn take_snapshot_text(config_path: &str) -> Result<String, String> {
    let res = call_mcp_tool(config_path, "take_snapshot", serde_json::json!({}))?;
    tool_text(&res)
}

fn extract_snapshot_uid(line: &str) -> Option<String> {
    let marker_pos = line.find("uid=")?;
    let mut rest = line[marker_pos + 4..].trim_start();
    rest = rest.trim_start_matches(['"', '\'', '[']);
    let uid: String = rest
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'' && *c != ']')
        .collect();
    if uid.is_empty() { None } else { Some(uid) }
}

fn find_snapshot_uid(snapshot: &str, include: &[&str], exclude: &[&str]) -> Option<String> {
    snapshot.lines().find_map(|line| {
        let lower = line.to_lowercase();
        let includes_all = include
            .iter()
            .all(|needle| lower.contains(&needle.to_lowercase()));
        let excludes_all = exclude
            .iter()
            .all(|needle| !lower.contains(&needle.to_lowercase()));
        if includes_all && excludes_all {
            extract_snapshot_uid(line)
        } else {
            None
        }
    })
}

fn is_glow_available() -> bool {
    Command::new("glow")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn render_markdown(markdown: &str, use_glow: bool) -> Result<(), String> {
    if markdown.is_empty() {
        return Ok(());
    }

    if use_glow {
        let glow = Command::new("glow")
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn();

        if let Ok(mut child) = glow {
            let stdin_opt = child.stdin.take();
            if let Some(mut stdin) = stdin_opt {
                let _ = stdin.write_all(markdown.as_bytes()).map_err(|e| {
                    eprintln!("Failed to send Markdown content to glow: {}", e);
                });
            }

            match child.wait() {
                Ok(status) if status.success() => {
                    return Ok(());
                }
                Ok(status) => {
                    eprintln!("glow exited with status: {}", status);
                }
                Err(e) => {
                    eprintln!("Failed to wait for glow process: {}", e);
                }
            }
        }
    }

    print!("{}", markdown);
    io::stdout()
        .flush()
        .map_err(|e| format!("Failed to flush stdout: {}", e))?;

    Ok(())
}

fn validate_provider_feature_support(provider: Provider, cli: &Cli) -> Result<(), String> {
    if cli.session.is_some() && cli.command.is_some() {
        return Err(
            "--session is supported only for a prompt invocation, not with a subcommand"
                .to_string(),
        );
    }

    if provider == Provider::Gemini && !cli.images.is_empty() {
        return Err(
            "Gemini image attachments are not supported yet. Use --file for Gemini document attachments."
                .to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    /// Build the `--output` value a test wants to aim at. Goes through the same
    /// `FromStr` clap uses, so tests exercise the real construction path and
    /// still cannot read the path back out — the point of the type.
    fn markdown_output_at(path: &std::path::Path) -> MarkdownOutput {
        path.to_str().unwrap().parse().unwrap()
    }

    #[test]
    fn validates_chrome_devtools_mcp_node_versions() {
        for version in [
            "v20.19.0",
            "v20.20.1\r\n",
            "v22.12.0",
            "v22.15.1",
            "v23.0.0",
            "v24.4.1",
        ] {
            assert!(
                validate_node_version_output(version).is_ok(),
                "expected {version:?} to be supported"
            );
        }

        for version in ["v18.20.8", "v20.17.0", "v20.18.9", "v21.7.3", "v22.11.0"] {
            assert!(
                validate_node_version_output(version).is_err(),
                "expected {version:?} to be rejected"
            );
        }
    }

    #[test]
    fn reports_actionable_node_version_errors() {
        let unsupported = validate_node_version_output("v20.17.0").unwrap_err();
        assert!(unsupported.contains("v20.17.0"));
        assert!(unsupported.contains("^20.19.0"));
        assert!(unsupported.contains("reopen the terminal"));

        for output in ["", "20.19", "not-a-version", "v20.19.0.1"] {
            assert!(
                validate_node_version_output(output).is_err(),
                "expected {output:?} to be rejected"
            );
        }
    }

    #[test]
    fn pins_chrome_devtools_mcp_version() {
        // `@latest` makes every npx spawn re-resolve the dist-tag against the
        // npm registry; combined with mcp-cli's timeout-less request wait this
        // hung whole runs (2026-07-11). The package spec must pin a version.
        let config = build_chrome_devtools_server_config(true, true, "/tmp/mcp.log", false);
        let args = config["args"].as_array().expect("args array");
        let pkg = args
            .iter()
            .filter_map(|a| a.as_str())
            .find(|a| a.starts_with("chrome-devtools-mcp"))
            .expect("chrome-devtools-mcp package argument");
        assert!(
            !pkg.ends_with("@latest"),
            "chrome-devtools-mcp must be version-pinned, got {pkg}"
        );
        let version = pkg.rsplit('@').next().unwrap_or_default();
        assert!(
            version.chars().next().is_some_and(|c| c.is_ascii_digit()),
            "expected an explicit pinned version, got {pkg}"
        );
    }

    #[test]
    fn classifies_transport_errors_for_reconnect() {
        // Transport failures earn a session reset + loud error (exact phrases
        // from mcp-cli's StdioClient surface inside CliError's `Details:`
        // line); the call is never replayed — see mcp_error_is_transport...
        for transport in [
            "MCP tool 'click' timed out after 90s",
            "Error [SERVER_CONNECTION_FAILED]: x\n  Details: Failed to send request to process stdin",
            "Error [TOOL_EXECUTION_FAILED]: x\n  Details: Server process exited unexpectedly. Last stderr:\nnpm error",
            "Error [SERVER_CONNECTION_FAILED]: x\n  Details: Stdio response receiver canceled",
            "Failed to start chrome-devtools MCP server: timed out after 120s",
        ] {
            assert!(
                mcp_error_is_transport(transport),
                "expected transport-class error: {transport}"
            );
        }
        // ...application-level tool errors must NOT reset the session — the
        // transport is fine and the caller needs the original error.
        for app_level in [
            "mcp-cli library call failed: Error [TOOL_EXECUTION_FAILED]: Tool \"click\" execution failed\n  Details: element not found",
            "mcp-cli library call failed: Error [TOOL_EXECUTION_FAILED]: Tool \"evaluate_script\" execution failed\n  Details: TypeError: x is undefined",
        ] {
            assert!(
                !mcp_error_is_transport(app_level),
                "expected app-level error to pass through: {app_level}"
            );
        }
    }

    #[test]
    fn piped_stdin_grace_skips_silent_pipe_when_prompt_argument_present() {
        // Agent harnesses (Claude Code / Codex) run commands with a non-tty
        // stdin they may never close; blocking on EOF hung whole runs
        // (2026-07-11). With a prompt argument in hand, a silent pipe must be
        // treated as "no piped input" after the grace period.
        let (_probe_tx, probe_rx) = std::sync::mpsc::channel::<StdinProbe>();
        let (_data_tx, data_rx) = std::sync::mpsc::channel::<std::io::Result<String>>();
        let out = recv_piped_stdin(&probe_rx, &data_rx, Duration::from_millis(50), true)
            .expect("silent pipe should yield empty stdin, not an error");
        assert_eq!(out, "");
    }

    #[test]
    fn piped_stdin_reads_live_pipe_to_eof_when_prompt_argument_present() {
        // A pipe that delivers data keeps the documented combine behavior:
        // `cat notes.md | ask-bridge '摘要'` must still append stdin.
        let (probe_tx, probe_rx) = std::sync::mpsc::channel();
        let (data_tx, data_rx) = std::sync::mpsc::channel();
        probe_tx.send(StdinProbe::Data).unwrap();
        data_tx.send(Ok("piped context".to_string())).unwrap();
        let out = recv_piped_stdin(&probe_rx, &data_rx, Duration::from_millis(50), true)
            .expect("live pipe should be read");
        assert_eq!(out, "piped context");
    }

    #[test]
    fn piped_stdin_waits_unbounded_when_no_prompt_argument() {
        // Without a prompt argument stdin IS the prompt: keep upstream's
        // unbounded wait even when data arrives long after any grace window.
        let (_probe_tx, probe_rx) = std::sync::mpsc::channel();
        let (data_tx, data_rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(120));
            let _ = data_tx.send(Ok("stdin is the prompt".to_string()));
        });
        let out = recv_piped_stdin(&probe_rx, &data_rx, Duration::from_millis(10), false)
            .expect("unbounded wait should return the piped prompt");
        assert_eq!(out, "stdin is the prompt");
    }

    #[test]
    fn builds_direct_quiet_mcp_configs() {
        fn config_args(config: &serde_json::Value) -> Vec<&str> {
            config["args"]
                .as_array()
                .expect("MCP config should contain an args array")
                .iter()
                .map(|arg| arg.as_str().expect("MCP arguments should be strings"))
                .collect()
        }

        let log_path = r"C:\Temp\ask bridge\chrome-devtools-mcp.log";
        let quiet_windows = build_chrome_devtools_server_config(true, true, log_path, true);
        let verbose_windows = build_chrome_devtools_server_config(false, true, log_path, true);
        let quiet_unix = build_chrome_devtools_server_config(true, true, log_path, false);
        let quiet_args = config_args(&quiet_windows);
        let verbose_args = config_args(&verbose_windows);

        assert_eq!(quiet_windows["command"].as_str(), Some("npx.cmd"));
        assert_eq!(verbose_windows["command"].as_str(), Some("npx.cmd"));
        assert_eq!(quiet_unix["command"].as_str(), Some("npx"));
        for required in [
            MCP_PACKAGE_SPEC,
            "--browser-url=http://127.0.0.1:9223",
            "--headless",
            "--logFile",
            log_path,
        ] {
            assert!(quiet_args.contains(&required));
            assert!(verbose_args.contains(&required));
        }
        assert!(quiet_args.contains(&"--no-usage-statistics"));
        assert!(quiet_args.contains(&"--no-performance-crux"));
        assert!(!verbose_args.contains(&"--no-usage-statistics"));
        assert!(!verbose_args.contains(&"--no-performance-crux"));
        assert!(!quiet_args.iter().any(|arg| arg.contains("2>nul")));
        assert_eq!(quiet_windows["env"]["CI"].as_str(), Some("1"));
        assert!(verbose_windows.get("env").is_none());
    }

    #[test]
    fn parses_script_result_containing_markdown_code_fence() {
        let markdown = "說明\n```rust\nfn main() { println!(\"ok\"); }\n```\n結尾";
        let encoded = serde_json::to_string(markdown).expect("markdown should serialize");
        let result = serde_json::json!({
            "content": [{
                "type": "text",
                "text": format!("Script ran on page and returned:\n```json\n{}\n```", encoded)
            }]
        });

        assert_eq!(
            parse_script_result(&result).expect("script result should parse"),
            serde_json::Value::String(markdown.to_string())
        );
    }

    #[test]
    fn rejects_malformed_script_fence_without_leaking_payload() {
        let secret = "private-response-content";
        let encoded = serde_json::to_string(secret).expect("secret should serialize");

        for text in [
            format!("Script ran on page and returned:\n```json\n{}", encoded),
            format!(
                "Script ran on page and returned:\n```json\n{} trailing-data\n```",
                encoded
            ),
        ] {
            let result = serde_json::json!({
                "content": [{ "type": "text", "text": text }]
            });
            let error = parse_script_result(&result).expect_err("malformed fence should fail");

            assert!(!error.contains(secret));
        }
    }

    #[test]
    fn rejects_malformed_script_shape_without_leaking_payload() {
        let secret = "private-response-content";
        let result = serde_json::json!({
            "content": [{ "type": "text", "unexpected": secret }]
        });
        let error = parse_script_result(&result).expect_err("malformed shape should fail");

        assert!(!error.contains(secret));
        assert!(error.contains("Could not extract text field"));
    }

    fn make_test_dir(name: &str) -> std::path::PathBuf {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "ask_bridge_{}_{}_{}",
            name,
            std::process::id(),
            timestamp
        ))
    }

    fn mark_test_file_executable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    #[test]
    fn parses_provider_as_global_argument() {
        let cli = Cli::try_parse_from(["ask-bridge", "--provider", "gemini", "login"]).unwrap();
        assert_eq!(cli.provider, Some(Provider::Gemini));
        assert!(matches!(cli.command, Some(Commands::Login)));

        let cli = Cli::try_parse_from(["ask-bridge", "login", "--provider", "gemini"]).unwrap();
        assert_eq!(cli.provider, Some(Provider::Gemini));
        assert!(matches!(cli.command, Some(Commands::Login)));
    }

    #[test]
    fn parses_config_command() {
        let cli = Cli::try_parse_from(["ask-bridge", "config", "--provider", "gemini"]).unwrap();
        assert_eq!(cli.provider, Some(Provider::Gemini));
        assert!(matches!(cli.command, Some(Commands::Config)));
    }

    #[test]
    fn parses_config_command_without_provider() {
        let cli = Cli::try_parse_from(["ask-bridge", "config"]).unwrap();
        assert_eq!(cli.provider, None);
        assert!(matches!(cli.command, Some(Commands::Config)));
    }

    #[test]
    fn parses_update_command() {
        let cli = Cli::try_parse_from(["ask-bridge", "update"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Update)));
    }

    #[test]
    fn leaves_provider_unset_when_cli_argument_is_missing() {
        let cli = Cli::try_parse_from(["ask-bridge", "hello"]).unwrap();
        assert_eq!(cli.provider, None);
    }

    #[test]
    fn parses_provider_from_config_json() {
        assert_eq!(
            parse_configured_provider(r#"{"provider":"gemini"}"#).unwrap(),
            Some(Provider::Gemini)
        );
        assert_eq!(
            parse_configured_provider(r#"{"provider":"chatgpt"}"#).unwrap(),
            Some(Provider::ChatGpt)
        );
        assert_eq!(
            parse_configured_provider(r#"{"provider":"chat-gpt"}"#).unwrap(),
            Some(Provider::ChatGpt)
        );
        assert_eq!(
            parse_configured_provider(r#"{"provider":"claude"}"#).unwrap(),
            Some(Provider::Claude)
        );
        assert_eq!(
            parse_configured_provider(r#"{"provider":"claude-ai"}"#).unwrap(),
            Some(Provider::Claude)
        );
        assert_eq!(parse_configured_provider(r#"{}"#).unwrap(), None);
    }

    #[test]
    fn resolves_provider_precedence() {
        assert_eq!(
            effective_provider(Some(Provider::ChatGpt), Some(Provider::Gemini)),
            Provider::ChatGpt
        );
        assert_eq!(
            effective_provider(None, Some(Provider::Gemini)),
            Provider::Gemini
        );
        assert_eq!(effective_provider(None, None), Provider::ChatGpt);
    }

    #[test]
    fn cli_provider_bypasses_invalid_config() {
        let provider = resolve_provider_with(Some(Provider::ChatGpt), || {
            Err("config should not be loaded".to_string())
        })
        .unwrap();

        assert_eq!(provider, Provider::ChatGpt);
    }

    #[test]
    fn resolves_provider_from_config_when_cli_provider_is_missing() {
        let provider = resolve_provider_with(None, || Ok(Some(Provider::Gemini))).unwrap();
        assert_eq!(provider, Provider::Gemini);
    }

    #[test]
    fn rejects_invalid_provider_in_config_json() {
        let err = parse_configured_provider(r#"{"provider":"copilot"}"#).unwrap_err();
        assert!(err.contains("Invalid provider"));
    }

    #[test]
    fn parses_browser_as_global_argument() {
        let cli = Cli::try_parse_from(["ask-bridge", "--browser", "/tmp/x", "login"]).unwrap();
        assert_eq!(cli.browser.as_deref(), Some("/tmp/x"));
        assert!(matches!(cli.command, Some(Commands::Login)));

        let cli = Cli::try_parse_from(["ask-bridge", "login", "--browser", "/tmp/x"]).unwrap();
        assert_eq!(cli.browser.as_deref(), Some("/tmp/x"));
    }

    #[test]
    fn parses_config_command_with_browser() {
        let cli = Cli::try_parse_from(["ask-bridge", "config", "--browser", "/tmp/x"]).unwrap();
        assert_eq!(cli.browser.as_deref(), Some("/tmp/x"));
        assert!(matches!(cli.command, Some(Commands::Config)));
    }

    #[test]
    fn parses_browser_from_config_json() {
        assert_eq!(
            parse_configured_browser(r#"{"browser":"/Applications/Brave Origin.app"}"#).unwrap(),
            Some("/Applications/Brave Origin.app".to_string())
        );
        assert_eq!(
            parse_configured_browser(r#"{"provider":"gemini","browser":"/x"}"#).unwrap(),
            Some("/x".to_string())
        );
        assert_eq!(parse_configured_browser(r#"{}"#).unwrap(), None);
        assert_eq!(
            parse_configured_browser(r#"{"browser":"  "}"#).unwrap(),
            None
        );
    }

    #[test]
    fn browser_cli_takes_precedence_over_config() {
        let selected = select_browser_value_with(Some("/cli".to_string()), || {
            Err("config should not be loaded".to_string())
        })
        .unwrap();
        assert_eq!(selected, Some("/cli".to_string()));
    }

    #[test]
    fn browser_falls_back_to_config_when_cli_missing() {
        let selected =
            select_browser_value_with(None, || Ok(Some("/from-config".to_string()))).unwrap();
        assert_eq!(selected, Some("/from-config".to_string()));

        let none = select_browser_value_with(None, || Ok(None)).unwrap();
        assert_eq!(none, None);
    }

    #[test]
    fn resolve_browser_binary_resolves_macos_app_bundle() {
        let dir = make_test_dir("browser_app");
        let macos = dir.join("Brave Test.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        let exec = macos.join("Brave Test");
        std::fs::write(&exec, b"#!/bin/sh\n").unwrap();
        mark_test_file_executable(&exec);

        let app_path = dir.join("Brave Test.app");
        let resolved = resolve_browser_binary(app_path.to_str().unwrap()).unwrap();
        assert_eq!(Path::new(&resolved), exec.as_path());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_browser_binary_accepts_direct_executable_path() {
        let dir = make_test_dir("browser_bin");
        std::fs::create_dir_all(&dir).unwrap();
        let exec = dir.join("chromium");
        std::fs::write(&exec, b"#!/bin/sh\n").unwrap();
        mark_test_file_executable(&exec);

        let resolved = resolve_browser_binary(exec.to_str().unwrap()).unwrap();
        assert_eq!(resolved, exec.to_string_lossy().to_string());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn resolve_browser_binary_rejects_non_executable_file() {
        let dir = make_test_dir("browser_nonexec");
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("chromium");
        std::fs::write(&file, b"not executable\n").unwrap();

        let err = resolve_browser_binary(file.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not executable"), "got: {}", err);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_browser_binary_errors_on_missing() {
        let err = resolve_browser_binary("/no/such/browser-xyz").unwrap_err();
        assert!(err.contains("not found"));
    }

    #[test]
    fn merged_config_json_preserves_untouched_fields() {
        // Setting browser must not drop an existing provider...
        let merged = merged_config_json(r#"{"provider":"gemini"}"#, None, Some("/b")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(value["provider"], "gemini");
        assert_eq!(value["browser"], "/b");

        // ...and setting provider must not drop an existing browser.
        let merged = merged_config_json(r#"{"browser":"/b"}"#, Some("chatgpt"), None).unwrap();
        let value: serde_json::Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(value["provider"], "chatgpt");
        assert_eq!(value["browser"], "/b");

        // Empty existing body starts fresh.
        let merged = merged_config_json("", Some("chatgpt"), Some("/b")).unwrap();
        let value: serde_json::Value = serde_json::from_str(&merged).unwrap();
        assert_eq!(value["provider"], "chatgpt");
        assert_eq!(value["browser"], "/b");
    }

    #[test]
    fn merged_config_json_rejects_non_object() {
        let err = merged_config_json("[]", Some("gemini"), None).unwrap_err();
        assert!(err.contains("not a JSON object"), "got: {}", err);
        let err2 = merged_config_json("\"hello\"", None, Some("/b")).unwrap_err();
        assert!(err2.contains("not a JSON object"), "got: {}", err2);
    }

    #[cfg(unix)]
    #[test]
    fn config_writer_rejects_symlink_without_touching_its_target() {
        let dir = make_test_dir("config_symlink");
        std::fs::create_dir_all(&dir).unwrap();
        let sentinel = dir.join("sentinel.json");
        let config = dir.join("config.json");
        std::fs::write(&sentinel, b"{\"keep\":\"PRECIOUS\"}\n").unwrap();
        std::os::unix::fs::symlink(&sentinel, &config).unwrap();

        let err = write_global_config_at(&config, Some(Provider::Gemini), None).unwrap_err();

        assert!(err.contains("symbolic link"), "got: {}", err);
        assert_eq!(
            std::fs::read_to_string(&sentinel).unwrap(),
            "{\"keep\":\"PRECIOUS\"}\n"
        );
        assert!(
            std::fs::symlink_metadata(&config)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the rejected destination symlink must remain untouched"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn config_writer_rejects_symlink_lock_without_touching_its_target() {
        let dir = make_test_dir("config_lock_symlink");
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.json");
        let lock = dir.join(".config.json.lock");
        let sentinel = dir.join("sentinel");
        std::fs::write(&sentinel, "DO NOT MODIFY").unwrap();
        std::os::unix::fs::symlink(&sentinel, &lock).unwrap();

        let err = write_global_config_at(&config, Some(Provider::Gemini), None).unwrap_err();

        assert!(err.contains("symbolic link"), "got: {err}");
        assert_eq!(std::fs::read_to_string(&sentinel).unwrap(), "DO NOT MODIFY");
        assert!(
            std::fs::symlink_metadata(&lock)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn config_write_replaces_existing_file_atomically_preserving_extras_and_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = make_test_dir("config_atomic_happy");
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("config.json");
        std::fs::write(&config, "{\"keep\":\"extra\"}\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_global_config_at(&config, Some(Provider::Gemini), Some("/b")).unwrap();

        let content = std::fs::read_to_string(&config).unwrap();
        assert!(content.ends_with('\n'), "got: {:?}", content);
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(value["provider"], "gemini");
        assert_eq!(value["browser"], "/b");
        assert_eq!(value["keep"], "extra");

        let metadata = std::fs::symlink_metadata(&config).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(
            metadata.permissions().mode() & 0o7777,
            0o644,
            "the atomic replace must preserve the existing file's mode"
        );

        let residue: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "config.json" && name != ".config.json.lock")
            .collect();
        assert!(
            residue.is_empty(),
            "staging residue left behind: {:?}",
            residue
        );
        assert!(
            std::fs::symlink_metadata(dir.join(".config.json.lock"))
                .unwrap()
                .file_type()
                .is_file(),
            "the persistent cross-process lock must be a regular file"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_browser_binary_rejects_directory() {
        let dir = make_test_dir("browser_plain_dir");
        std::fs::create_dir_all(&dir).unwrap();
        let err = resolve_browser_binary(dir.to_str().unwrap()).unwrap_err();
        assert!(err.contains("is a directory"), "got: {}", err);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_browser_binary_errors_on_nonexistent_app() {
        let err = resolve_browser_binary("/no/such/Brave.app").unwrap_err();
        assert!(err.contains("not found"), "got: {}", err);
    }

    #[test]
    fn resolve_browser_binary_errors_on_app_without_macos_dir() {
        let dir = make_test_dir("browser_empty_app");
        let app = dir.join("Empty.app");
        std::fs::create_dir_all(&app).unwrap();
        let err = resolve_browser_binary(app.to_str().unwrap()).unwrap_err();
        assert!(err.contains("No executable found inside"), "got: {}", err);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn resolve_browser_binary_rejects_non_executable_bundle_binary() {
        let dir = make_test_dir("browser_nonexec_app");
        let macos = dir.join("Blocked.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        std::fs::write(macos.join("Blocked"), b"not executable\n").unwrap();

        let err = resolve_browser_binary(dir.join("Blocked.app").to_str().unwrap()).unwrap_err();
        assert!(err.contains("No executable found"), "got: {}", err);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_browser_binary_handles_uppercase_app_extension() {
        let dir = make_test_dir("browser_upper_app");
        let macos = dir.join("Foo.APP/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        let exec = macos.join("Foo");
        std::fs::write(&exec, b"#!/bin/sh\n").unwrap();
        mark_test_file_executable(&exec);
        let app = dir.join("Foo.APP");
        let resolved = resolve_browser_binary(app.to_str().unwrap()).unwrap();
        assert_eq!(Path::new(&resolved), exec.as_path());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn resolve_browser_binary_accepts_app_bundle_with_trailing_slash() {
        let dir = make_test_dir("browser_app_slash");
        let macos = dir.join("Brave Test.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        let exec = macos.join("Brave Test");
        std::fs::write(&exec, b"#!/bin/sh\n").unwrap();
        mark_test_file_executable(&exec);
        let app_with_slash = format!("{}/", dir.join("Brave Test.app").to_str().unwrap());
        let resolved = resolve_browser_binary(&app_with_slash).unwrap();
        assert_eq!(Path::new(&resolved), exec.as_path());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn resolve_browser_binary_falls_back_to_first_executable_skipping_dotfiles() {
        use std::os::unix::fs::PermissionsExt;
        let dir = make_test_dir("browser_fallback");
        let macos = dir.join("Renamed.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        // A dotfile and a non-executable file that must both be skipped.
        std::fs::write(macos.join(".DS_Store"), b"junk").unwrap();
        std::fs::write(macos.join("Info.plist"), b"<plist/>").unwrap();
        // The real executable, whose name differs from the bundle stem "Renamed".
        let bin = macos.join("ActualBinary");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let resolved = resolve_browser_binary(dir.join("Renamed.app").to_str().unwrap()).unwrap();
        assert_eq!(resolved, bin.to_string_lossy().to_string());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn command_uses_browser_detects_match_and_mismatch() {
        let brave = "/Applications/Brave Origin.app/Contents/MacOS/Brave Origin";
        let chrome_cmd = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9223 --user-data-dir=/x";
        assert!(!command_uses_browser(chrome_cmd, brave));
        let brave_cmd = format!("{} --remote-debugging-port=9223 --user-data-dir=/x", brave);
        assert!(command_uses_browser(&brave_cmd, brave));
        // An empty override path never matches (avoids matching every command).
        assert!(!command_uses_browser(chrome_cmd, ""));
    }

    #[test]
    fn is_blank_tab_url_matches_blank_and_internal_pages() {
        assert!(is_blank_tab_url("about:blank"));
        assert!(is_blank_tab_url("chrome://newtab/"));
        assert!(is_blank_tab_url("brave://newtab/"));
        assert!(is_blank_tab_url("edge://newtab/"));
        assert!(is_blank_tab_url("chrome://welcome"));
        assert!(is_blank_tab_url("chrome://new-tab-page/"));
    }

    #[test]
    fn is_blank_tab_url_rejects_real_https_and_content() {
        // Regression: a real https host starting with "newtab" must NOT be
        // treated as a blank tab (the old contains("://newtab") over-matched).
        assert!(!is_blank_tab_url("https://newtab.example.com"));
        assert!(!is_blank_tab_url("https://chatgpt.com/"));
        assert!(!is_blank_tab_url("https://gemini.google.com/app"));
        assert!(!is_blank_tab_url("about:settings"));
    }

    #[test]
    fn rejects_non_string_browser_in_config_json() {
        let err = parse_configured_browser(r#"{"browser": 42}"#).unwrap_err();
        assert!(err.contains("Failed to parse config.json"), "got: {}", err);
        assert_eq!(
            parse_configured_browser(r#"{"browser": null}"#).unwrap(),
            None
        );
        // A wrong-typed browser value also breaks provider loading (same struct).
        assert!(parse_configured_provider(r#"{"provider":"gemini","browser":42}"#).is_err());
    }

    #[test]
    fn browser_config_error_propagates_when_cli_missing() {
        let err = select_browser_value_with(None, || Err("boom".to_string())).unwrap_err();
        assert_eq!(err, "boom");
    }

    #[test]
    fn resolve_browser_override_rejects_bad_cli_path() {
        // A bad --browser value fails loudly and never silently falls back to
        // Chrome. Some(cli) short-circuits config loading, so this never reads
        // the real ~/.config file.
        let err = resolve_browser_override(Some("/no/such/browser-xyz".to_string())).unwrap_err();
        assert!(err.contains("not found"), "got: {}", err);
    }

    #[test]
    fn app_bundle_from_binary_extracts_bundle_path() {
        assert_eq!(
            app_bundle_from_binary("/Applications/Brave Origin.app/Contents/MacOS/Brave Origin"),
            Some("/Applications/Brave Origin.app".to_string())
        );
        assert_eq!(
            app_bundle_from_binary("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            Some("/Applications/Google Chrome.app".to_string())
        );
        // A bare executable (no .app bundle) -> None, so the launcher falls back
        // to a direct spawn instead of `open -a`.
        assert_eq!(app_bundle_from_binary("/usr/bin/chromium"), None);
        // Right structure but the bundle dir does not end in .app.
        assert_eq!(app_bundle_from_binary("/opt/foo/Contents/MacOS/foo"), None);
    }

    #[test]
    fn app_bundle_from_binary_is_case_insensitive() {
        // Consistent with resolve_browser_binary: the default macOS volume is
        // case-insensitive, so these all name a real bundle layout.
        assert_eq!(
            app_bundle_from_binary_lexical("/Applications/Foo.APP/Contents/MacOS/Foo"),
            Some("/Applications/Foo.APP".to_string())
        );
        assert_eq!(
            app_bundle_from_binary_lexical("/Applications/foo.app/contents/macos/foo"),
            Some("/Applications/foo.app".to_string())
        );
        // Still rejects non-bundle layouts.
        assert_eq!(app_bundle_from_binary_lexical("/usr/bin/chromium"), None);
    }

    #[cfg(unix)]
    #[test]
    fn app_bundle_from_binary_resolves_symlinked_binary() {
        let dir = make_test_dir("bundle_symlink");
        let macos = dir.join("Linked.app/Contents/MacOS");
        std::fs::create_dir_all(&macos).unwrap();
        let real_bin = macos.join("Linked");
        std::fs::write(&real_bin, b"#!/bin/sh\n").unwrap();
        let link = dir.join("linked-alias");
        std::os::unix::fs::symlink(&real_bin, &link).unwrap();

        // The symlink path is not lexically inside the bundle...
        assert_eq!(app_bundle_from_binary_lexical(link.to_str().unwrap()), None);
        // ...but canonicalization recovers the bundle.
        let resolved = app_bundle_from_binary(link.to_str().unwrap()).unwrap();
        assert!(
            resolved.ends_with("Linked.app"),
            "expected a Linked.app bundle path, got: {}",
            resolved
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn open_launch_args_gates_foreground_on_headless() {
        let browser_args = vec!["--flag-a".to_string(), "--flag-b".to_string()];
        // Headless: background launch, -g present and first.
        let bg = open_launch_args("/Applications/X.app", true, &browser_args);
        assert_eq!(
            bg,
            vec![
                "-g",
                "-n",
                "-a",
                "/Applications/X.app",
                "--args",
                "--flag-a",
                "--flag-b"
            ]
        );
        // Headful (login): NO -g — the user must be able to see/focus the window.
        let fg = open_launch_args("/Applications/X.app", false, &browser_args);
        assert_eq!(
            fg,
            vec![
                "-n",
                "-a",
                "/Applications/X.app",
                "--args",
                "--flag-a",
                "--flag-b"
            ]
        );
    }

    /// `ask-bridge update` overwrites the binary the user runs, so what the
    /// download does when it goes wrong is the whole story.
    ///
    /// `curl -fsSL ... | bash` starts the shell before the body has finished
    /// arriving. A connection that dies half way through therefore executes
    /// half an installer -- far enough to have deleted or replaced things --
    /// and the pipeline's exit status is bash's, so the command reports
    /// success and the caller never learns the update was partial. The stub
    /// `curl` below is exactly that: it emits an installer prefix and exits
    /// non-zero.
    #[cfg(not(target_os = "windows"))]
    #[test]
    fn a_download_that_dies_half_way_through_is_never_executed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let stub_dir = dir.path().join("stub-bin");
        std::fs::create_dir_all(&stub_dir).unwrap();
        let marker = dir.path().join("installer-ran");

        // Writes to the `-o` destination when asked for one, to stdout when
        // not -- i.e. it plays along with either shape of update command, so
        // this test cannot pass merely because the flags changed.
        let stub = r#"#!/bin/sh
dest=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-o" ]; then dest="$a"; fi
  prev="$a"
done
payload="touch '__MARKER__'"
if [ -n "$dest" ]; then
  printf '%s\n' "$payload" > "$dest"
else
  printf '%s\n' "$payload"
fi
exit "${CURL_EXIT:-1}"
"#
        .replace("__MARKER__", marker.to_str().unwrap());
        let curl = stub_dir.join("curl");
        std::fs::write(&curl, stub).unwrap();
        std::fs::set_permissions(&curl, std::fs::Permissions::from_mode(0o755)).unwrap();

        let run = |curl_exit: &str| -> bool {
            let _ = std::fs::remove_file(&marker);
            std::process::Command::new("sh")
                .args(["-c", UNIX_UPDATE_SHELL_COMMAND])
                .env(
                    "PATH",
                    format!(
                        "{}:{}",
                        stub_dir.display(),
                        std::env::var("PATH").unwrap_or_default()
                    ),
                )
                .env("CURL_EXIT", curl_exit)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("sh should be available")
                .success()
        };

        assert!(
            !run("1"),
            "a download that failed reported the update as successful"
        );
        assert!(
            !marker.exists(),
            "the truncated installer body was executed"
        );

        // Positive control: a download that completes still installs, so the
        // guard is not satisfied by refusing to run anything.
        assert!(
            run("0"),
            "a successful download must still run the installer"
        );
        assert!(
            marker.exists(),
            "the downloaded installer was never executed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_launcher_reports_success_failure_and_spawn_error() {
        assert!(run_launcher("sh", &["-c".to_string(), "exit 0".to_string()]).unwrap());
        assert!(!run_launcher("sh", &["-c".to_string(), "exit 1".to_string()]).unwrap());
        assert!(run_launcher("/no/such/launcher-xyz", &[]).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn process_is_alive_probes_real_processes() {
        // Our own (very alive) process.
        let me = std::process::id().to_string();
        assert_eq!(process_is_alive(&me), Some(true));

        // A killed AND reaped child no longer exists for `ps`.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id().to_string();
        child.kill().unwrap();
        child.wait().unwrap(); // reap so the PID actually disappears
        assert_eq!(process_is_alive(&pid), Some(false));

        // Non-PID inputs must be indeterminate, never "dead".
        assert_eq!(process_is_alive(""), None);
        assert_eq!(process_is_alive("12x"), None);
    }

    #[cfg(unix)]
    #[test]
    fn wait_for_ask_chrome_pids_to_exit_detects_death_and_survival() {
        // A killed, reaped child is detected as exited by the real
        // process_command/process_is_alive probes.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id().to_string();
        child.kill().unwrap();
        child.wait().unwrap(); // reap so the PID actually disappears
        assert!(wait_for_ask_chrome_pids_to_exit(
            &[pid],
            "/tmp/ask-bridge-test-profile",
            20
        ));

        // A live process whose command line carries the ask-bridge marker is
        // still running as ask chrome: the bounded wait returns false.
        let mut marked = spawn_marked_ask_chrome_stub();
        let marked_pid = marked.id().to_string();
        let still_running = !wait_for_ask_chrome_pids_to_exit(
            std::slice::from_ref(&marked_pid),
            "/tmp/ask-bridge-test-profile",
            2,
        );
        terminate_marked_ask_chrome_stub(&mut marked);
        assert!(still_running);
    }

    /// Spawns a stub process whose argv carries the ask-bridge marker, so the
    /// real process probes classify it as a live ask chrome.
    #[cfg(unix)]
    fn spawn_marked_ask_chrome_stub() -> std::process::Child {
        use std::os::unix::process::CommandExt;

        std::process::Command::new("sh")
            // Compound command: stops sh from exec-replacing itself with
            // `sleep`, which would drop the marker from its argv.
            .args(["-c", "sleep 30; :", "sh", "--ask-bridge-instance"])
            // Give the stub its own process group (pgid == its own pid) so
            // teardown can signal the whole subtree without ever reaching a
            // process this test did not spawn.
            .process_group(0)
            .spawn()
            .unwrap()
    }

    /// Tears the stub down. `sh` forks `sleep`, so the whole subtree must die.
    #[cfg(unix)]
    fn terminate_marked_ask_chrome_stub(child: &mut std::process::Child) {
        let pgid = child.id();
        // `process_group(0)` above makes the stub its own group leader, so the
        // group id equals its pid: signalling `-pgid` can only hit the stub and
        // its descendants.
        assert!(pgid > 1, "refusing to signal process group {pgid}");
        std::process::Command::new("/bin/kill")
            .args(["-KILL", "--", &format!("-{pgid}")])
            .status()
            .ok();
        child.kill().ok();
        child.wait().ok();
    }

    #[cfg(unix)]
    fn child_pids_of(parent: u32) -> Vec<String> {
        let output = std::process::Command::new("ps")
            .args(["-eo", "pid=,ppid="])
            .output()
            .unwrap();
        let parent = parent.to_string();
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .filter_map(|line| {
                let mut fields = line.split_whitespace();
                let pid = fields.next()?;
                let ppid = fields.next()?;
                (ppid == parent).then(|| pid.to_string())
            })
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn marked_ask_chrome_stub_teardown_leaves_no_orphaned_descendants() {
        // Regression: the stub's teardown used to signal only the direct `sh`
        // child, orphaning the `sleep` it forked. Every `cargo test` run then
        // leaked a live process onto the developer's (or CI's) machine.
        let mut marked = spawn_marked_ask_chrome_stub();
        let marked_pid = marked.id();

        // Wait for `sh` to fork `sleep` so the subtree is fully formed.
        let mut subtree = Vec::new();
        for _ in 0..100 {
            subtree = child_pids_of(marked_pid);
            if !subtree.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            !subtree.is_empty(),
            "stub never forked a child, so this test cannot observe orphaning"
        );

        terminate_marked_ask_chrome_stub(&mut marked);

        for pid in &subtree {
            let mut gone = false;
            for _ in 0..100 {
                if process_is_alive(pid) == Some(false) {
                    gone = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            assert!(
                gone,
                "teardown orphaned descendant pid {pid} of stub {marked_pid}"
            );
        }
        assert_eq!(
            process_is_alive(&marked_pid.to_string()),
            Some(false),
            "stub {marked_pid} itself survived teardown"
        );
    }

    #[test]
    fn require_ask_chrome_pids_to_exit_reports_a_bounded_wait_timeout() {
        let me = std::process::id().to_string();
        let err = require_ask_chrome_pids_to_exit(std::slice::from_ref(&me), "/tmp/profile", 0)
            .unwrap_err();
        assert!(err.contains(&me), "got: {}", err);
        assert!(err.contains("still running"), "got: {}", err);
    }

    #[test]
    fn hide_budget_covers_port_wait() {
        // A slow-but-successful launch must still get hidden: the hide thread's
        // PID wait must outlast the main port wait.
        const { assert!(HIDE_PID_WAIT_ITERS >= PORT_WAIT_ITERS) };
    }

    #[test]
    fn parses_close_command() {
        let cli = Cli::try_parse_from(["ask-bridge", "close"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Close)));
    }

    #[test]
    fn hides_debug_commands_from_help() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();

        assert!(!help.contains("\n  open"));
        assert!(!help.contains("\n  get"));
        assert!(!help.contains("\n  dump"));
        assert!(!help.contains("\n  screenshot"));
        assert!(help.contains("\n  login"));
        assert!(help.contains("\n  close"));
        assert!(help.contains("\n  update"));
    }

    #[test]
    fn still_parses_hidden_debug_commands() {
        let cli = Cli::try_parse_from(["ask-bridge", "open"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Open { .. })));

        let cli = Cli::try_parse_from(["ask-bridge", "get"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Get { .. })));

        let cli = Cli::try_parse_from(["ask-bridge", "dump"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Dump)));

        let cli = Cli::try_parse_from(["ask-bridge", "screenshot"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Screenshot)));
    }

    #[test]
    fn parses_verbose_get_command_flag() {
        let url = "https://chatgpt.com/c/6a50fe34-43c0-83ee-ab86-d41adf91625e";
        let cli = Cli::try_parse_from(["ask-bridge", "get", "--verbose", url]).unwrap();
        if let Some(Commands::Get {
            url: parsed_url,
            verbose,
        }) = cli.command
        {
            assert_eq!(parsed_url, Some(url.to_string()));
            assert!(verbose);
        } else {
            panic!("expected get command");
        }
        assert!(!cli.verbose);
    }

    #[test]
    fn rejects_unknown_provider() {
        assert!(Cli::try_parse_from(["ask-bridge", "--provider", "copilot", "hello"]).is_err());
    }

    #[test]
    fn parses_claude_provider_argument() {
        let cli = Cli::try_parse_from(["ask-bridge", "--provider", "claude", "hello"]).unwrap();
        assert_eq!(cli.provider, Some(Provider::Claude));
    }

    #[test]
    fn parses_session_id_alias_and_rejects_new_session_conflict() {
        let cli = Cli::try_parse_from([
            "ask-bridge",
            "--provider",
            "chatgpt",
            "--session-id",
            "conversation-123",
            "continue",
        ])
        .unwrap();
        assert_eq!(cli.session.as_deref(), Some("conversation-123"));

        assert!(
            Cli::try_parse_from([
                "ask-bridge",
                "--new",
                "--session",
                "conversation-123",
                "continue",
            ])
            .is_err()
        );
    }

    #[test]
    fn maps_provider_urls() {
        assert_eq!(
            Provider::from_url("https://chatgpt.com/c/abc"),
            Some(Provider::ChatGpt)
        );
        assert_eq!(
            Provider::from_url("https://gemini.google.com/app/abc"),
            Some(Provider::Gemini)
        );
        assert_eq!(
            Provider::from_url("https://claude.ai/chat/abc"),
            Some(Provider::Claude)
        );
        assert_eq!(Provider::from_url("https://example.com"), None);
        assert_eq!(
            Provider::from_url("https://example.com/?next=https://chatgpt.com/c/abc"),
            None
        );
        assert_eq!(Provider::from_url("http://chatgpt.com/c/abc"), None);
    }

    #[test]
    fn resolves_session_ids_for_each_provider() {
        assert_eq!(
            resolve_session_target(Provider::ChatGpt, true, "chat-123").unwrap(),
            (
                Provider::ChatGpt,
                "https://chatgpt.com/c/chat-123".to_string()
            )
        );
        assert_eq!(
            resolve_session_target(Provider::Gemini, true, "gemini_123").unwrap(),
            (
                Provider::Gemini,
                "https://gemini.google.com/app/gemini_123".to_string()
            )
        );
        assert_eq!(
            resolve_session_target(Provider::Claude, true, "claude-123").unwrap(),
            (
                Provider::Claude,
                "https://claude.ai/chat/claude-123".to_string()
            )
        );
    }

    #[test]
    fn session_url_infers_provider_unless_cli_provider_conflicts() {
        let target =
            resolve_session_target(Provider::Gemini, false, "https://chatgpt.com/c/chat-123")
                .unwrap();
        assert_eq!(target.0, Provider::ChatGpt);
        assert_eq!(target.1, "https://chatgpt.com/c/chat-123");

        let error =
            resolve_session_target(Provider::Gemini, true, "https://chatgpt.com/c/chat-123")
                .unwrap_err();
        assert!(error.contains("but --provider selected Gemini"));
    }

    #[test]
    fn rejects_invalid_session_urls_and_ids() {
        for invalid in [
            "https://example.com/c/chat-123",
            "https://chatgpt.com/",
            "https://gemini.google.com/app",
            "https://claude.ai/chat/",
            "../chat-123",
            "chat/123",
        ] {
            assert!(
                resolve_session_target(Provider::ChatGpt, false, invalid).is_err(),
                "expected {invalid:?} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_a_conversation_marker_nested_beneath_another_route() {
        for (provider, nested) in [
            (Provider::ChatGpt, "https://chatgpt.com/settings/c/chat-123"),
            (
                Provider::Gemini,
                "https://gemini.google.com/settings/app/gemini-123",
            ),
            (
                Provider::Claude,
                "https://claude.ai/settings/chat/claude-123",
            ),
        ] {
            assert!(
                resolve_session_target(provider, false, nested).is_err(),
                "accepted a conversation marker nested below an unrelated route: {nested}"
            );
        }
    }

    #[test]
    fn a_chatgpt_custom_gpt_conversation_url_is_accepted() {
        let url = "https://chatgpt.com/g/g-p-project/c/conversation-123";

        assert_eq!(
            resolve_session_target(Provider::ChatGpt, false, url),
            Ok((Provider::ChatGpt, url.to_string()))
        );
    }

    #[test]
    fn gemini_account_prefixed_conversation_urls_are_accepted() {
        for url in [
            "https://gemini.google.com/u/0/app/conversation-123",
            "https://gemini.google.com/u/1/app/conversation-123?pageId=none",
            "https://gemini.google.com/u/12/app/conversation-123",
        ] {
            assert_eq!(
                resolve_session_target(Provider::Gemini, true, url),
                Ok((Provider::Gemini, url.to_string())),
                "refused a Gemini multi-account conversation URL: {url}"
            );
        }
    }

    #[test]
    fn rejects_empty_segments_around_the_conversation_route() {
        for (provider, malformed) in [
            (Provider::ChatGpt, "https://chatgpt.com//c/chat-123"),
            (Provider::ChatGpt, "https://chatgpt.com/c//chat-123"),
            (Provider::ChatGpt, "https://chatgpt.com/c/chat-123/"),
            (
                Provider::Gemini,
                "https://gemini.google.com//app/gemini-123",
            ),
            (
                Provider::Gemini,
                "https://gemini.google.com/app//gemini-123",
            ),
            (
                Provider::Gemini,
                "https://gemini.google.com/app/gemini-123/",
            ),
            (Provider::Claude, "https://claude.ai//chat/claude-123"),
            (Provider::Claude, "https://claude.ai/chat//claude-123"),
            (Provider::Claude, "https://claude.ai/chat/claude-123/"),
        ] {
            assert!(
                resolve_session_target(provider, false, malformed).is_err(),
                "accepted an empty segment in a conversation route: {malformed}"
            );
        }
    }

    #[test]
    fn rejects_malformed_gemini_account_prefixes() {
        for malformed in [
            "https://gemini.google.com/u/app/conversation-123",
            "https://gemini.google.com/u//app/conversation-123",
            "https://gemini.google.com/u/account/app/conversation-123",
            "https://gemini.google.com/u/-1/app/conversation-123",
            "https://gemini.google.com/u/1/settings/app/conversation-123",
            "https://gemini.google.com/u/1/app/",
            "https://gemini.google.com/u/1/app/conversation-123/extra",
        ] {
            assert!(
                resolve_session_target(Provider::Gemini, true, malformed).is_err(),
                "accepted a malformed Gemini account-prefixed route: {malformed}"
            );
        }
    }

    /// The hosts real `--session` use lands on must keep working, so the
    /// narrowing cannot be bought by breaking the feature.
    ///
    /// Case is normalised, not rejected: DNS is case-insensitive and `Url`
    /// folds the host before anything here sees it, so `CHATGPT.com` *is* the
    /// canonical host and resolves to the canonical URL verbatim. Same for the
    /// default port. Rejecting either would refuse a URL this tool builds
    /// itself, buying nothing -- what must not survive case folding is a
    /// *spoof*, which the reject test pins.
    #[test]
    fn a_session_url_is_accepted_on_the_providers_exact_conversation_host() {
        for (url, provider, resolved) in [
            (
                "https://chatgpt.com/c/abc",
                Provider::ChatGpt,
                "https://chatgpt.com/c/abc",
            ),
            (
                "https://CHATGPT.com/c/abc",
                Provider::ChatGpt,
                "https://chatgpt.com/c/abc",
            ),
            (
                "https://chatgpt.com:443/c/abc",
                Provider::ChatGpt,
                "https://chatgpt.com/c/abc",
            ),
            (
                "https://chatgpt.com/c/abc?model=gpt-5#top",
                Provider::ChatGpt,
                "https://chatgpt.com/c/abc?model=gpt-5#top",
            ),
            (
                "https://gemini.google.com/app/abc",
                Provider::Gemini,
                "https://gemini.google.com/app/abc",
            ),
            (
                "https://claude.ai/chat/abc",
                Provider::Claude,
                "https://claude.ai/chat/abc",
            ),
        ] {
            assert_eq!(
                resolve_session_target(Provider::ChatGpt, false, url),
                Ok((provider, resolved.to_string())),
                "the canonical conversation host was refused: {url}"
            );
        }
    }

    /// `--session` is the one path where a URL nobody observed in the browser is
    /// navigated to and then typed into, so its host rule is *equality* -- the
    /// dot boundary that tab identity uses would hand the prompt to
    /// `evil.chatgpt.com`, which costs a sub-domain takeover rather than a
    /// domain registration but is still not the provider.
    ///
    /// The last two assertions are the point of the whole change: the two
    /// boundaries must stay *different*. A future refactor that "unifies" them
    /// in either direction turns this red.
    #[test]
    fn a_session_url_is_refused_on_every_host_that_is_not_exactly_the_providers() {
        for (url, why) in [
            ("https://evil.chatgpt.com/c/abc", "sub-domain"),
            ("https://EVIL.CHATGPT.COM/c/abc", "sub-domain, upper case"),
            ("https://a.b.c.chatgpt.com/c/abc", "deep sub-domain"),
            ("https://www.chatgpt.com/c/abc", "www. redirects, is not it"),
            ("https://sora.chatgpt.com/c/abc", "sibling product"),
            ("https://chatgpt.com./c/abc", "trailing root dot"),
            ("https://chatgpt.com.evil.test/c/abc", "suffix look-alike"),
            ("https://chatgpt.com@evil.test/c/abc", "userinfo, not host"),
            ("https://evil.gemini.google.com/app/abc", "sub-domain"),
            ("https://evil.claude.ai/chat/abc", "sub-domain"),
            (
                "https://www.claude.ai/chat/abc",
                "www. redirects, is not it",
            ),
        ] {
            let error = resolve_session_target(Provider::ChatGpt, false, url)
                .expect_err(&format!("accepted a non-provider host ({why}): {url}"));
            assert!(
                error.contains("host must be exactly one of:"),
                "{url} was refused, but not by the host rule: {error}"
            );
        }

        // Rejected before this change and still rejected -- the narrowing must
        // not have moved which error explains them.
        for url in ["http://chatgpt.com/c/abc", "http://evil.chatgpt.com/c/abc"] {
            let error = resolve_session_target(Provider::ChatGpt, false, url)
                .expect_err(&format!("accepted a plain-http session URL: {url}"));
            assert!(
                error.contains("must use https"),
                "{url} was refused, but not for its scheme: {error}"
            );
        }
        // A provider-owned host is still not a conversation without the
        // conversation-shaped path, and that stays a *different* error.
        let error =
            resolve_session_target(Provider::ChatGpt, false, "https://chatgpt.com/settings")
                .expect_err("accepted a non-conversation path on the provider host");
        assert!(
            error.contains("not a supported ChatGPT conversation URL"),
            "a provider host with a non-conversation path gave: {error}"
        );

        // Tab identity is a different question and keeps its own, looser
        // answer: a sub-domain tab found in the browser is still the provider's
        // (and is re-checked against its own `location.href`).
        assert!(Provider::ChatGpt.owns_url("https://sora.chatgpt.com/c/abc"));
        assert!(!Provider::ChatGpt.owns_session_origin(
            &Url::parse("https://sora.chatgpt.com/c/abc").expect("valid URL")
        ));
    }

    /// Upstream's message named the rule it wished it had ("belong to
    /// chatgpt.com…"), which reads as if a sub-domain belongs. The message has
    /// to state the rule that actually runs, and name the hosts by asking the
    /// providers rather than by repeating them.
    #[test]
    fn the_session_host_error_states_the_exact_rule_it_enforces() {
        let error =
            resolve_session_target(Provider::ChatGpt, false, "https://evil.chatgpt.com/c/a")
                .expect_err("sub-domain accepted");

        assert!(error.contains("must use https"), "{error}");
        assert!(error.contains("host must be exactly one of:"), "{error}");
        assert!(error.contains("sub-domain"), "{error}");
        assert!(error.contains("trailing dot"), "{error}");
        assert!(error.contains("userinfo"), "{error}");
        for provider in SESSION_PROVIDERS {
            assert!(
                error.contains(provider.primary_host()),
                "{} is accepted but unnamed: {error}",
                provider.primary_host()
            );
        }
        // "belong to" is the wording that made a sub-domain sound allowed.
        assert!(!error.contains("belong to"), "{error}");
        assert!(error.contains("non-default port"), "{error}");
    }

    /// The port is part of the origin, and the rule said "exact origin" while
    /// comparing only scheme and host.
    ///
    /// `https://chatgpt.com:8443/c/abc` is a different origin with different
    /// cookies -- reachable by anyone who can answer on that port for that host
    /// (a proxy, a compromised CDN edge, a machine on a network doing TLS
    /// interception) without owning `chatgpt.com`'s DNS. The accept half is not
    /// decoration: `Url` folds an explicitly written `:443` away, and a fix
    /// written as "reject any URL with a port in the text" would refuse a URL
    /// this tool's own tests build.
    #[test]
    fn a_session_url_is_refused_on_a_non_default_port() {
        for (url, provider) in [
            ("https://chatgpt.com:8443/c/abc", Provider::ChatGpt),
            ("https://chatgpt.com:80/c/abc", Provider::ChatGpt),
            ("https://chatgpt.com:1/c/abc", Provider::ChatGpt),
            ("https://gemini.google.com:8443/app/abc", Provider::Gemini),
            ("https://claude.ai:8443/chat/abc", Provider::Claude),
        ] {
            let error = resolve_session_target(Provider::ChatGpt, false, url)
                .expect_err(&format!("accepted a non-default port: {url}"));
            assert!(
                error.contains("host must be exactly one of:"),
                "{url} was refused, but not by the origin rule: {error}"
            );
            assert!(
                !provider.owns_session_origin(&Url::parse(url).expect("valid URL")),
                "{url} still passes owns_session_origin"
            );
        }

        // The default port, written out or omitted, is the same origin and must
        // stay accepted.
        for url in ["https://chatgpt.com:443/c/abc", "https://chatgpt.com/c/abc"] {
            assert_eq!(
                resolve_session_target(Provider::ChatGpt, false, url),
                Ok((Provider::ChatGpt, "https://chatgpt.com/c/abc".to_string())),
                "the default port was refused: {url}"
            );
        }
    }

    /// Drive [`verify_session_page_is_provider`] against a tab that reports
    /// `live_href`, after the run was asked to open `expected_href`.
    fn session_verdict_for(
        expected_href: &str,
        live_href: &str,
        provider: Provider,
    ) -> Result<(), String> {
        let mut fake = FakeMcp::new(&[(1, "about:blank")]).on_live_url(1, live_href);
        verify_session_page_is_provider(
            &mut |tool, args| fake.call(tool, args),
            provider,
            expected_href,
        )
    }

    /// What `--session` refuses on the command line, a redirect must not hand
    /// back.
    ///
    /// [`resolve_session_target`] restricts the URL to the provider's exact
    /// conversation origin, but the landing page used to be checked with the
    /// *generic* gate, whose predicate is [`Provider::owns_url`] (the sub-domain
    /// rule) or [`Provider::owns_auth_url`]. Every host in this list is one
    /// `resolve_session_target` rejects and the generic gate accepts, so before
    /// the split the input restriction was decorative: land there after
    /// navigation and the prompt is typed in -- [`main`] proceeds through
    /// [`check_login_status`] on both `Ok(Unknown)` and `Err(_)`, so a
    /// composer-shaped DOM on such a page is all it takes.
    #[test]
    fn a_session_tab_that_redirects_off_the_exact_origin_is_refused() {
        for (href, why) in [
            ("https://evil.chatgpt.com/c/abc", "sub-domain"),
            ("https://sora.chatgpt.com/c/abc", "sibling product"),
            ("https://www.chatgpt.com/c/abc", "www."),
            ("https://chatgpt.com./c/abc", "trailing root dot"),
            ("https://chatgpt.com:8443/c/abc", "non-default port"),
            ("http://chatgpt.com/c/abc", "plain http"),
            ("https://chatgpt.com/settings", "not a conversation path"),
            ("https://chatgpt.com/", "root, i.e. a fresh chat"),
            ("https://evil.test/c/abc", "unrelated origin"),
            ("about:blank", "not a URL with a host at all"),
        ] {
            let error = session_verdict_for("https://chatgpt.com/c/abc", href, Provider::ChatGpt)
                .expect_err(&format!("the session tab was driven at {why}: {href}"));
            assert!(
                error.contains(href),
                "the refusal must name what it saw ({why}): {error}"
            );
        }

        // The generic gate is the one that accepts these; that is the whole
        // reason --session may not use it. If this stops holding the two gates
        // have been unified and the split is pointless.
        for href in [
            "https://evil.chatgpt.com/c/abc",
            "https://sora.chatgpt.com/c/abc",
        ] {
            assert!(
                Provider::ChatGpt.owns_url(href),
                "{href} is no longer accepted by the generic predicate"
            );
        }
    }

    /// A session that lands on the provider's own sign-in page is the ordinary
    /// expired-session case: it must stop the run, and it must say what to do.
    ///
    /// This is the one arm where the generic gate's behaviour was defensible --
    /// it returns `Ok` so [`check_login_status`] can print the actionable
    /// message. That is not safe on this path, because `Ok` also means the
    /// prompt gets typed if the page happens to present a composer. Refusing
    /// with the same instructions keeps the help and drops the risk.
    #[test]
    fn a_session_tab_that_lands_on_the_sign_in_page_says_so_and_still_refuses() {
        let error = session_verdict_for(
            "https://chatgpt.com/c/abc",
            "https://auth.openai.com/authorize",
            Provider::ChatGpt,
        )
        .expect_err("a sign-in landing was accepted as a conversation");

        assert!(error.contains("sign-in"), "{error}");
        assert!(error.contains("expired"), "{error}");
        assert!(
            error.contains("ask-bridge --provider chatgpt login"),
            "{error}"
        );
    }

    /// Differential probe: the landing gate must never accept an href that
    /// `--session` itself would refuse on the command line.
    ///
    /// The two checks exist for the same reason and are enforced by different
    /// code — [`resolve_session_target`] restricts what may be *asked for*,
    /// [`verify_session_page_is_provider`] restricts what may be *typed into*.
    /// Any href the second accepts and the first rejects is a way to reach the
    /// composer at a URL the tool was built to refuse: the session is opened at
    /// a legitimate conversation, the page navigates, and the gate waves it
    /// through. So the expected target here is held fixed and legitimate, and
    /// only the live href varies — that is the real shape of the escape.
    ///
    /// The candidate list is a host- and path-spoofing census: case and scheme
    /// variants, an explicit default port and a non-default one, a trailing
    /// root dot, userinfo, backslash-vs-at confusions, percent-encoded and
    /// full-width (U+3002) dots, a punycode lookalike, doubled and traversing
    /// path segments, `blob:`/`javascript:` wrappers, whitespace and newline
    /// padding, a leading-zero port, loopback literals, sibling products, the
    /// auth origin, and the other two providers' conversation URLs.
    ///
    /// Adapted from a 2026-08-07 review probe that predates the current
    /// three-argument `session_verdict_for`; the original passed one href and
    /// could not distinguish "refused because the target was malformed" from
    /// "refused because the landing was". Holding the target fixed removes that
    /// ambiguity.
    #[test]
    fn the_landing_gate_never_accepts_what_the_command_line_refuses() {
        const EXPECTED: &str = "https://chatgpt.com/c/abc";
        let candidates = [
            "https://chatgpt.com/c/abc",
            "https://chatgpt.com:443/c/abc",
            "https://CHATGPT.COM/c/abc",
            "HTTPS://chatgpt.com/c/abc",
            "https://chatgpt.com./c/abc",
            "https://chatgpt.com:8443/c/abc",
            "https://user:pw@chatgpt.com/c/abc",
            "https://chatgpt.com@evil.test/c/abc",
            "https://evil.test\\@chatgpt.com/c/abc",
            "https://chatgpt.com\\@evil.test/c/abc",
            "https://chatgpt.com\\.evil.test/c/abc",
            "https://chatgpt%2ecom/c/abc",
            "https://chatgpt\u{3002}com/c/abc",
            "https://xn--chatgpt-.com/c/abc",
            "https://chatgpt.com:/c/abc",
            "https://chatgpt.com//c/abc",
            "https:/\\chatgpt.com/c/abc",
            "https:\\\\chatgpt.com/c/abc",
            "https://chatgpt.com/%2e%2e/c/abc",
            "https://chatgpt.com/x/../c/abc",
            "https://chatgpt.com/c/abc/../../settings",
            "https://chatgpt.com/settings/c/abc",
            "https://chatgpt.com/c/abc?next=https://evil.test",
            "https://chatgpt.com/c/",
            "https://chatgpt.com/c",
            "https://chatgpt.com/#/c/abc",
            "https://[::ffff:127.0.0.1]/c/abc",
            "https://127.0.0.1/c/abc",
            "https://chatgpt.com.evil.test/c/abc",
            "https://sora.chatgpt.com/c/abc",
            "https://auth.openai.com/authorize",
            "https://gemini.google.com/app/abc",
            "https://claude.ai/chat/abc",
            "  https://chatgpt.com/c/abc  ",
            "https://chatgpt.com/c/abc\n",
            "https://chatgpt.com/c/%61bc",
            "https://chatgpt.com/c/a%2Fb",
            "blob:https://chatgpt.com/c/abc",
            "javascript:location='https://chatgpt.com/c/abc'",
            "https://chatgpt.com:0443/c/abc",
        ];

        let escapes: Vec<&str> = candidates
            .into_iter()
            .filter(|href| {
                let gate = session_verdict_for(EXPECTED, href, Provider::ChatGpt).is_ok();
                let cli = resolve_session_target(Provider::ChatGpt, false, href).is_ok();
                gate && !cli
            })
            .collect();

        assert!(
            escapes.is_empty(),
            "the landing gate accepts hrefs the command line refuses: {escapes:?}"
        );
    }

    /// Anti-tautology: the gate must still pass the page it was aimed at, for
    /// every provider, including the query and fragment a real provider adds.
    #[test]
    fn a_session_tab_still_on_its_conversation_is_accepted() {
        for (live_href, provider) in [
            ("https://chatgpt.com/c/abc", Provider::ChatGpt),
            ("https://chatgpt.com/c/abc?model=gpt-5", Provider::ChatGpt),
            ("https://chatgpt.com/c/abc#top", Provider::ChatGpt),
            ("https://chatgpt.com:443/c/abc", Provider::ChatGpt),
            ("https://gemini.google.com/app/abc", Provider::Gemini),
            ("https://claude.ai/chat/abc", Provider::Claude),
        ] {
            let expected_href = provider.conversation_url_from_id("abc");
            assert_eq!(
                session_verdict_for(&expected_href, live_href, provider),
                Ok(()),
                "the conversation the run was opened at was refused: {live_href}"
            );
        }

        assert_eq!(
            session_verdict_for(
                "https://chatgpt.com:443/c/abc?model=gpt-5#top",
                "https://chatgpt.com/c/abc",
                Provider::ChatGpt,
            ),
            Ok(()),
            "decorations on the original URL must not change its conversation identity"
        );
    }

    #[test]
    fn a_bare_gemini_session_can_land_on_an_account_prefixed_route() {
        assert_eq!(
            session_verdict_for(
                "https://gemini.google.com/app/abc",
                "https://gemini.google.com/u/12/app/abc?pageId=none#response",
                Provider::Gemini,
            ),
            Ok(()),
            "a Gemini account selector changed the spelling, not the conversation"
        );
    }

    #[test]
    fn an_explicit_gemini_account_prefix_must_not_drift() {
        let expected_href = "https://gemini.google.com/u/1/app/abc";

        assert_eq!(
            session_verdict_for(
                expected_href,
                "https://gemini.google.com/u/1/app/abc?pageId=none",
                Provider::Gemini,
            ),
            Ok(()),
            "the explicitly selected Gemini account was refused"
        );

        for live_href in [
            "https://gemini.google.com/u/0/app/abc",
            "https://gemini.google.com/app/abc",
        ] {
            let error = session_verdict_for(expected_href, live_href, Provider::Gemini).expect_err(
                "accepted a Gemini session after its explicit account selector drifted",
            );
            assert!(error.contains(live_href), "unexpected error: {error}");
        }
    }

    #[test]
    fn a_prefixed_gemini_route_still_rejects_a_different_conversation() {
        let live_href = "https://gemini.google.com/u/1/app/different";
        let error = session_verdict_for(
            "https://gemini.google.com/app/original",
            live_href,
            Provider::Gemini,
        )
        .expect_err("accepted a different Gemini conversation behind an account prefix");

        assert!(error.contains(live_href), "unexpected error: {error}");
    }

    #[test]
    fn a_session_tab_that_redirects_to_a_different_conversation_is_refused() {
        for provider in SESSION_PROVIDERS {
            let expected_href = provider.conversation_url_from_id("original");
            let live_href = provider.conversation_url_from_id("different");
            let error = session_verdict_for(&expected_href, &live_href, provider)
                .expect_err("accepted a different conversation on the same provider origin");
            assert!(error.contains(&live_href), "{error}");
        }
    }

    #[test]
    fn a_session_tab_that_redirects_to_a_different_custom_gpt_is_refused() {
        let expected_href = "https://chatgpt.com/g/g-p-one/c/shared-conversation";
        let live_href = "https://chatgpt.com/g/g-p-two/c/shared-conversation";

        let error = session_verdict_for(expected_href, live_href, Provider::ChatGpt)
            .expect_err("accepted the same conversation ID under a different custom GPT");

        assert!(error.contains(live_href), "{error}");
    }

    #[test]
    fn a_session_tab_still_on_its_custom_gpt_conversation_is_accepted() {
        let expected_href = "https://chatgpt.com/g/g-p-one/c/shared-conversation";
        let live_href = "https://chatgpt.com/g/g-p-one/c/shared-conversation?model=gpt-5#response";

        assert_eq!(
            session_verdict_for(expected_href, live_href, Provider::ChatGpt),
            Ok(()),
            "the same custom-GPT conversation was refused after harmless URL decorations"
        );
    }

    /// Realistic ChatGPT tab titles, each rendered the way the server would
    /// (`<title> (<url>)`). `R*` are the ones a rule that treats any
    /// `scheme:`-shaped token as an opaque URL wrongly refuses; `K*` are the
    /// ones that must keep working under any rule.
    const TITLE_CORPUS: &[(&str, &str)] = &[
        (
            "R01",
            "Fix bug (error: undefined) (https://chatgpt.com/c/abc)",
        ),
        ("R02", "npm (ERR: ELIFECYCLE) (https://chatgpt.com/c/abc)"),
        ("R03", "Report (Q1: 2026) (https://chatgpt.com/c/abc)"),
        ("R04", "Notes (see: docs) (https://chatgpt.com/c/abc)"),
        ("R05", "Deploy (ref: #123) (https://chatgpt.com/c/abc)"),
        ("R06", "TODO (urgent: ship) (https://chatgpt.com/c/abc)"),
        (
            "R07",
            "Build fails (C:\\dev\\app) (https://chatgpt.com/c/abc)",
        ),
        ("R08", "Migration (v2: beta) (https://chatgpt.com/c/abc)"),
        ("R09", "SQL (WHERE: id=1) (https://chatgpt.com/c/abc)"),
        (
            "R10",
            "Docker setup (note: use compose) (https://chatgpt.com/c/abc)",
        ),
        ("R11", "Ratio (a:b) explained (https://chatgpt.com/c/abc)"),
        (
            "R12",
            "ChatGPT (GPT-5: thinking) (https://chatgpt.com/c/abc)",
        ),
        ("R13", "Setup (npm: install) (https://chatgpt.com/c/abc)"),
        ("K14", "ChatGPT (2 unread) (https://chatgpt.com/c/abc)"),
        ("K15", "Standup (10:30 AM) (https://chatgpt.com/c/abc)"),
        ("K16", "除錯 (錯誤: 未定義) (https://chatgpt.com/c/abc)"),
        (
            "K17",
            "Compare (http://a.com vs b.com) (https://chatgpt.com/c/abc)",
        ),
        ("K18", "Foo (bar) (baz) (https://chatgpt.com/c/abc)"),
        ("K19", "Q3 plan (draft) (https://chatgpt.com/c/abc)"),
        ("K20", "Plan (phase (one)) (https://chatgpt.com/c/abc)"),
        ("K21", "https://chatgpt.com/ (https://chatgpt.com/c/abc)"),
        ("K22", "https://chatgpt.com/c/abc"),
    ];

    /// Every forgery shape, as whole `list_pages` lines so the `[selected]` and
    /// ` isolatedContext=` suffixes are peeled by the code under test. None of
    /// these may ever resolve to a provider.
    const HOSTILE_CORPUS: &[(&str, &str)] = &[
        (
            "H01 data titled",
            "0: Free VPN (data:text/html,<title>Free VPN</title>x (https://chatgpt.com/)",
        ),
        (
            "H02 data untitled",
            "0: data:text/html,x (https://chatgpt.com/)",
        ),
        (
            "H03 data titled+selected",
            "0: Free VPN (data:text/html,x (https://chatgpt.com/) [selected]",
        ),
        (
            "H04 data untitled+selected",
            "0: data:text/html,x (https://chatgpt.com/) [selected]",
        ),
        (
            "H05 data isolatedContext truncation",
            "0: https://chatgpt.com/ (data:text/html,x isolatedContext=y)",
        ),
        (
            "H06 data isolatedContext double-forge",
            "0: T (data:text/html,x (https://chatgpt.com/) isolatedContext=q)",
        ),
        (
            "H07 data double-forge",
            "0: A (data:x (https://chatgpt.com/) (https://chatgpt.com/)",
        ),
        (
            "H08 near-miss: forged group, marker eats the tail",
            "0: data:text/html,q (https://chatgpt.com/ isolatedContext=y)",
        ),
        (
            "H09 blob titled",
            "0: https://chatgpt.com/ (blob:https://chatgpt.com/6c8f-1234)",
        ),
        ("H10 blob untitled", "0: blob:https://chatgpt.com/6c8f-1234"),
        (
            "H11 javascript titled",
            "0: ChatGPT (javascript:location.href='https://chatgpt.com/')",
        ),
        (
            "H12 javascript untitled",
            "0: javascript:location.href='https://chatgpt.com/'",
        ),
        ("H13 mailto untitled", "0: mailto:ops@chatgpt.com"),
        (
            "H14 data with userinfo lookalike",
            "0: T (data:text/html,x (https://chatgpt.com@evil.test/)",
        ),
    ];

    /// What the production filters ask of a listed page: the provider that owns
    /// it, or `None` when the line could not be read (`Page::url == None`) or
    /// the URL is nobody's.
    fn provider_of(page: &Page) -> Option<Provider> {
        page.url.as_deref().and_then(Provider::from_url)
    }

    /// The URL of the tab that is selected when tab preparation returns -- i.e.
    /// the tab `submit_regular_prompt` would type the prompt into.
    fn prompt_target_url(fake: &FakeMcp) -> String {
        fake.live_url(fake.selected.expect("a page must be selected"))
    }

    // ---------------------------------------------------------------------
    // CLOSED GAP (was: opaque-path URLs can forge the listing grammar).
    //
    // These three tests were written red and `#[ignore]`d while the gap was
    // open. They are the acceptance criteria for closing it, so they now run in
    // the ordinary suite and their names are kept for traceability rather than
    // renamed. What closes them is `page_url_from_label` refusing to answer
    // when a line has more than one possible reading; the root cause -- that
    // `page.url()` keeps raw spaces for opaque-path schemes, so the page
    // chooses where the ` (` and ` isolatedContext=` separators fall -- is
    // unchanged and unfixable in the prose.
    // ---------------------------------------------------------------------

    /// The premise the url-shape guard was removed on --
    /// "`page.url()` never contains a bare space, so ` (` can only come from
    /// the title boundary" -- is false for schemes with an OPAQUE path. The
    /// WHATWG URL serialiser percent-encodes SPACE in the path, query and
    /// fragment of a *special* scheme, but an opaque path (`data:`, `blob:`)
    /// is encoded with the C0-control set only, which does not contain SPACE.
    /// So a `data:` page can put a literal ` (` inside its own URL and choose
    /// what the "trailing parenthesised group" is.
    #[test]
    fn known_gap_g2_data_url_can_forge_the_trailing_group() {
        // One self-contained hostile page: the HTML sets its own title, and the
        // URL carries the forged separator.
        let pages = parse_pages(concat!(
            "## Pages\n",
            "0: Free VPN (data:text/html,<title>Free VPN</title>x (https://chatgpt.com/)\n",
        ));
        assert_eq!(
            provider_of(&pages[0]),
            None,
            "a data: page forged the trailing group and was adopted as a provider (parsed url = {:?})",
            pages[0].url
        );
        // Not merely "no provider matched": the line is unreadable, so the tab
        // has no URL at all and cannot be mistaken for blank or disposable
        // either.
        assert_eq!(pages[0].url, None);
    }

    /// The consequence -- the forged tab is SELECTED on
    /// the reuse path, i.e. it is the tab the prompt gets typed into.
    #[test]
    fn known_gap_g2_forged_tab_is_selected_on_reuse_path() {
        let mut fake = FakeMcp::new(&[
            (
                1,
                "Free VPN (data:text/html,<title>Free VPN</title>x (https://chatgpt.com/)",
            ),
            (2, "https://example.com/"),
        ])
        .on_live_url(
            1,
            "data:text/html,<title>Free VPN</title>x (https://chatgpt.com/",
        );
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        );
        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert!(
            fake.page_ids_for("select_page").is_empty(),
            "the forged data: tab was SELECTED: {:?}",
            fake.page_ids_for("select_page")
        );
        assert_eq!(prompt_target_url(&fake), "https://chatgpt.com/");
    }

    /// The same premise failure reached through the NEW
    /// isolatedContext stripper. The hardening only considered a hostile
    /// *title* embedding the marker; a hostile *URL* embedding it works,
    /// because the name it leaves behind ("y)") has no space.
    #[test]
    fn known_gap_g3_url_can_forge_the_isolated_context_marker() {
        let pages = parse_pages(concat!(
            "## Pages\n",
            "0: https://chatgpt.com/ (data:text/html,x isolatedContext=y)\n",
        ));
        assert_eq!(
            provider_of(&pages[0]),
            None,
            "a data: page forged the isolatedContext marker and was adopted (parsed url = {:?})",
            pages[0].url
        );
        assert_eq!(pages[0].url, None);
    }

    // ---------------------------------------------------------------------
    // The whole seam, one scheme at a time: what `list_pages` printed -> which
    // tab preparation adopts -> which tab the prompt would be typed into.
    //
    // Each case states what is actually known about that scheme. Only `data:`
    // has runtime evidence of a *forgeable separator* (the three tests above,
    // which failed before this guard existed); the others are here because they
    // share the opaque-path property that makes a line unreadable, and the
    // assertions are limited to what each payload demonstrates.
    // ---------------------------------------------------------------------

    /// The hostile tab and the tab the prompt lands on, for a listing that no
    /// provider tab can be read out of.
    fn drive_reuse_path(fake: &mut FakeMcp, provider: Provider) -> (Vec<usize>, String) {
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            provider,
            false,
            true,
            false,
            Duration::ZERO,
        );
        assert!(result.is_ok(), "unexpected error: {:?}", result);
        (fake.page_ids_for("select_page"), prompt_target_url(fake))
    }

    /// `data:` -- the one with runtime evidence. The URL keeps a raw ` (`, so
    /// the page decides where the title/URL boundary appears; here it moves the
    /// boundary with the ` isolatedContext=` marker instead of a second group,
    /// which is the G3 payload driven through the whole seam rather than
    /// through `parse_pages` alone.
    #[test]
    fn data_scheme_tab_reaches_neither_selection_nor_the_prompt() {
        // The hostile tab is deliberately not the selected one. ` [selected]` is
        // appended *after* the marker (McpResponse.js:666), and a trailing
        // ` [selected]` puts a space into the forged name, which the stripper
        // already refuses -- so the payload only bites on a line without it.
        let mut fake = FakeMcp::new(&[
            (1, "https://example.com/"),
            (
                2,
                "https://chatgpt.com/ (data:text/html,x isolatedContext=y)",
            ),
        ])
        .on_live_url(2, "data:text/html,x isolatedContext=y");
        let (selected, prompt_target) = drive_reuse_path(&mut fake, Provider::ChatGpt);

        assert!(
            selected.is_empty(),
            "the data: tab was selected: {selected:?}"
        );
        assert_eq!(prompt_target, "https://chatgpt.com/");
        assert!(
            fake.open_ids().contains(&2),
            "a tab we could not identify is not ours to close"
        );
    }

    /// `blob:` -- a real top-level page URL (`URL.createObjectURL`) that
    /// *contains* the provider's origin, so it is the scheme most likely to
    /// survive a host check written as a substring match.
    ///
    /// **What this pins is [`url_host`]'s pre-existing http(s)-only rule.** The
    /// line reads back unambiguously under both the old parser and the new one
    /// -- the UA mints `blob:<origin>/<uuid>` with no space in it, so no
    /// separator can be forged -- and the *rejection* comes entirely from the
    /// scheme check. Removing that check turns this test red.
    ///
    /// It is not immune to the reading rule, though, and an earlier version of
    /// this comment wrongly claimed it was: a rule broad enough to drop the
    /// whitespace condition makes the whole line a second possible reading, the
    /// URL stops resolving at all, and this test fails on its `parse_pages`
    /// assertion instead (measured: `left: None, right:
    /// Some("blob:https://chatgpt.com/6c8f-1234")`). What it is insensitive to
    /// is the live-URL gate.
    #[test]
    fn blob_scheme_tab_reaches_neither_selection_nor_the_prompt() {
        let mut fake = FakeMcp::new(&[
            (
                1,
                "https://chatgpt.com/ (blob:https://chatgpt.com/6c8f-1234)",
            ),
            (2, "https://example.com/"),
        ])
        .on_live_url(1, "blob:https://chatgpt.com/6c8f-1234");
        let (selected, prompt_target) = drive_reuse_path(&mut fake, Provider::ChatGpt);

        // The line is readable -- exactly one reading survives -- so this tab is
        // rejected on its scheme, not on ambiguity.
        let pages =
            parse_pages("## Pages\n0: https://chatgpt.com/ (blob:https://chatgpt.com/6c8f-1234)\n");
        assert_eq!(
            pages[0].url.as_deref(),
            Some("blob:https://chatgpt.com/6c8f-1234")
        );
        assert!(
            selected.is_empty(),
            "the blob: tab was selected: {selected:?}"
        );
        assert_eq!(prompt_target, "https://chatgpt.com/");
    }

    /// `javascript:` -- a wrapper payload carrying the provider's own URL.
    ///
    /// Same standing as the `blob:` case above: **this pins [`url_host`]'s
    /// http(s)-only rule**, not the ambiguity rule. The line is unambiguous
    /// under every parser variant, so only removing the scheme check turns it
    /// red. Whether Chrome ever leaves a tab on a `javascript:` URL is not
    /// established here -- a `javascript:` navigation replaces the document
    /// without changing its URL -- so no claim is made beyond "a line that
    /// reads as one never reaches the composer".
    #[test]
    fn javascript_scheme_tab_reaches_neither_selection_nor_the_prompt() {
        let mut fake = FakeMcp::new(&[
            (
                1,
                "ChatGPT (javascript:location.href='https://chatgpt.com/')",
            ),
            (2, "https://example.com/"),
        ])
        .on_live_url(1, "javascript:location.href='https://chatgpt.com/'");
        let (selected, prompt_target) = drive_reuse_path(&mut fake, Provider::ChatGpt);

        assert!(
            selected.is_empty(),
            "the javascript: tab was selected: {selected:?}"
        );
        assert_eq!(prompt_target, "https://chatgpt.com/");
    }

    /// `mailto:` -- the case the scheme allow-list deliberately resolves
    /// *against* the parser, and therefore the one that shows why there are two
    /// locks.
    ///
    /// `mailto:ops@evil.test (https://chatgpt.com/)` has two readings a URL
    /// parser would accept: an untitled tab sitting on that whole string, or a
    /// real ChatGPT tab titled `mailto:ops@evil.test`. Only the second is
    /// something a browser can produce -- Chrome hands `mailto:` to an external
    /// protocol handler and never leaves a tab on it -- so
    /// [`SPACE_BEARING_PAGE_SCHEMES`] excludes it and the line resolves to the
    /// provider. That is the right call for real titles and it is exactly the
    /// call that would be wrong if the premise were ever false, so this test
    /// asserts the premise being false is still safe: the tab really is on the
    /// `mailto:` URL, and [`verify_selected_page_is_provider`] refuses it before
    /// anything is typed.
    #[test]
    fn mailto_scheme_tab_reaches_neither_selection_nor_the_prompt() {
        let pages = parse_pages("## Pages\n0: mailto:ops@evil.test (https://chatgpt.com/)\n");
        assert_eq!(
            pages[0].url.as_deref(),
            Some("https://chatgpt.com/"),
            "a mailto:-shaped title must not cost a real provider tab"
        );

        let mut fake = FakeMcp::new(&[
            (1, "mailto:ops@evil.test (https://chatgpt.com/)"),
            (2, "https://example.com/"),
        ])
        .on_live_url(1, "mailto:ops@evil.test (https://chatgpt.com/)");
        let err = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        )
        .expect_err("expected a refusal, got Ok");

        assert!(
            err.contains("mailto:ops@evil.test") && err.contains("refusing"),
            "the error must name what the tab really is: {err}"
        );
        assert!(
            fake.urls_for("new_page").is_empty(),
            "no prompt-bearing tab was reached"
        );
    }

    /// The second lock, on the assumption the first one is built from: the
    /// listing says this tab is ChatGPT's and it reads back unambiguously, but
    /// the tab is really on a `data:` page. That is what a wrong serialisation
    /// model -- or a tab that navigated between `list_pages` and `select_page`
    /// -- looks like from here, and `location.href` is the one answer that does
    /// not come from the prose.
    #[test]
    fn a_tab_whose_live_url_contradicts_the_listing_never_gets_the_prompt() {
        let mut fake = FakeMcp::new(&[(1, "https://chatgpt.com/c/abc")])
            .on_live_url(1, "data:text/html,<h1>fake composer</h1>");
        let err = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        )
        .expect_err("expected a refusal, got Ok");

        assert!(
            err.contains("data:text/html,<h1>fake composer</h1>") && err.contains("refusing"),
            "the error must name what the tab really is: {err}"
        );
        // Nothing was typed anywhere: the caller exits before the composer.
        assert!(fake.urls_for("new_page").is_empty());
    }

    /// Every realistic title in [`TITLE_CORPUS`] must still resolve to the real
    /// URL. The `R*` half is the measured cost of an ambiguity rule that treats
    /// any `scheme:`-shaped token as a possible opaque URL: all 13 of them read
    /// back correctly at HEAD and return `None` under that rule, which turns a
    /// working provider tab into one extra tab on every run, forever.
    #[test]
    fn every_realistic_title_still_reads_back_to_the_real_url() {
        let refused: Vec<&str> = TITLE_CORPUS
            .iter()
            .filter(|(_, label)| page_url_from_label(label) != Some("https://chatgpt.com/c/abc"))
            .map(|(tag, _)| *tag)
            .collect();
        assert!(
            refused.is_empty(),
            "these titles no longer resolve to their tab's URL: {refused:?}"
        );
    }

    /// Every forgery shape in [`HOSTILE_CORPUS`], as whole listing lines so the
    /// `[selected]` and ` isolatedContext=` suffixes are peeled by the code
    /// under test. Titled and untitled, single and double forge, and the
    /// near-miss where the marker eats the tail of a forged group.
    #[test]
    fn no_forged_listing_line_ever_resolves_to_a_provider() {
        let adopted: Vec<(&str, Option<String>)> = HOSTILE_CORPUS
            .iter()
            .map(|(tag, line)| (*tag, parse_pages(&format!("## Pages\n{line}\n"))))
            .filter(|(_, pages)| provider_of(&pages[0]).is_some())
            .map(|(tag, pages)| (tag, pages[0].url.clone()))
            .collect();
        assert!(
            adopted.is_empty(),
            "these forged lines were adopted as a provider: {adopted:?}"
        );
    }

    /// `--new` promises to clean up *this* provider's previous tabs, and a tab
    /// whose line reads back is still disposed of -- a parenthesised title must
    /// not turn the documented cleanup into a leak of one tab per run.
    ///
    /// The unreadable tab is deliberately NOT disposed of. `--new`'s own rule is
    /// that tabs which are not this provider's are not ours to close, and a tab
    /// we cannot name has not been shown to be ours. HEAD closed it, but only as
    /// a side effect of mis-reading it as the provider's -- the same mis-reading
    /// that got the prompt typed into it.
    #[test]
    fn new_session_disposes_readable_provider_tabs_and_spares_unreadable_ones() {
        for (label, live, expected_after) in [
            (
                "Fix bug (error: undefined) (https://chatgpt.com/c/abc)",
                "https://chatgpt.com/c/abc",
                vec![2, 3],
            ),
            (
                "https://chatgpt.com/c/abc",
                "https://chatgpt.com/c/abc",
                vec![2, 3],
            ),
            (
                "Free VPN (data:text/html,x (https://chatgpt.com/)",
                "data:text/html,x (https://chatgpt.com/",
                vec![1, 2, 3],
            ),
        ] {
            let mut fake =
                FakeMcp::new(&[(1, label), (2, "https://example.com/other")]).on_live_url(1, live);
            let result = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::ChatGpt,
                true,
                true,
                false,
                Duration::ZERO,
            );
            assert!(result.is_ok(), "unexpected error for {label:?}: {result:?}");
            assert_eq!(
                fake.open_ids(),
                expected_after,
                "wrong --new disposal for {label:?}"
            );
        }
    }

    /// The path that has no pinned tab: `new_page` came back without an
    /// identifiable fresh ID, so nothing was ever committed to and the readiness
    /// probe runs against whichever tab happens to be selected. Without a check
    /// at the return, a passing probe on a hostile page is enough to send the
    /// prompt there.
    #[test]
    fn an_unpinned_run_verifies_the_tab_before_reporting_success() {
        let mut fake = FakeMcp::new(&[(1, "https://evil.test/")]);
        fake.new_page_opens_nothing = true;
        let err = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        )
        .expect_err("expected a refusal, got Ok");

        assert!(
            err.contains("https://evil.test/") && err.contains("refusing"),
            "the error must name the tab that would have received the prompt: {err}"
        );
    }

    /// The unpinned path is reachable exactly when a logged-out session
    /// redirects the fresh tab to a sign-in host *and* a second tab appears at
    /// the same time (a provider popup, a restored session), which is what
    /// leaves [`fresh_page_ids`] unable to name the tab this run opened.
    ///
    /// Measured: with the gate refusing anything but [`Provider::owns_url`],
    /// both Gemini and ChatGPT returned `Err("...reports
    /// https://accounts.google.com/... instead; refusing to drive it")` where
    /// they previously returned `Ok` and let [`check_login_status`] print the
    /// actionable "run `ask-bridge login`" message. Accepting a provider-owned
    /// sign-in origin restores that, and the second half of this test pins how
    /// narrow the acceptance is.
    #[test]
    fn a_logged_out_fresh_tab_still_reaches_the_login_message() {
        for (provider, landing) in [
            (
                Provider::Gemini,
                "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fgemini.google.com%2Fapp",
            ),
            (Provider::ChatGpt, "https://auth.openai.com/authorize?x=1"),
        ] {
            let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
            fake.new_page_lands_on = Some(landing.to_string());
            fake.new_page_also_opens = Some("https://example.com/popup".to_string());
            let result = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                provider,
                false,
                true,
                false,
                Duration::ZERO,
            );
            assert!(
                result.is_ok(),
                "a sign-in redirect must still reach the login check for {}: {:?}",
                provider.display_name(),
                result
            );
        }

        // Narrow: a sign-in host that is not on its way back to this provider,
        // and a page that is not a sign-in host at all, are both still refused.
        for landing in [
            "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fevil.test%2F",
            "https://evil.test/composer",
        ] {
            let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
            fake.new_page_lands_on = Some(landing.to_string());
            fake.new_page_also_opens = Some("https://example.com/popup".to_string());
            let err = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::Gemini,
                false,
                true,
                false,
                Duration::ZERO,
            )
            .expect_err("expected a refusal, got Ok");
            assert!(err.contains("refusing"), "wrong error for {landing}: {err}");
        }
    }

    /// The accepted cost of the ambiguity rule, pinned so it cannot change
    /// silently.
    ///
    /// A title that itself contains ` (data:` makes its line unreadable: the
    /// `data:` candidate it creates is a URL a browser really could be on, so
    /// nothing in the prose separates "a ChatGPT tab titled `talk about (data:
    /// urls)`" from "a tab sitting on `data: urls) (https://chatgpt.com/c/abc`".
    /// This was NOT narrowed away. Requiring a `data:` candidate to contain a
    /// comma (a real data URL must) would fix the first case below but not the
    /// second, and its failure direction is the wrong one: if the premise were
    /// ever false, a comma-less forgery would become the *unique* reading and be
    /// adopted. The current rule's failure direction is one extra tab.
    ///
    /// The empty-title line is included for completeness: it is refused too,
    /// but it was already unreadable at HEAD, so it is not a regression.
    ///
    /// The cost is bounded and does not accumulate -- the second run adopts the
    /// readable tab the first run opened, rather than opening a third.
    #[test]
    fn a_title_quoting_a_data_url_costs_one_tab_and_is_never_adopted() {
        for line in [
            "1: talk about (data: urls) (https://chatgpt.com/c/abc)",
            "1: A (data:text/html,x) (https://chatgpt.com/c/abc)",
            "1:  (https://chatgpt.com/c/abc)",
        ] {
            let pages = parse_pages(&format!("## Pages\n{line}\n"));
            assert_eq!(pages[0].url, None, "expected an unreadable line: {line}");
        }

        let mut fake = FakeMcp::new(&[(1, "talk about (data: urls) (https://chatgpt.com/c/abc)")])
            .on_live_url(1, "https://chatgpt.com/c/abc");
        for run in 1..=2 {
            let result = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::ChatGpt,
                false,
                true,
                false,
                Duration::ZERO,
            );
            assert!(result.is_ok(), "run {run} failed: {result:?}");
        }
        assert_eq!(
            fake.open_ids(),
            vec![1, 2],
            "the orphaned tab must cost exactly one tab, not one per run"
        );
        assert!(
            !fake.page_ids_for("select_page").contains(&1),
            "the unreadable tab was selected: {:?}",
            fake.page_ids_for("select_page")
        );
    }

    /// The reading rule itself: one possible reading is the answer, and both
    /// "none" and "more than one" are refusals. Written against the boundary
    /// cases the seam tests above cannot show individually.
    #[test]
    fn a_label_is_read_only_when_exactly_one_reading_is_possible() {
        // Unique: the title cannot be a URL, so only the group can be.
        assert_eq!(
            page_url_from_label("ChatGPT (4o) (https://chatgpt.com/c/abc)"),
            Some("https://chatgpt.com/c/abc"),
            "a parenthesised title must not make an unambiguous line unreadable"
        );
        // Unique: an untitled page.
        assert_eq!(
            page_url_from_label("about:blank"),
            Some("about:blank"),
            "blank-tab handling depends on non-http schemes still being read"
        );
        // Two readings -- the opaque URL is one of them.
        assert_eq!(
            page_url_from_label("T (data:text/html,x (https://chatgpt.com/)"),
            None
        );
        // Two readings -- an untitled tab on the whole opaque URL, or a titled
        // tab on the group.
        assert_eq!(
            page_url_from_label("data:text/html,x (https://chatgpt.com/)"),
            None
        );
        // No reading at all: the isolatedContext stripper cut a line mid-URL,
        // and what is left is not something a serialiser emits.
        assert_eq!(
            page_url_from_label("https://chatgpt.com/ (data:text/html,x"),
            None
        );
    }

    /// Reuse path with a stale auth tab present. Asserts the
    /// ORDERING the fix depends on -- the replacement tab must be opened (and
    /// therefore identifiable) BEFORE anything is closed -- and that the auth
    /// tab is never selected.
    ///
    /// The ordering is not cosmetic. If the stale auth tab is the *only* tab,
    /// closing it first leaves the browser with zero pages, which takes the
    /// window and the CDP connection with it. This is the invariant the
    /// disposal's own safety argument rests on ("the tab we drive is already
    /// pinned"), and nothing else checks it.
    #[test]
    fn reuse_path_opens_the_replacement_tab_before_disposing_anything() {
        let mut fake = FakeMcp::new(&[
            (
                1,
                "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fgemini.google.com%2Fapp",
            ),
            (2, "https://example.com/notes"),
        ]);
        let r = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::Gemini,
            false,
            true,
            false,
            Duration::ZERO,
        );
        assert!(r.is_ok(), "unexpected error: {:?}", r);
        let seq: Vec<String> = fake
            .calls
            .iter()
            .map(|(t, a)| {
                format!(
                    "{}{}",
                    t,
                    a.get("pageId")
                        .map(|v| format!("#{}", v))
                        .unwrap_or_default()
                )
            })
            .collect();

        let new_page_at = seq.iter().position(|c| c.starts_with("new_page"));
        let close_at = seq.iter().position(|c| c.starts_with("close_page"));
        match (new_page_at, close_at) {
            (Some(n), Some(c)) => assert!(
                n < c,
                "disposal ran BEFORE the replacement tab existed: {:?}",
                seq
            ),
            other => panic!("expected both a new_page and a close_page: {:?}", other),
        }
        assert!(
            fake.page_ids_for("select_page").is_empty(),
            "an auth tab was selected: {:?}",
            fake.page_ids_for("select_page")
        );
        assert!(
            !fake.open_ids().contains(&1),
            "stale auth tab survived: {:?}",
            fake.open_ids()
        );
        assert!(
            fake.open_ids().contains(&2),
            "the user's unrelated tab was closed: {:?}",
            fake.open_ids()
        );
    }

    /// Q16: the reuse path's disposal must report its close failures the same
    /// way the `--new` path does. The asymmetry was untested.
    #[test]
    fn reuse_path_close_failures_also_reach_the_caller() {
        let mut fake = FakeMcp::new(&[
            (
                1,
                "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fgemini.google.com%2Fapp",
            ),
            (2, "https://example.com/notes"),
        ]);
        fake.close_failures = vec![1];

        let outcome = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::Gemini,
            false,
            true,
            false,
            Duration::ZERO,
        )
        .expect("tab preparation should still succeed");

        assert_eq!(
            outcome.close_failures.len(),
            1,
            "reuse-path close failure never reached the caller: {:?}",
            outcome.close_failures
        );
        assert_eq!(outcome.close_failures[0].0, 1);
    }

    /// Q8: only the parameters that a sign-in flow actually uses may nominate a
    /// destination, and the authoritative one wins regardless of query order.
    #[test]
    fn auth_destination_comes_only_from_known_keys_in_priority_order() {
        // A field the flow never uses cannot smuggle in a destination.
        for smuggled in [
            "https://accounts.google.com/signin?hint=https%3A%2F%2Fgemini.google.com%2Fapp",
            "https://accounts.google.com/signin?state=https%3A%2F%2Fgemini.google.com%2F",
            "https://accounts.google.com/signin?ref=https://gemini.google.com/app",
        ] {
            assert_eq!(auth_destination_host(smuggled), None, "{}", smuggled);
            assert!(
                !Provider::Gemini.owns_auth_url(smuggled),
                "a non-destination parameter nominated a destination: {}",
                smuggled
            );
        }

        // `redirect_uri` outranks weaker carriers wherever it appears.
        let service_first = "https://accounts.google.com/o/oauth2/v2/auth?service=https%3A%2F%2Fgemini.google.com%2Fapp&redirect_uri=https%3A%2F%2Fnotion.so%2Fcb";
        assert_eq!(
            auth_destination_host(service_first),
            Some("notion.so".to_string())
        );
        assert!(!Provider::Gemini.owns_auth_url(service_first));

        let continue_first = "https://accounts.google.com/o/oauth2/v2/auth?continue=https%3A%2F%2Fclaude.ai%2F&redirect_uri=https%3A%2F%2Fnotion.so%2Fcb";
        assert_eq!(
            auth_destination_host(continue_first),
            Some("notion.so".to_string())
        );
        assert!(!Provider::Claude.owns_auth_url(continue_first));

        // A bare service code yields no host, so a real callback still wins.
        let real = "https://accounts.google.com/o/oauth2/v2/auth?service=lso&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fauth%2Fcallback%2Fgoogle";
        assert_eq!(auth_destination_host(real), Some("claude.ai".to_string()));
        assert!(Provider::Claude.owns_auth_url(real));

        // A `?` inside a fragment starts no query.
        assert_eq!(
            auth_destination_host(
                "https://accounts.google.com/signin#x?continue=https%3A%2F%2Fgemini.google.com%2F"
            ),
            None
        );
    }

    /// The single-purpose allow-list must fail CLOSED: any auth host that is
    /// not vetted is treated as shared infrastructure and has to prove its
    /// destination. That applies to every way a host can reach
    /// `Provider::auth_hosts` without being vetted -- a new provider, an
    /// existing provider gaining an auth host, or a host dropped from the
    /// allow-list while still named as some provider's auth host.
    #[test]
    fn unvetted_auth_hosts_default_to_needing_a_destination() {
        assert!(is_single_purpose_auth_host("auth.openai.com"));
        assert!(is_single_purpose_auth_host("auth0.openai.com"));
        // Sub-domain, not equality: a vetted host's sub-domain stays vetted.
        // Matching on equality would silently demote it to needing a
        // destination that a single-purpose login URL does not carry.
        assert!(is_single_purpose_auth_host("sub.auth.openai.com"));
        // Shared today...
        assert!(!is_single_purpose_auth_host("accounts.google.com"));
        // ...and the hosts an unvetted addition would bring, which must not
        // silently inherit the host-only rule.
        assert!(!is_single_purpose_auth_host("login.microsoftonline.com"));
        assert!(!is_single_purpose_auth_host("login.okta.com"));
        // Never a look-alike of a vetted host.
        assert!(!is_single_purpose_auth_host("auth.openai.com.evil.test"));
        assert!(!is_single_purpose_auth_host("notauth.openai.com"));
    }

    /// A hostile page only has to *mention* a provider domain to be adopted as
    /// that provider's tab when ownership is decided by substring. Ownership
    /// must be decided by the canonical host instead.
    #[test]
    fn provider_ownership_rejects_lookalike_hosts() {
        for spoof in [
            "https://chatgpt.com.evil.test/",
            "https://evil.test/?next=chatgpt.com",
            "https://chatgpt.com@evil.test/",
            "https://notchatgpt.com/",
            "https://evil.test/chatgpt.com/c/abc",
            "https://evil.test/#https://chatgpt.com/",
            "https://gemini.google.com.evil.test/",
            "https://gemini.google.com@evil.test/",
            "https://claude.ai.evil.test/",
            "https://claude.ai@evil.test/",
            "https://evil.test/?u=claude.ai",
        ] {
            assert_eq!(Provider::from_url(spoof), None, "spoof accepted: {}", spoof);
            for provider in [Provider::ChatGpt, Provider::Gemini, Provider::Claude] {
                assert!(
                    !provider.owns_url(spoof),
                    "{:?} claimed spoof URL {}",
                    provider,
                    spoof
                );
            }
        }
    }

    /// The narrowing must not break the hosts real usage lands on: the bare
    /// host, `www.`, sub-domains, an explicit port, a trailing root dot and
    /// mixed case.
    #[test]
    fn provider_ownership_accepts_real_provider_hosts() {
        for (url, expected) in [
            ("https://chatgpt.com/", Provider::ChatGpt),
            ("https://chatgpt.com/c/abc?x=1#y", Provider::ChatGpt),
            ("https://www.chatgpt.com/", Provider::ChatGpt),
            ("https://CHATGPT.com/c/abc", Provider::ChatGpt),
            ("https://chatgpt.com./c/abc", Provider::ChatGpt),
            ("https://chatgpt.com:443/c/abc", Provider::ChatGpt),
            ("https://sora.chatgpt.com/", Provider::ChatGpt),
            ("https://gemini.google.com/app", Provider::Gemini),
            ("https://gemini.google.com/app/abc", Provider::Gemini),
            ("https://claude.ai/new", Provider::Claude),
            ("https://claude.ai/chat/abc", Provider::Claude),
            ("https://www.claude.ai/login", Provider::Claude),
        ] {
            assert_eq!(Provider::from_url(url), Some(expected), "rejected: {}", url);
        }
    }

    /// A `data:` URL has a scheme with no `//`, so any
    /// "does the candidate look like a URL?" guard rejects it, keeps the whole
    /// label, and then reads the host out of the page's own *title*.
    #[test]
    fn page_title_cannot_outrank_the_real_url_for_schemes_without_a_double_slash() {
        let pages = parse_pages(concat!(
            "## Pages\n",
            "0: https://chatgpt.com/ (data:text/html,<h1>fake composer</h1>) [selected]\n",
        ));
        assert_eq!(
            provider_of(&pages[0]),
            None,
            "a data: page titled with a provider URL was adopted as that provider (parsed url = {:?})",
            pages[0].url
        );
    }

    /// The consequence that matters -- the spoof tab is not
    /// merely misclassified, it is the tab that gets *selected*, which is the
    /// tab the prompt is then typed into.
    #[test]
    fn data_url_spoof_tab_is_never_selected_on_the_reuse_path() {
        let mut fake = FakeMcp::new(&[
            (
                1,
                "https://chatgpt.com/ (data:text/html,<h1>fake composer</h1>)",
            ),
            (2, "https://example.com/"),
        ])
        .on_live_url(1, "data:text/html,<h1>fake composer</h1>");
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert!(
            fake.page_ids_for("select_page").is_empty(),
            "the data: spoof tab was SELECTED: {:?}",
            fake.page_ids_for("select_page")
        );
    }

    /// Other schemes that carry no `//` and would have slipped through the same
    /// guard, plus the `<scheme>:<http url>` wrappers.
    #[test]
    fn non_http_schemes_are_never_provider_owned() {
        for url in [
            "data:text/html,<h1>x</h1>",
            "blob:https://chatgpt.com/6c8f-1234",
            "javascript:alert(document.domain)",
            "view-source:https://chatgpt.com/",
            "filesystem:https://chatgpt.com/temporary/x",
            "chrome-extension://abcdefghijklmnop/panel.html",
            "file:///Users/x/chatgpt.com/index.html",
            "about:blank",
        ] {
            assert_eq!(
                Provider::from_url(url),
                None,
                "accepted non-http URL: {}",
                url
            );
        }
    }

    /// chrome-devtools-mcp renders a titled page as `<title> (<url>)`. The URL
    /// is the trailing parenthesised group; taking anything else lets a page
    /// title (attacker-controlled) decide which provider owns the tab.
    #[test]
    fn parse_pages_reads_the_url_out_of_a_titled_label() {
        let pages = parse_pages(concat!(
            "## Pages\n",
            "0: ChatGPT (https://chatgpt.com/c/abc) [selected]\n",
            "1: https://gemini.google.com/app\n",
            "2: Wiki (https://en.wikipedia.org/wiki/Foo_(bar))\n",
            "3: Visit https://chatgpt.com now (https://evil.test/)\n",
            "4: Sneaky (https://chatgpt.com/) (https://evil.test/)\n",
        ));
        let urls: Vec<Option<&str>> = pages.iter().map(|p| p.url.as_deref()).collect();
        assert_eq!(
            urls,
            vec![
                Some("https://chatgpt.com/c/abc"),
                Some("https://gemini.google.com/app"),
                Some("https://en.wikipedia.org/wiki/Foo_(bar)"),
                Some("https://evil.test/"),
                Some("https://evil.test/"),
            ]
        );
        assert!(pages[0].selected);
        assert!(!pages[1].selected);
        assert_eq!(provider_of(&pages[0]), Some(Provider::ChatGpt));
        assert_eq!(provider_of(&pages[3]), None);
        assert_eq!(provider_of(&pages[4]), None);
    }

    /// A3: `chrome-devtools-mcp` auto-discovers externally created
    /// BrowserContexts, so one incognito window is enough to append
    /// ` isolatedContext=<name>` *after* `[selected]`. All three shapes must
    /// parse to the real URL and the right selection flag.
    #[test]
    fn parse_pages_handles_the_isolated_context_suffix() {
        let pages = parse_pages(concat!(
            "## Pages\n",
            "0: ChatGPT (https://chatgpt.com/c/abc) [selected]\n",
            "1: ChatGPT (https://chatgpt.com/c/def) isolatedContext=isolated-context-1\n",
            "2: https://chatgpt.com/c/ghi isolatedContext=ask\n",
            "3: https://gemini.google.com/app [selected] isolatedContext=isolated-context-2\n",
        ));
        let parsed: Vec<(Option<&str>, bool, Option<Provider>)> = pages
            .iter()
            .map(|p| (p.url.as_deref(), p.selected, provider_of(p)))
            .collect();
        assert_eq!(
            parsed,
            vec![
                (
                    Some("https://chatgpt.com/c/abc"),
                    true,
                    Some(Provider::ChatGpt)
                ),
                (
                    Some("https://chatgpt.com/c/def"),
                    false,
                    Some(Provider::ChatGpt)
                ),
                (
                    Some("https://chatgpt.com/c/ghi"),
                    false,
                    Some(Provider::ChatGpt)
                ),
                (
                    Some("https://gemini.google.com/app"),
                    true,
                    Some(Provider::Gemini)
                ),
            ]
        );
    }

    /// The isolatedContext marker must be anchored to the grammar, not merely
    /// searched for: a page can put the literal marker in its *title*, and
    /// splitting on that would truncate the label back to attacker-chosen text
    /// -- the same failure mode as A1, through a different door.
    #[test]
    fn a_title_cannot_fake_the_isolated_context_marker() {
        let pages = parse_pages(concat!(
            "## Pages\n",
            "0: https://chatgpt.com/ isolatedContext=z (https://evil.test/)\n",
            "1: https://chatgpt.com/ isolatedContext=z (data:text/html,x)\n",
        ));
        assert_eq!(pages[0].url.as_deref(), Some("https://evil.test/"));
        assert_eq!(provider_of(&pages[0]), None);
        assert_eq!(pages[1].url.as_deref(), Some("data:text/html,x"));
        assert_eq!(provider_of(&pages[1]), None);
    }

    /// A4: `Provider::from_url` needs an explicit http(s) scheme. This is user
    /// reachable -- `ask-bridge open <url>` and `get <url>` both run
    /// `Provider::from_url(&url).unwrap_or(provider)` -- so a bare host now
    /// falls back to the *configured* provider instead of being sniffed out of
    /// the string. Pinned deliberately: a scheme-less argument is not a URL a
    /// browser can navigate to anyway.
    #[test]
    fn scheme_less_urls_do_not_identify_a_provider() {
        for url in [
            "chatgpt.com",
            "chatgpt.com/c/abc",
            "www.chatgpt.com/",
            "gemini.google.com/app",
            "claude.ai/new",
            "//chatgpt.com/c/abc",
            "   https://chatgpt.com/",
        ] {
            assert_eq!(
                Provider::from_url(url),
                None,
                "scheme-less input identified a provider: {}",
                url
            );
        }
    }

    /// `url_host` pins userinfo handling in *both* directions. Only the second
    /// case proves the strip is load-bearing: without it a legitimate provider
    /// URL carrying userinfo is rejected, which is the failure the first case
    /// alone cannot detect.
    #[test]
    fn url_host_resolves_userinfo_ports_and_backslashes_like_a_browser() {
        // Userinfo is not the host.
        assert_eq!(
            url_host("https://chatgpt.com@evil.test/"),
            Some("evil.test".to_string())
        );
        // ...and the host still wins when the userinfo is the scary-looking part.
        assert_eq!(
            url_host("https://evil.test@chatgpt.com/c/abc"),
            Some("chatgpt.com".to_string())
        );
        assert!(Provider::ChatGpt.owns_url("https://evil.test@chatgpt.com/c/abc"));
        assert!(!Provider::ChatGpt.owns_url("https://chatgpt.com@evil.test/"));
        // A backslash ends the authority just like a slash, so it cannot be
        // used to smuggle the real host into what looks like a path.
        assert_eq!(
            url_host("https://evil.test\\@chatgpt.com/"),
            Some("evil.test".to_string())
        );
        assert!(!Provider::ChatGpt.owns_url("https://evil.test\\@chatgpt.com/"));
        // Ports, IPv6 literals, root dot and case.
        assert_eq!(
            url_host("https://chatgpt.com:8443/c/abc"),
            Some("chatgpt.com".to_string())
        );
        assert_eq!(url_host("http://[::1]:9223/json"), Some("::1".to_string()));
        assert_eq!(
            url_host("https://ChatGPT.COM./"),
            Some("chatgpt.com".to_string())
        );
        assert_eq!(url_host("https:///nohost"), None);
        assert_eq!(url_host("chatgpt.com/c/abc"), None);
    }

    /// An offline stand-in for `chrome-devtools-mcp`. It models the page list
    /// the real server keeps (monotonically increasing IDs, `new_page` selects
    /// the page it opened) and records every call, so tab bookkeeping can be
    /// asserted without ever starting a browser.
    ///
    /// `pages` holds the *listing line* for each tab, which is what the real
    /// server prints and the only thing the parser gets to see. What the tab is
    /// really on is a separate fact -- that is the whole point of the attack --
    /// so it lives in `live_urls`, defaults to the listing line (true for the
    /// untitled tabs most fixtures use), and is set explicitly by any test
    /// where the two must disagree. Nothing here derives one from the other;
    /// deriving it would put the code under test into the harness.
    struct FakeMcp {
        pages: Vec<(usize, String)>,
        live_urls: Vec<(usize, String)>,
        selected: Option<usize>,
        next_id: usize,
        calls: Vec<(String, Value)>,
        close_failures: Vec<usize>,
        probes: usize,
        not_ready_probes: usize,
        vanish_page_after_probes: Option<(usize, usize)>,
        new_page_opens_nothing: bool,
        /// Where the tab `new_page` opens actually lands, when that is not the
        /// URL it was asked for -- i.e. a redirect that has already happened by
        /// the time the server echoes the page list.
        new_page_lands_on: Option<String>,
        /// A second tab that appears alongside the one `new_page` opened (a
        /// provider popup, a restored session).
        new_page_also_opens: Option<String>,
        /// A tab that is in the page list `new_page` echoes and already gone by
        /// the time anyone asks again -- a popup that closed itself. It never
        /// enters the fake's state, which is the whole point: it is what makes
        /// the echo and a fresh `list_pages` disagree.
        new_page_echoes_transiently: Option<String>,
    }

    impl FakeMcp {
        fn new(pages: &[(usize, &str)]) -> Self {
            FakeMcp {
                pages: pages
                    .iter()
                    .map(|(id, url)| (*id, (*url).to_string()))
                    .collect(),
                live_urls: Vec::new(),
                selected: pages.first().map(|(id, _)| *id),
                next_id: pages.iter().map(|(id, _)| *id).max().unwrap_or(0) + 1,
                calls: Vec::new(),
                close_failures: Vec::new(),
                probes: 0,
                not_ready_probes: 0,
                vanish_page_after_probes: None,
                new_page_opens_nothing: false,
                new_page_lands_on: None,
                new_page_also_opens: None,
                new_page_echoes_transiently: None,
            }
        }

        /// Say what tab `id` is *really* on, when its listing line says
        /// something else.
        fn on_live_url(mut self, id: usize, url: &str) -> Self {
            self.live_urls.push((id, url.to_string()));
            self
        }

        /// What `() => location.href` answers for tab `id`.
        fn live_url(&self, id: usize) -> String {
            self.live_urls
                .iter()
                .find(|(pid, _)| *pid == id)
                .map(|(_, url)| url.clone())
                .or_else(|| {
                    self.pages
                        .iter()
                        .find(|(pid, _)| *pid == id)
                        .map(|(_, label)| label.clone())
                })
                .unwrap_or_default()
        }

        fn text_result(text: String) -> Value {
            serde_json::json!({"content": [{"type": "text", "text": text}]})
        }

        fn page_list_text(&self) -> String {
            let mut out = String::from("## Pages\n");
            for (id, url) in &self.pages {
                out.push_str(&format!(
                    "{}: {}{}\n",
                    id,
                    url,
                    if self.selected == Some(*id) {
                        " [selected]"
                    } else {
                        ""
                    }
                ));
            }
            out
        }

        fn page_id_arg(args: &Value) -> usize {
            args.get("pageId")
                .and_then(|v| v.as_u64())
                .expect("pageId argument") as usize
        }

        fn call(&mut self, tool: &str, args: Value) -> Result<Value, String> {
            self.calls.push((tool.to_string(), args.clone()));
            match tool {
                "list_pages" => Ok(Self::text_result(self.page_list_text())),
                "new_page" => {
                    if !self.new_page_opens_nothing {
                        let id = self.next_id;
                        self.next_id += 1;
                        let url = self.new_page_lands_on.clone().unwrap_or_else(|| {
                            args.get("url")
                                .and_then(|u| u.as_str())
                                .unwrap_or("about:blank")
                                .to_string()
                        });
                        self.pages.push((id, url));
                        self.selected = Some(id);
                        if let Some(extra) = self.new_page_also_opens.clone() {
                            let extra_id = self.next_id;
                            self.next_id += 1;
                            self.pages.push((extra_id, extra));
                        }
                    }
                    let mut echo = self.page_list_text();
                    if let Some(transient) = self.new_page_echoes_transiently.clone() {
                        let id = self.next_id;
                        self.next_id += 1;
                        echo.push_str(&format!("{}: {}\n", id, transient));
                    }
                    Ok(Self::text_result(echo))
                }
                "navigate_page" => {
                    let url = args
                        .get("url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("about:blank")
                        .to_string();
                    let selected = self.selected.expect("a page must be selected");
                    for page in self.pages.iter_mut() {
                        if page.0 == selected {
                            page.1 = url.clone();
                        }
                    }
                    Ok(Self::text_result(self.page_list_text()))
                }
                "close_page" => {
                    let id = Self::page_id_arg(&args);
                    if self.close_failures.contains(&id) {
                        return Err(format!("close_page failed for page {}", id));
                    }
                    self.pages.retain(|(pid, _)| *pid != id);
                    if self.selected == Some(id) {
                        self.selected = self.pages.first().map(|(pid, _)| *pid);
                    }
                    Ok(Self::text_result(self.page_list_text()))
                }
                "select_page" => {
                    let id = Self::page_id_arg(&args);
                    if !self.pages.iter().any(|(pid, _)| *pid == id) {
                        return Err("No page found".to_string());
                    }
                    self.selected = Some(id);
                    Ok(Self::text_result(self.page_list_text()))
                }
                "evaluate_script" => {
                    let function = args.get("function").and_then(|f| f.as_str()).unwrap_or("");
                    // Exact match, not `contains`: production also evaluates
                    // `() => window.location.href` elsewhere, and a loose match
                    // would silently answer those with a page URL too.
                    if function == LIVE_URL_PROBE_JS {
                        // Not a readiness probe -- do not advance `probes`, or
                        // the tests that count them would drift.
                        let selected = self.selected.expect("a page must be selected");
                        return Ok(Self::text_result(format!(
                            "Script ran.\n```json\n{}\n```",
                            serde_json::json!(self.live_url(selected))
                        )));
                    }
                    self.probes += 1;
                    if let Some((probe, id)) = self.vanish_page_after_probes
                        && self.probes == probe
                    {
                        self.pages.retain(|(pid, _)| *pid != id);
                    }
                    let ready = self.probes > self.not_ready_probes;
                    Ok(Self::text_result(format!(
                        "Script ran.\n```json\n{}\n```",
                        ready
                    )))
                }
                other => Err(format!("unexpected MCP tool call: {}", other)),
            }
        }

        fn open_ids(&self) -> Vec<usize> {
            self.pages.iter().map(|(id, _)| *id).collect()
        }

        fn page_ids_for(&self, tool: &str) -> Vec<usize> {
            self.calls
                .iter()
                .filter(|(name, _)| name == tool)
                .filter_map(|(_, args)| args.get("pageId").and_then(|v| v.as_u64()))
                .map(|id| id as usize)
                .collect()
        }

        fn urls_for(&self, tool: &str) -> Vec<String> {
            self.calls
                .iter()
                .filter(|(name, _)| name == tool)
                .filter_map(|(_, args)| args.get("url").and_then(|v| v.as_str()))
                .map(|url| url.to_string())
                .collect()
        }
    }

    /// `--new` promises to clean up *this* provider's old tabs. Closing every
    /// other tab takes the user's Gemini, Claude and unrelated tabs with it.
    ///
    /// The promise lives in README.md "### 3. 開啟全新對話" and README.en.md
    /// "### 3. Open a Brand New Session (`--new`)". Cited by heading, not by
    /// line number: an upstream rewrite reflows those files and every line
    /// citation here silently starts pointing at unrelated prose, which is
    /// exactly how the docs came to claim the opposite of this code.
    /// [`the_new_flag_docs_still_describe_the_disposal_this_code_performs`] is
    /// the machine-checked half of the same contract.
    #[test]
    fn new_session_leaves_other_providers_tabs_open() {
        let mut fake = FakeMcp::new(&[
            (1, "https://chatgpt.com/c/old"),
            (2, "https://gemini.google.com/app"),
            (7, "https://example.com/notes"),
        ]);
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert_eq!(
            fake.page_ids_for("close_page"),
            vec![1],
            "--new must close only the old ChatGPT tab"
        );
        assert_eq!(fake.open_ids(), vec![2, 7, 8]);
        assert_eq!(fake.selected, Some(8));
    }

    /// A blank launcher tab is not the user's content, and the pre-fix code
    /// disposed of it. Keep doing that so `--new` does not leave one behind.
    #[test]
    fn new_session_still_disposes_of_a_blank_tab() {
        let mut fake = FakeMcp::new(&[(1, "about:blank")]);
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert_eq!(fake.page_ids_for("close_page"), vec![1]);
        assert_eq!(fake.open_ids(), vec![2]);
        assert_eq!(fake.selected, Some(2));
    }

    /// Closing the old tab is best effort. When it fails, the freshly opened
    /// tab must still be the one that gets driven -- picking "the first tab
    /// whose URL looks like the provider" hands the prompt back to the stale
    /// conversation `--new` was asked to escape.
    #[test]
    fn new_session_never_falls_back_to_a_tab_that_failed_to_close() {
        let mut fake = FakeMcp::new(&[
            (1, "https://chatgpt.com/c/old"),
            (2, "https://gemini.google.com/app"),
        ]);
        fake.close_failures = vec![1];
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert!(
            !fake.page_ids_for("select_page").contains(&1),
            "stale tab 1 was selected: {:?}",
            fake.page_ids_for("select_page")
        );
        assert_eq!(fake.selected, Some(3));
        assert!(fake.open_ids().contains(&2), "Gemini tab was closed");
    }

    /// If the new tab cannot be identified, there is no safe fallback: driving
    /// whatever happens to be selected is how a prompt ends up on the wrong
    /// page. Fail immediately instead of waiting out the readiness timeout.
    #[test]
    fn new_session_fails_loud_when_the_new_tab_cannot_be_identified() {
        let mut fake = FakeMcp::new(&[(1, "https://example.com/")]);
        fake.new_page_opens_nothing = true;
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        );

        let err = result.expect_err("expected a loud failure, got Ok");
        assert!(
            err.contains("identify"),
            "error should name the unidentifiable tab: {}",
            err
        );
        assert!(
            fake.page_ids_for("select_page").is_empty(),
            "nothing may be selected when the new tab is unknown"
        );
    }

    /// H1 through the tab-selection seam: a page that merely mentions the
    /// provider domain must never be selected, so a prompt can never be typed
    /// into it.
    #[test]
    fn lookalike_tab_is_never_selected_on_the_reuse_path() {
        let mut fake = FakeMcp::new(&[
            (1, "https://chatgpt.com.evil.test/"),
            (2, "https://example.com/?next=chatgpt.com"),
        ]);
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert!(
            fake.page_ids_for("select_page").is_empty(),
            "a lookalike tab was selected: {:?}",
            fake.page_ids_for("select_page")
        );
        assert_eq!(fake.urls_for("new_page"), vec!["https://chatgpt.com/"]);
        assert!(fake.open_ids().contains(&1), "lookalike tab was closed");
    }

    /// H1 through the `--new` seam: a lookalike tab is neither adopted as the
    /// old provider tab (so it is not closed) nor selected as the new one.
    #[test]
    fn lookalike_tab_is_never_selected_or_closed_on_the_new_path() {
        let mut fake = FakeMcp::new(&[
            (1, "https://chatgpt.com.evil.test/"),
            (2, "https://gemini.google.com/app"),
        ]);
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert_eq!(fake.selected, Some(3));
        assert!(
            fake.page_ids_for("close_page").is_empty(),
            "closed tabs that --new must not touch: {:?}",
            fake.page_ids_for("close_page")
        );
        assert_eq!(fake.open_ids(), vec![1, 2, 3]);
    }

    /// Three consecutive `--new` runs where an expired
    /// session leaves the previous tab parked on the provider's auth host.
    /// Those tabs are neither provider-owned nor blank, so a
    /// same-provider-only filter never closes them and the tab count grows
    /// linearly -- against README.en.md's "avoid cluttering your browser with
    /// too many tabs" (section "### 3. Open a Brand New Session (`--new`)").
    /// The census, not just the final state, is the assertion: it is what
    /// distinguishes "bounded" from "leaking".
    #[test]
    fn new_session_does_not_leak_tabs_that_drifted_to_the_auth_host() {
        let mut fake = FakeMcp::new(&[(1, "https://chatgpt.com/")]);
        let mut census = Vec::new();
        for _ in 0..3 {
            let ok = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::ChatGpt,
                true,
                true,
                false,
                Duration::ZERO,
            );
            assert!(ok.is_ok(), "unexpected error: {:?}", ok);
            // The tab --new just opened gets redirected to the auth host,
            // exactly as an expired session does in the browser.
            let drifted = fake.selected.expect("a tab is selected");
            for page in fake.pages.iter_mut() {
                if page.0 == drifted {
                    page.1 = "https://auth.openai.com/authorize".to_string();
                }
            }
            census.push(fake.open_ids().len());
        }
        assert_eq!(
            census,
            vec![1, 1, 1],
            "--new leaked auth-host tabs: open-tab count after runs 1..3 was {:?}",
            census
        );
    }

    /// The auth-host allowance is scoped to the provider being opened: a
    /// ChatGPT `--new` must not reap a Google account tab, which belongs to the
    /// Gemini/Claude sign-in flow.
    #[test]
    fn auth_host_disposal_is_scoped_to_the_provider() {
        const GEMINI_SIGNIN: &str = "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fgemini.google.com%2Fapp";
        assert!(Provider::ChatGpt.owns_auth_url("https://auth.openai.com/authorize"));
        assert!(!Provider::ChatGpt.owns_auth_url(GEMINI_SIGNIN));
        assert!(Provider::Gemini.owns_auth_url(GEMINI_SIGNIN));
        assert!(!Provider::Gemini.owns_auth_url("https://auth.openai.com/authorize"));
        // Never a real page, and never a look-alike of the auth host either.
        assert!(!Provider::ChatGpt.owns_auth_url("https://chatgpt.com/c/abc"));
        assert!(!Provider::ChatGpt.owns_auth_url("https://auth.openai.com.evil.test/"));

        let mut fake =
            FakeMcp::new(&[(1, GEMINI_SIGNIN), (2, "https://auth.openai.com/authorize")]);
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        );
        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert_eq!(
            fake.page_ids_for("close_page"),
            vec![2],
            "only ChatGPT's own auth tab may be disposed of"
        );
        assert!(
            fake.open_ids().contains(&1),
            "Google account tab was closed"
        );
    }

    /// Every user-visible description of `--new` must still describe the
    /// disposal the code above actually performs.
    ///
    /// This exists because the inversion already happened: an upstream rewrite
    /// replaced "closes previous tabs for the same provider" with "all tabs
    /// will be preserved" on all four surfaces at once, the local disposal code
    /// was kept, and nothing went red -- docs are not compiled and no test read
    /// them. Every behavioural test in this file passed while the documentation
    /// promised the opposite of the behaviour they pinned.
    ///
    /// Two halves, and neither is redundant:
    ///
    /// 1. **Code -> claim.** Re-derive each disposal category from the real
    ///    predicate, so that if `owns_auth_url` or `is_blank_tab_url` ever drops
    ///    out of the filter, the prose below becomes false and this fails here
    ///    rather than in the docs.
    /// 2. **Claim -> docs.** Require each surface to still carry the specific
    ///    vocabulary of what is closed *and* what is spared. A rewrite that
    ///    reduces the section to "existing tabs are preserved" cannot satisfy
    ///    it, and neither can one that deletes the section.
    ///
    /// What it cannot do: judge prose. A surface could keep every required word
    /// and still read badly. It fails on *absence*, which is the failure mode an
    /// upstream rewrite produces.
    #[test]
    fn the_new_flag_docs_still_describe_the_disposal_this_code_performs() {
        // Half 1: the categories, straight from `ensure_provider_tab_with`'s
        // `disposable_ids` filter.
        let provider = Provider::ChatGpt;
        let disposable = |url: &str| {
            provider.owns_url(url) || provider.owns_auth_url(url) || is_blank_tab_url(url)
        };
        for url in [
            "https://chatgpt.com/c/old",         // this provider's own tab
            "about:blank",                       // blank tab
            "https://auth.openai.com/authorize", // stale sign-in tab
        ] {
            assert!(
                disposable(url),
                "the docs pinned below promise {url} is disposed of by --new"
            );
        }
        for url in [
            "https://gemini.google.com/app", // another provider
            "https://example.com/notes",     // an unrelated site
        ] {
            assert!(
                !disposable(url),
                "the docs pinned below promise {url} is spared by --new"
            );
        }

        // Half 2: each surface, by the words that only a disposal description
        // has. `include_str!` also makes cargo rebuild this test when a doc
        // file changes, so editing a README alone is enough to run the check.
        let surfaces: [(&str, &str, &[&str]); 3] = [
            (
                "README.md",
                include_str!("../README.md"),
                &[
                    "清理先前同一 provider 的分頁",
                    "會關閉",
                    "空白分頁",
                    "登入網域",
                    "會保留",
                    "其他 provider 的分頁",
                ],
            ),
            (
                "README.en.md",
                include_str!("../README.en.md"),
                &[
                    "dispose of this\n  provider's previous tabs",
                    "**Closed**",
                    "blank tabs",
                    "sign-in host",
                    "**Preserved**",
                    "other providers' tabs",
                ],
            ),
            (
                "skills/ask-bridge/SKILL.md",
                include_str!("../skills/ask-bridge/SKILL.md"),
                &[
                    "並關閉同一 provider 的既有分頁、空白分頁與停在該 provider 登入網域的分頁",
                    "其他 provider 與其他網站的分頁一律保留",
                ],
            ),
        ];
        for (name, text, required) in surfaces {
            let text = text.replace("\r\n", "\n");
            for needle in required {
                assert!(
                    text.contains(needle),
                    "{name} no longer says {needle:?}; --new still disposes of this \
                     provider's tabs, so this surface now describes behaviour the \
                     code does not have"
                );
            }
        }

        // The fourth surface is `--new`'s clap doc comment, which lives in this
        // very file -- so the needles are split, or this test would find its own
        // source text and pass with the help string deleted.
        let source = include_str!("main.rs");
        for needle in [
            concat!(
                "closing this provider's previous tabs, ",
                "blank tabs and tabs left on its sign-in host"
            ),
            concat!(
                "Other providers' tabs and unrelated ",
                "sites' tabs are preserved"
            ),
        ] {
            assert!(
                source.contains(needle),
                "the clap --help text for --new no longer says {needle:?}; \
                 `ask-bridge --help` is the surface a user reads first"
            );
        }

        // The exact sentences the upstream rewrite installed. Requiring absence
        // is weaker than requiring presence above -- a differently worded
        // inversion slips past it -- but this one has already shipped once.
        let inversions: [(&str, &str, &str); 3] = [
            (
                "README.md",
                include_str!("../README.md"),
                "分頁與其他網站分頁都會保留",
            ),
            (
                "README.en.md",
                include_str!("../README.en.md"),
                "All provider and non-provider tabs that existed before the command will be preserved",
            ),
            (
                "skills/ask-bridge/SKILL.md",
                include_str!("../skills/ask-bridge/SKILL.md"),
                "同時保留所有既有頁籤",
            ),
        ];
        for (name, text, inverted) in inversions {
            assert!(
                !text.contains(inverted),
                "{name} has been re-inverted to {inverted:?}"
            );
        }
    }

    /// M13: a close failure must escape the close loop instead of being
    /// dropped inside it. Its journey out to the caller is pinned separately by
    /// `close_failures_reach_the_caller`.
    #[test]
    fn close_failures_are_returned_not_swallowed() {
        let mut fake = FakeMcp::new(&[
            (1, "https://chatgpt.com/c/old"),
            (2, "https://chatgpt.com/c/older"),
            (3, "https://gemini.google.com/app"),
        ]);
        fake.close_failures = vec![2];

        let failures = close_tabs(
            &mut |tool, args| fake.call(tool, args),
            &[1, 2],
            Provider::ChatGpt,
            false,
        );

        assert_eq!(
            failures.len(),
            1,
            "expected exactly one failure: {:?}",
            failures
        );
        assert_eq!(failures[0].0, 2);
        assert!(
            failures[0].1.contains("close_page failed"),
            "the underlying error must be carried, got {:?}",
            failures[0].1
        );
        // The one that could close, did; the stubborn one is still open.
        assert_eq!(fake.open_ids(), vec![2, 3]);
    }

    /// N1/N4: the failures must survive the *call site* too. Collecting them
    /// inside `close_tabs` and then discarding them there (`let _ = ...`, or
    /// consuming the vec and reporting nothing) just moves the silence one
    /// frame out, so pin the value the caller actually receives.
    #[test]
    fn close_failures_reach_the_caller() {
        let mut fake = FakeMcp::new(&[
            (1, "https://chatgpt.com/c/old"),
            (2, "https://gemini.google.com/app"),
        ]);
        fake.close_failures = vec![1];

        let outcome = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        )
        .expect("tab preparation should still succeed");

        assert_eq!(
            outcome.close_failures.len(),
            1,
            "caller was not told about the close failure: {:?}",
            outcome.close_failures
        );
        assert_eq!(outcome.close_failures[0].0, 1);
        // A clean run must not invent failures.
        let mut clean = FakeMcp::new(&[(1, "https://chatgpt.com/c/old")]);
        let ok = ensure_provider_tab_with(
            &mut |tool, args| clean.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        )
        .expect("tab preparation should succeed");
        assert!(ok.close_failures.is_empty());
    }

    /// Item 2: `accounts.google.com` is shared infrastructure, so the host
    /// alone must not authorise closing a tab. Only a sign-in URL that says it
    /// is heading back to *this* provider counts as our debris.
    #[test]
    fn shared_google_auth_host_is_disposable_only_for_its_own_destination() {
        // continue= pointing at the provider -> ours.
        assert!(Provider::Gemini.owns_auth_url(
            "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fgemini.google.com%2Fapp"
        ));
        assert!(Provider::Gemini.owns_auth_url(
            "https://accounts.google.com/ServiceLogin?continue=https://gemini.google.com/app&hl=en"
        ));
        // Claude signs in through Google OAuth, which carries redirect_uri.
        assert!(Provider::Claude.owns_auth_url(
            "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&redirect_uri=https%3A%2F%2Fclaude.ai%2Fapi%2Fauth%2Fcallback%2Fgoogle&scope=email"
        ));

        // An unrelated app's consent screen -> never ours, for any provider.
        let stranger = "https://accounts.google.com/o/oauth2/v2/auth?client_id=999&redirect_uri=https%3A%2F%2Fnotion.so%2Fcallback&scope=drive";
        for provider in [Provider::Gemini, Provider::Claude, Provider::ChatGpt] {
            assert!(
                !provider.owns_auth_url(stranger),
                "{:?} claimed a third-party consent screen",
                provider
            );
        }

        // No destination parameter at all -> hands off (account chooser, a
        // half-typed password, a 2FA prompt waiting on a phone).
        for bare in [
            "https://accounts.google.com/AccountChooser",
            "https://accounts.google.com/signin/v2/identifier",
            "https://accounts.google.com/",
            "https://accounts.google.com/signin?hl=en&flowName=GlifWebSignIn",
        ] {
            for provider in [Provider::Gemini, Provider::Claude] {
                assert!(
                    !provider.owns_auth_url(bare),
                    "{:?} claimed a bare Google page: {}",
                    provider,
                    bare
                );
            }
        }

        // A destination that only look-alikes the provider is not a match.
        assert!(!Provider::Gemini.owns_auth_url(
            "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fgemini.google.com.evil.test%2F"
        ));
        // The single-purpose host still needs no destination check.
        assert!(Provider::ChatGpt.owns_auth_url("https://auth.openai.com/authorize"));
    }

    /// The user's in-progress Google sign-in for something else survives a
    /// `--new`, while the provider's own drifted tab still gets cleaned up.
    #[test]
    fn new_session_spares_an_unrelated_google_consent_screen() {
        let mut fake = FakeMcp::new(&[
            (
                1,
                "https://accounts.google.com/o/oauth2/v2/auth?client_id=999&redirect_uri=https%3A%2F%2Fnotion.so%2Fcallback",
            ),
            (
                2,
                "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fgemini.google.com%2Fapp",
            ),
        ]);
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::Gemini,
            true,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert_eq!(
            fake.page_ids_for("close_page"),
            vec![2],
            "only the tab heading back to Gemini may be closed"
        );
        assert!(
            fake.open_ids().contains(&1),
            "a third-party consent screen was closed"
        );
    }

    /// Item 4: the default (reuse) path opens a tab whenever no provider tab is
    /// found -- which is exactly what a drifted login tab looks like -- so
    /// without disposal it leaks one tab per invocation. Disposing is safe here
    /// only because the tab being driven is the freshly opened, already pinned
    /// one; the login page is never selected.
    #[test]
    fn reuse_path_does_not_leak_drifted_login_tabs() {
        let mut fake = FakeMcp::new(&[(
            1,
            "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fgemini.google.com%2Fapp",
        )]);
        let mut census = Vec::new();
        for _ in 0..3 {
            let ok = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::Gemini,
                false,
                true,
                false,
                Duration::ZERO,
            );
            assert!(ok.is_ok(), "unexpected error: {:?}", ok);
            let drifted = fake.selected.expect("a tab is selected");
            for page in fake.pages.iter_mut() {
                if page.0 == drifted {
                    page.1 =
                        "https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fgemini.google.com%2Fapp"
                            .to_string();
                }
            }
            census.push(fake.open_ids().len());
        }
        assert_eq!(
            census,
            vec![1, 1, 1],
            "the reuse path leaked drifted login tabs: {:?}",
            census
        );
        // The login tab is disposed of, never driven.
        assert!(
            fake.page_ids_for("select_page").is_empty(),
            "a login page was selected: {:?}",
            fake.page_ids_for("select_page")
        );
    }

    /// M15: when more than one tab appears (a provider popup, a restored
    /// session) the provider-owned one is the answer, and a genuinely
    /// ambiguous result stays ambiguous so the caller fails loud.
    #[test]
    fn fresh_page_ids_disambiguates_by_provider_ownership() {
        let after = parse_pages(concat!(
            "## Pages\n",
            "1: https://example.com/\n",
            "2: https://chatgpt.com/\n",
            "3: https://tracker.example.net/popup\n",
        ));
        assert_eq!(fresh_page_ids(&[1], &after, Provider::ChatGpt), vec![2]);
        // Nothing new at all, and two equally plausible new tabs, both stay
        // un-disambiguated -- that is what makes the caller refuse to guess.
        assert!(fresh_page_ids(&[1, 2, 3], &after, Provider::ChatGpt).is_empty());
        let two_owned = parse_pages(concat!(
            "## Pages\n",
            "1: https://example.com/\n",
            "2: https://chatgpt.com/\n",
            "3: https://chatgpt.com/c/other\n",
        ));
        assert_eq!(
            fresh_page_ids(&[1], &two_owned, Provider::ChatGpt),
            vec![2, 3]
        );
    }

    /// [`created_page_id`] answers a different question from [`fresh_page_ids`]
    /// -- "which of these did *this* client's `new_page` open" -- and each of
    /// its three answers is a decision the caller acts on.
    #[test]
    fn created_page_id_reads_the_selection_new_page_moved() {
        // The fresh tab this client selected, even though the *other* fresh tab
        // is the one that reads back as the provider's.
        let after = parse_pages(concat!(
            "## Pages\n",
            "1: https://example.com/\n",
            "2: https://auth.openai.com/authorize?x=1 [selected]\n",
            "3: https://chatgpt.com/c/other\n",
        ));
        assert_eq!(created_page_id(&[1], &after), Some(2));

        // A tab that was already there is not one this run created, however
        // firmly the listing says it is selected.
        let stale = parse_pages(concat!(
            "## Pages\n",
            "1: https://chatgpt.com/c/old [selected]\n",
            "2: https://chatgpt.com/\n",
        ));
        assert_eq!(created_page_id(&[1], &stale), None);

        // `[selected]` is prose, and an untitled `data:` URL can end in it, so
        // a page can forge a second claim. Two claimants is "cannot identify",
        // never "take the first" -- the forged one sorts first here.
        let forged = parse_pages(concat!(
            "## Pages\n",
            "1: https://example.com/\n",
            "2: data:text/html,x [selected]\n",
            "3: https://chatgpt.com/ [selected]\n",
        ));
        assert_eq!(created_page_id(&[1], &forged), None);
    }

    /// The marker is emitted as `' [selected]'` -- always with that leading
    /// space (chrome-devtools-mcp 1.5.0, McpResponse.js:666, and the label it
    /// follows is either `<title> (<url>)` or a bare URL, never empty). A URL
    /// that merely *ends* in the six characters is not a selected page, and
    /// reading it as one costs a claimant: with the run's own tab already
    /// claiming, two claimants is `None`, and `None` now aborts the run.
    #[test]
    fn a_url_that_ends_in_the_marker_is_not_a_selected_page() {
        // Untitled because it is still loading, which is exactly when a fresh
        // tab shows its bare URL.
        let pages = parse_pages(concat!(
            "## Pages\n",
            "1: https://example.com/\n",
            "2: https://notes.example.com/board#[selected]\n",
            "3: https://chatgpt.com/ [selected]\n",
        ));
        assert_eq!(
            pages
                .iter()
                .filter(|p| p.selected)
                .map(|p| p.id)
                .collect::<Vec<_>>(),
            vec![3],
            "a URL ending in the literal text was read as a second selection"
        );
        assert_eq!(
            pages[1].url.as_deref(),
            Some("https://notes.example.com/board#[selected]"),
            "the URL must not be truncated at the text that looks like the marker"
        );
        assert_eq!(created_page_id(&[1], &pages), Some(3));

        // The space is what upstream emits, so a page that puts one there can
        // still forge a claim -- `created_page_id`'s answer to that is `None`,
        // not "take the first", and that must not change.
        let forged = parse_pages(concat!(
            "## Pages\n",
            "1: https://example.com/\n",
            "2: data:text/html,x [selected]\n",
            "3: https://chatgpt.com/ [selected]\n",
        ));
        assert_eq!(created_page_id(&[1], &forged), None);
    }

    /// Two ask-bridge runs against the same Chrome each get their own
    /// chrome-devtools-mcp child, but the browser's page-ID space is shared. So
    /// a run that opens its tab while the other run is opening one sees *two*
    /// fresh provider tabs and [`fresh_page_ids`] cannot name either as its
    /// own.
    ///
    /// Continuing unpinned from there is not "only losing the pinning": every
    /// fallback left picks by origin alone. The readiness re-focus takes the
    /// *first* provider-owned tab in the listing, and the final gate
    /// (`verify_selected_page_is_provider`) checks the origin and never the tab
    /// identity -- so the run types its prompt into the other run's
    /// conversation, both prompts interleave in one tab, and each run copies
    /// whichever assistant message happened to be last. Two silently wrong
    /// artifacts, both exit 0.
    #[test]
    fn two_fresh_provider_tabs_are_refused_rather_than_driven_unpinned() {
        let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
        // The other run's tab, landing between this run's snapshot and the
        // page list its own `new_page` echoes back.
        fake.new_page_also_opens = Some("https://chatgpt.com/".to_string());
        let err = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        )
        .expect_err("expected a refusal, got Ok");

        assert!(
            err.contains("refusing") && err.contains("[2, 3]"),
            "the error must refuse and name the tabs it could not tell apart: {err}"
        );

        // Positive control, and the reason the refusal keys on *provider-owned*
        // ambiguity rather than on "more than one fresh ID": a second tab that
        // is not the provider's leaves fresh_page_ids able to name the one that
        // is, so the run still pins and proceeds.
        let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
        fake.new_page_also_opens = Some("https://example.com/popup".to_string());
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {result:?}");
        assert_eq!(
            fake.page_ids_for("select_page"),
            Vec::<usize>::new(),
            "the pinned tab is the one new_page already selected"
        );
    }

    /// The refusal above ends the run, so it must not rest on a single
    /// snapshot. The list `new_page` echoes can still name a tab that has
    /// already gone -- a popup that closed itself -- and that is not a second
    /// run. Ask once more before refusing, which is the same second look the
    /// `--new` branch takes at the same ambiguity.
    #[test]
    fn a_tab_that_is_gone_on_the_second_look_is_not_a_second_run() {
        let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
        fake.new_page_echoes_transiently = Some("https://chatgpt.com/c/other".to_string());
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        );

        assert!(
            result.is_ok(),
            "a tab that no longer exists must not end the run: {result:?}"
        );
        assert_eq!(
            fake.selected,
            Some(2),
            "the run must still pin the tab it opened"
        );
    }

    /// The ambiguity guard above only fires when *both* fresh tabs read back as
    /// the provider's. Two concurrent runs do not have to be in step, and the
    /// asymmetric interleaving is the common one:
    ///
    /// 1. this run's own tab is created but is still blank / mid-redirect / on
    ///    the auth host when the listing is taken;
    /// 2. the other run's tab, opened a moment earlier, has already settled on
    ///    the provider;
    /// 3. so exactly *one* fresh ID is provider-owned -- the other run's.
    ///
    /// `owned_fresh.len() > 1` never fires, [`fresh_page_ids`] hands back that
    /// single "owned" ID as if it were an answer, and the run pins the other
    /// run's conversation. Pinning is not a hint either: it is what the
    /// readiness re-focus goes back to, and it *suppresses* the origin check at
    /// the return, so every prompt, copy and artifact from there on lands in
    /// the other run's tab with nothing left to notice.
    ///
    /// Provider-URL matching cannot tell "this run opened it" from "it happens
    /// to be on the provider". Only the listing `new_page` echoed back to
    /// *this* client can, because that client's own selection is what
    /// `new_page` moved -- see [`created_page_id`].
    #[test]
    fn a_fresh_provider_tab_this_run_did_not_open_is_never_pinned() {
        for force_new in [false, true] {
            let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
            // This run's tab: created, selected, still on the sign-in host.
            fake.new_page_lands_on = Some("https://auth.openai.com/authorize?x=1".to_string());
            // The other run's tab: already loaded, never selected here.
            fake.new_page_also_opens = Some("https://chatgpt.com/c/other".to_string());
            // Reach the attempt-10 re-focus, so that a run which did pin the
            // wrong tab is caught driving it rather than merely naming it.
            fake.not_ready_probes = 10;

            let err = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::ChatGpt,
                force_new,
                true,
                false,
                Duration::ZERO,
            )
            .expect_err(&format!(
                "expected a refusal, got Ok (force_new={force_new})"
            ));

            assert!(
                err.contains("refusing") && err.contains("(ID: 3)"),
                "the error must refuse and name the tab it would have driven (force_new={force_new}): {err}"
            );
            assert!(
                !fake.page_ids_for("select_page").contains(&3),
                "the tab this run did not open was driven (force_new={force_new}): {:?}",
                fake.page_ids_for("select_page")
            );
        }

        // Positive control: the same sign-in landing with no second run in the
        // browser still pins this run's own tab and proceeds, so the refusal
        // above is keyed on the collision and not on the redirect.
        for force_new in [false, true] {
            let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
            fake.new_page_lands_on = Some("https://auth.openai.com/authorize?x=1".to_string());
            fake.not_ready_probes = 10;

            let result = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::ChatGpt,
                force_new,
                true,
                false,
                Duration::ZERO,
            );

            assert!(
                result.is_ok(),
                "a sign-in redirect must still reach the login check (force_new={force_new}): {result:?}"
            );
            assert_eq!(
                fake.selected,
                Some(2),
                "the run must stay on the tab it opened (force_new={force_new})"
            );
        }
    }

    /// The cost of reading the identity out of prose: whatever makes
    /// [`created_page_id`] answer `None` now *aborts* a run that would
    /// otherwise have been fine. So the reading has to be exact.
    ///
    /// One run, no collision, its own tab correctly fresh, selected and on the
    /// provider -- plus one ordinary tab that appeared alongside it and whose
    /// URL happens to end in the six characters `[selected]`. Nothing here is
    /// ambiguous to a reader; it was ambiguous only to a suffix match that did
    /// not require the space the marker is always emitted with.
    #[test]
    fn a_tab_whose_url_ends_in_the_marker_does_not_abort_an_uncontested_run() {
        for force_new in [false, true] {
            let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
            fake.new_page_also_opens =
                Some("https://notes.example.com/board#[selected]".to_string());

            let result = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::ChatGpt,
                force_new,
                true,
                false,
                Duration::ZERO,
            );

            assert!(
                result.is_ok(),
                "an uncontested run was refused because another tab's URL ends \
                 in the marker text (force_new={force_new}): {result:?}"
            );
            assert_eq!(
                fake.selected,
                Some(2),
                "the run must drive the tab it opened (force_new={force_new})"
            );
        }
    }

    /// The other half of the same refusal: `created == None` is "cannot
    /// identify", and that is a refusal too, not a licence to take the only
    /// candidate on offer.
    ///
    /// The listing comes back with exactly one fresh provider tab and *no*
    /// fresh tab that this client selected. That is reachable without any
    /// forgery: this run's own tab can be gone by the time the list is taken --
    /// it closed itself, or it crashed -- and when the selected page goes away
    /// chrome-devtools-mcp 1.5.0 re-selects `#pages[0]`
    /// (`McpContext.createPagesSnapshot`), which is some tab that was already
    /// there. What is left unclaimed is the *other* run's fresh provider tab,
    /// and adopting it is the whole defect this guard exists for.
    #[test]
    fn a_fresh_provider_tab_that_no_selection_claims_is_refused_too() {
        for force_new in [false, true] {
            let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
            fake.new_page_opens_nothing = true;
            fake.new_page_echoes_transiently = Some("https://chatgpt.com/".to_string());

            let err = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::ChatGpt,
                force_new,
                true,
                false,
                Duration::ZERO,
            )
            .expect_err(&format!(
                "a fresh provider tab this run cannot claim was driven anyway \
                 (force_new={force_new})"
            ));

            assert!(
                err.contains("is not the tab this run opened") && err.contains("opened: None"),
                "the refusal must be the identity one, and must say that nothing \
                 claimed the tab (force_new={force_new}): {err}"
            );
            assert!(
                !fake.page_ids_for("select_page").contains(&2),
                "the unclaimed tab was driven (force_new={force_new}): {:?}",
                fake.page_ids_for("select_page")
            );
        }
    }

    // ---------------------------------------------------------------------
    // What the causal-identity guard does NOT cover. Both tests below assert
    // today's behaviour so that it is disclosed and cannot change silently; a
    // failure here means the gap was closed, and the test should be rewritten
    // to say so rather than relaxed.
    // ---------------------------------------------------------------------

    /// `--new` disposes of a provider tab another run is using.
    ///
    /// The identity guard protects the tab this run *opens*. It says nothing
    /// about the tabs `--new` clears away first, and nothing in a listing
    /// separates "the other run's live conversation" from "a tab the user left
    /// open", which is exactly what `--new` is documented to clear.
    #[test]
    fn known_gap_h10_new_disposes_of_another_runs_conversation_tab() {
        let mut fake = FakeMcp::new(&[(1, "ChatGPT (https://chatgpt.com/c/other-run)")]);

        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {result:?}");
        assert_eq!(
            fake.page_ids_for("close_page"),
            vec![1],
            "`--new` no longer closes a provider tab it cannot prove is stale; \
             if that is deliberate this gap is closed and this test should be \
             rewritten to state the new rule"
        );
    }

    /// Every identity refusal leaks the tab it had already opened.
    ///
    /// The refusal happens after `new_page`, and the run cannot clean up after
    /// itself for the same reason it is refusing: it does not know which of the
    /// fresh tabs is its own, and closing the wrong one would take the other
    /// run's conversation with it. The leak is not inert -- the leftover
    /// provider tab is what the *next* run's adopt branch picks up (see the
    /// comment on that branch), so repeated collisions make the adoption gap
    /// more likely, not less.
    #[test]
    fn known_gap_h10_a_refusal_leaves_the_tab_it_opened_behind() {
        for force_new in [false, true] {
            let mut fake = FakeMcp::new(&[(1, "https://example.com/notes")]);
            fake.new_page_lands_on = Some("https://auth.openai.com/authorize?x=1".to_string());
            fake.new_page_also_opens = Some("https://chatgpt.com/c/other".to_string());

            let err = ensure_provider_tab_with(
                &mut |tool, args| fake.call(tool, args),
                Provider::ChatGpt,
                force_new,
                true,
                false,
                Duration::ZERO,
            )
            .expect_err(&format!(
                "expected the identity refusal (force_new={force_new})"
            ));
            assert!(err.contains("refusing"), "{err}");

            assert!(
                fake.open_ids().contains(&2),
                "the refused run cleaned up the tab it opened (force_new={force_new}); \
                 this gap is closed and this test should be rewritten: {:?}",
                fake.open_ids()
            );
            assert!(
                fake.page_ids_for("close_page").is_empty(),
                "a refusal closed a tab (force_new={force_new}): {:?}",
                fake.page_ids_for("close_page")
            );
        }
    }

    /// The adopt path drives a provider tab this run never opened.
    ///
    /// This is the largest of the three gaps and was the only one with no
    /// change detector at all -- the other two have one each, while this one
    /// had a comment. The causal-identity guard covers the window in which a
    /// tab is *fresh*; from `provider_pages.first()` down the only gate is
    /// `verify_selected_page_is_provider`, which asks where the tab is and
    /// never whose it is. A conversation another run is in the middle of is
    /// indistinguishable from the idle tab this branch exists to reuse, and the
    /// leak pinned by the test above makes that collision more likely with
    /// every refusal, not less.
    ///
    /// Not closable here: the identity the fresh-tab branch uses comes from
    /// this client's own `new_page`, and a settled tab was never opened by this
    /// run, so there is nothing to compare it against. A failure means the gap
    /// was closed -- rewrite this test to state the new rule rather than
    /// relaxing it.
    #[test]
    fn known_gap_h10_the_adopt_path_drives_another_runs_conversation_tab() {
        let mut fake = FakeMcp::new(&[
            (1, "https://example.com/notes"),
            (
                2,
                "ChatGPT (https://chatgpt.com/c/another-runs-conversation)",
            ),
        ])
        .on_live_url(2, "https://chatgpt.com/c/another-runs-conversation");

        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {result:?}");
        assert_eq!(
            fake.page_ids_for("select_page"),
            vec![2],
            "the adopt path no longer drives a settled provider tab it cannot \
             prove it opened; if that is deliberate this gap is closed and this \
             test should be rewritten to state the new rule"
        );
        // Not merely "selected": this is the tab the prompt is typed into and
        // the tab the answer is copied back from.
        assert_eq!(
            prompt_target_url(&fake),
            "https://chatgpt.com/c/another-runs-conversation",
            "the run would type its prompt into the other run's conversation"
        );
        assert!(
            fake.urls_for("new_page").is_empty(),
            "a tab was opened instead of adopted, so this no longer exercises \
             the adopt path: {:?}",
            fake.urls_for("new_page")
        );
    }

    /// While waiting for the page to load, the periodic re-focus must go back
    /// to the tab this call pinned. Re-deriving "the first tab that looks like
    /// the provider" hands the session to the stale tab that failed to close.
    #[test]
    fn readiness_refocus_returns_to_the_pinned_tab() {
        let mut fake = FakeMcp::new(&[
            (1, "https://chatgpt.com/c/old"),
            (2, "https://gemini.google.com/app"),
        ]);
        fake.close_failures = vec![1];
        // Force the loop past the attempt-10 re-focus checkpoint.
        fake.not_ready_probes = 10;
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert_eq!(
            fake.page_ids_for("select_page"),
            vec![3, 3],
            "the re-focus must return to the pinned tab, not the stale one"
        );
    }

    /// If the pinned tab is gone there is nothing safe to fall back to: the
    /// readiness probe would run against whatever is selected, and the
    /// Gemini/Claude probes treat a bare "Sign in|登入" on *any* page as ready.
    #[test]
    fn readiness_fails_loud_when_the_pinned_tab_disappears() {
        let mut fake = FakeMcp::new(&[(1, "https://chatgpt.com/c/old")]);
        fake.not_ready_probes = 50;
        fake.vanish_page_after_probes = Some((5, 2));
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            true,
            true,
            false,
            Duration::ZERO,
        );

        let err = result.expect_err("expected a loud failure, got Ok");
        assert!(
            err.contains("disappeared"),
            "error should say the pinned tab vanished: {}",
            err
        );
    }

    /// Regression guard for the ordinary reuse path: a real provider tab is
    /// still found and focused instead of opening yet another tab.
    #[test]
    fn reuse_path_still_focuses_an_existing_provider_tab() {
        let mut fake = FakeMcp::new(&[
            (4, "https://example.com/"),
            (5, "ChatGPT (https://chatgpt.com/c/abc)"),
        ])
        .on_live_url(5, "https://chatgpt.com/c/abc");
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::ChatGpt,
            false,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert_eq!(fake.page_ids_for("select_page"), vec![5]);
        assert!(fake.urls_for("new_page").is_empty());
        assert_eq!(fake.open_ids(), vec![4, 5]);
    }

    /// Regression guard: a lone blank tab is still navigated in place rather
    /// than leaving a spare tab behind.
    #[test]
    fn reuse_path_still_navigates_a_lone_blank_tab() {
        let mut fake = FakeMcp::new(&[(1, "about:blank")]);
        let result = ensure_provider_tab_with(
            &mut |tool, args| fake.call(tool, args),
            Provider::Gemini,
            false,
            true,
            false,
            Duration::ZERO,
        );

        assert!(result.is_ok(), "unexpected error: {:?}", result);
        assert_eq!(
            fake.urls_for("navigate_page"),
            vec!["https://gemini.google.com/app"]
        );
        assert!(fake.urls_for("new_page").is_empty());
        assert_eq!(fake.open_ids(), vec![1]);
    }

    #[test]
    fn parses_chatgpt_agent_prompt_with_chinese_agent_name() {
        assert_eq!(
            parse_chatgpt_agent_prompt(
                "@智慧 研究多奇數位創意有限公司的發展沿革與創辦人的豐功偉業"
            ),
            Some(ChatGptAgentPrompt {
                agent_mention: "@智慧",
                body: "研究多奇數位創意有限公司的發展沿革與創辦人的豐功偉業"
            })
        );
    }

    #[test]
    fn parses_chatgpt_agent_prompt_with_ten_character_agent_name() {
        assert_eq!(
            parse_chatgpt_agent_prompt("@一二三四五六七八九十 查資料"),
            Some(ChatGptAgentPrompt {
                agent_mention: "@一二三四五六七八九十",
                body: "查資料"
            })
        );
    }

    #[test]
    fn trims_extra_whitespace_between_chatgpt_agent_and_body() {
        assert_eq!(
            parse_chatgpt_agent_prompt("@智慧 \n\t查資料").unwrap().body,
            "查資料"
        );
    }

    #[test]
    fn rejects_invalid_chatgpt_agent_prompt_shapes() {
        assert_eq!(parse_chatgpt_agent_prompt("智慧 查資料"), None);
        assert_eq!(parse_chatgpt_agent_prompt("@ 查資料"), None);
        assert_eq!(parse_chatgpt_agent_prompt("@智慧"), None);
        assert_eq!(parse_chatgpt_agent_prompt("@智慧   "), None);
        assert_eq!(
            parse_chatgpt_agent_prompt("@一二三四五六七八九十甲 查資料"),
            None
        );
    }

    #[test]
    fn extracts_snapshot_uid_from_common_formats() {
        assert_eq!(
            extract_snapshot_uid(r#"- button "上傳檔案" [uid="1_23"]"#),
            Some("1_23".to_string())
        );
        assert_eq!(
            extract_snapshot_uid(r#"- button "Upload file" uid=42"#),
            Some("42".to_string())
        );
    }

    #[test]
    fn finds_snapshot_uid_with_include_and_exclude_terms() {
        let snapshot = r#"
            - button "加入雲端硬碟檔案" [uid="1_10"]
            - menuitem "上傳檔案. 文件、資料、程式碼檔案" [uid="1_11"]
        "#;
        assert_eq!(
            find_snapshot_uid(snapshot, &["上傳檔案"], &["雲端"]),
            Some("1_11".to_string())
        );
    }

    #[test]
    fn rejects_gemini_image_attachments() {
        let cli = Cli::try_parse_from([
            "ask-bridge",
            "--provider",
            "gemini",
            "--image",
            "token.png",
            "read",
        ])
        .unwrap();
        assert!(validate_provider_feature_support(Provider::Gemini, &cli).is_err());
    }

    #[test]
    fn allows_claude_image_and_file_attachments() {
        let cli = Cli::try_parse_from([
            "ask-bridge",
            "--provider",
            "claude",
            "--image",
            "token.png",
            "--file",
            "token.txt",
            "read",
        ])
        .unwrap();
        assert!(validate_provider_feature_support(Provider::Claude, &cli).is_ok());
    }

    #[test]
    fn allows_gemini_file_attachments() {
        let cli = Cli::try_parse_from([
            "ask-bridge",
            "--provider",
            "gemini",
            "--file",
            "token.txt",
            "read",
        ])
        .unwrap();
        assert!(validate_provider_feature_support(Provider::Gemini, &cli).is_ok());
    }

    #[test]
    fn parses_reasoning_cli_argument() {
        let cli = Cli::try_parse_from([
            "ask-bridge",
            "--provider",
            "chatgpt",
            "--model",
            "GPT-5.6 Sol",
            "--reasoning",
            "high",
            "solve",
        ])
        .unwrap();

        assert_eq!(cli.model.as_deref(), Some("GPT-5.6 Sol"));
        assert_eq!(cli.reasoning.as_deref(), Some("high"));
    }

    #[test]
    fn resolves_chatgpt_model_and_reasoning_independently() {
        let plan =
            resolve_selection_plan(Provider::ChatGpt, Some("GPT-5.6 Sol"), Some("medium")).unwrap();

        assert_eq!(plan.model.as_deref(), Some("GPT-5.6 Sol"));
        assert_eq!(plan.reasoning, Some(ReasoningRequest::ChatGptMedium));
        assert!(!plan.used_legacy_model);
    }

    #[test]
    fn resolves_chatgpt_reasoning_aliases() {
        for (value, expected) in [
            ("auto", ReasoningRequest::ChatGptAuto),
            ("自動", ReasoningRequest::ChatGptAuto),
            ("智慧", ReasoningRequest::ChatGptAuto),
            ("instant", ReasoningRequest::ChatGptInstant),
            ("即時", ReasoningRequest::ChatGptInstant),
            ("medium", ReasoningRequest::ChatGptMedium),
            ("中", ReasoningRequest::ChatGptMedium),
            ("中等", ReasoningRequest::ChatGptMedium),
            ("high", ReasoningRequest::ChatGptHigh),
            ("高", ReasoningRequest::ChatGptHigh),
        ] {
            let plan = resolve_selection_plan(Provider::ChatGpt, None, Some(value)).unwrap();
            assert_eq!(plan.reasoning, Some(expected), "unexpected alias {value}");
        }
    }

    #[test]
    fn converts_legacy_reasoning_like_model_values() {
        let chatgpt = resolve_selection_plan(Provider::ChatGpt, Some("高"), None).unwrap();
        assert_eq!(chatgpt.model, None);
        assert_eq!(chatgpt.reasoning, Some(ReasoningRequest::ChatGptHigh));
        assert!(chatgpt.used_legacy_model);

        let gemini = resolve_selection_plan(Provider::Gemini, Some("延伸思考"), None).unwrap();
        assert_eq!(gemini.model, None);
        assert_eq!(gemini.reasoning, Some(ReasoningRequest::GeminiExtended));
        assert!(gemini.used_legacy_model);
    }

    #[test]
    fn validates_gemini_extended_thinking_combinations() {
        let plan =
            resolve_selection_plan(Provider::Gemini, Some("3.1 Pro"), Some("extended")).unwrap();
        assert_eq!(plan.model.as_deref(), Some("3.1 Pro"));
        assert_eq!(plan.reasoning, Some(ReasoningRequest::GeminiExtended));

        let error = resolve_selection_plan(Provider::Gemini, Some("3.6 Flash"), Some("extended"))
            .unwrap_err();
        assert!(error.contains("incompatible"));
    }

    #[test]
    fn rejects_unsupported_or_ambiguous_reasoning_values() {
        let unsupported =
            resolve_selection_plan(Provider::ChatGpt, None, Some("ultra")).unwrap_err();
        assert!(unsupported.contains("auto, instant, medium, high"));

        let ambiguous =
            resolve_selection_plan(Provider::ChatGpt, Some("高"), Some("high")).unwrap_err();
        assert!(ambiguous.contains("cannot be combined"));
    }

    #[test]
    fn rejects_claude_reasoning_without_changing_model_selection() {
        let error =
            resolve_selection_plan(Provider::Claude, Some("Sonnet"), Some("high")).unwrap_err();
        assert!(error.contains("Claude"));
        assert!(error.contains("--reasoning"));

        let plan = resolve_selection_plan(Provider::Claude, Some("Sonnet"), None).unwrap();
        assert_eq!(plan.model.as_deref(), Some("Sonnet"));
        assert_eq!(plan.reasoning, None);
    }

    #[test]
    fn preserves_claude_model_selector_script() {
        let target = serde_json::to_string("Sonnet").unwrap();
        let script = claude_model_switch_script(&target);

        assert!(script.contains(r#"[data-testid="model-selector-dropdown"]"#));
        assert!(script.contains("model|claude|opus|sonnet|haiku|fable"));
        assert!(script.contains("startsWith(target)"));
        assert!(script.contains(r#"const target = norm("Sonnet");"#));
    }

    #[test]
    fn preserves_provider_baselines_without_reasoning() {
        for provider in [Provider::ChatGpt, Provider::Gemini, Provider::Claude] {
            let plan = resolve_selection_plan(provider, None, None).unwrap();
            assert_eq!(plan, SelectionPlan::default());
        }
    }

    #[test]
    fn finds_linux_google_chrome_command_from_path() {
        let root = make_test_dir("chrome_path");
        let first_dir = root.join("first");
        let second_dir = root.join("second");
        std::fs::create_dir_all(&first_dir).unwrap();
        std::fs::create_dir_all(&second_dir).unwrap();

        let stable_path = first_dir.join("google-chrome-stable");
        let chrome_path = second_dir.join("google-chrome");
        std::fs::write(&stable_path, "").unwrap();
        std::fs::write(&chrome_path, "").unwrap();
        mark_test_file_executable(&stable_path);
        mark_test_file_executable(&chrome_path);

        let path_env = std::env::join_paths([first_dir.as_os_str(), second_dir.as_os_str()])
            .expect("test PATH should be joinable");

        let found = find_linux_chrome_path(Some(path_env.as_os_str()), &[]);

        assert_eq!(found, Some(chrome_path.to_string_lossy().to_string()));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn finds_linux_chrome_from_standard_candidates_when_path_misses() {
        let root = make_test_dir("chrome_candidate");
        std::fs::create_dir_all(&root).unwrap();
        let chrome_path = root.join("google-chrome");
        std::fs::write(&chrome_path, "").unwrap();
        mark_test_file_executable(&chrome_path);

        let chrome_path_str = chrome_path.to_string_lossy().to_string();
        let candidates = [chrome_path_str.as_str()];

        let found = find_linux_chrome_path(None, &candidates);

        assert_eq!(found, Some(chrome_path_str));

        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn linux_chrome_discovery_skips_non_executable_files() {
        let root = make_test_dir("chrome_nonexec_discovery");
        let path_dir = root.join("path");
        let candidate_dir = root.join("candidate");
        std::fs::create_dir_all(&path_dir).unwrap();
        std::fs::create_dir_all(&candidate_dir).unwrap();
        let path_file = path_dir.join("google-chrome");
        let candidate_file = candidate_dir.join("google-chrome");
        std::fs::write(&path_file, "").unwrap();
        std::fs::write(&candidate_file, "").unwrap();
        let path_env = std::env::join_paths([path_dir.as_os_str()]).unwrap();
        let candidate = candidate_file.to_string_lossy().to_string();

        assert_eq!(
            find_linux_chrome_path(Some(path_env.as_os_str()), &[candidate.as_str()]),
            None
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn returns_none_when_linux_chrome_is_missing() {
        assert_eq!(find_linux_chrome_path(None, &[]), None);
    }

    #[test]
    fn matches_profile_argument_with_quotes_and_slashes() {
        let command = r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9223 "--user-data-dir=C:\Users\Will\.config\ask-bridge\chrome-profile""#;
        let profile_path = r"C:/Users/Will/.config/ask-bridge/chrome-profile";

        assert!(command_uses_profile(command, profile_path));
    }

    #[test]
    fn matches_profile_argument_when_value_is_separated_by_space() {
        let command = r#"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9223 --user-data-dir /Users/will/.config/ask-bridge/chrome-profile"#;
        let profile_path = "/Users/will/.config/ask-bridge/chrome-profile";

        assert!(command_uses_profile(command, profile_path));
    }

    #[test]
    fn rejects_different_profile_argument() {
        let command = r#"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --remote-debugging-port=9223 --user-data-dir=/Users/will/.config/other/chrome-profile"#;
        let profile_path = "/Users/will/.config/ask-bridge/chrome-profile";

        assert!(!command_uses_profile(command, profile_path));
    }

    #[test]
    fn rejects_profile_and_marker_prefixes_with_extra_suffixes() {
        let profile_path = r"C:\Users\Will\.config\ask-bridge\chrome-profile";
        let profile_copy =
            r#"chrome.exe --user-data-dir=C:\Users\Will\.config\ask-bridge\chrome-profile-copy"#;
        let marker_copy = "chrome.exe --ask-bridge-instance-copy";

        assert!(!command_uses_profile(profile_copy, profile_path));
        assert!(!command_identifies_ask_chrome(marker_copy, profile_path));
    }

    #[test]
    fn composer_without_account_or_auth_controls_has_logged_in_state() {
        let signals = LoginSignals {
            account: false,
            auth_control: false,
            auth_path: false,
            composer: true,
            stable: true,
        };

        assert_eq!(signals.state(Provider::ChatGpt), LoginState::LoggedIn);
    }

    #[test]
    fn chatgpt_login_signals_wait_for_ambiguous_auth_shell() {
        let script = Provider::ChatGpt.login_signals_js();

        assert!(script.starts_with("async () =>"));
        assert!(script.contains("earliestDecision"));
        assert!(script.contains("stableSince"));
        assert!(script.contains("let stable = false"));
        assert!(script.contains("JSON.stringify(nextSignals)"));
        assert!(script.contains("await new Promise"));
        assert!(script.contains("Date.now() + 5000"));
        assert!(script.contains("return { ...signals, stable }"));
    }

    #[test]
    fn account_control_has_logged_in_state() {
        let signals = LoginSignals {
            account: true,
            auth_control: false,
            auth_path: false,
            composer: true,
            stable: true,
        };

        assert_eq!(signals.state(Provider::ChatGpt), LoginState::LoggedIn);
    }

    #[test]
    fn auth_control_or_auth_path_has_logged_out_state() {
        let visible_auth_control = LoginSignals {
            account: false,
            auth_control: true,
            auth_path: false,
            composer: true,
            stable: true,
        };
        let auth_path = LoginSignals {
            account: false,
            auth_control: false,
            auth_path: true,
            composer: false,
            stable: false,
        };

        assert_eq!(
            visible_auth_control.state(Provider::ChatGpt),
            LoginState::LoggedOut
        );
        assert_eq!(auth_path.state(Provider::ChatGpt), LoginState::LoggedOut);
    }

    #[test]
    fn empty_login_signals_have_unknown_state() {
        let signals = LoginSignals {
            account: false,
            auth_control: false,
            auth_path: false,
            composer: false,
            stable: true,
        };

        assert_eq!(signals.state(Provider::ChatGpt), LoginState::Unknown);
    }

    #[test]
    fn unstable_chatgpt_signals_never_block_or_confirm_login() {
        for signals in [
            LoginSignals {
                account: false,
                auth_control: true,
                auth_path: false,
                composer: true,
                stable: false,
            },
            LoginSignals {
                account: false,
                auth_control: false,
                auth_path: false,
                composer: true,
                stable: false,
            },
        ] {
            assert_eq!(signals.state(Provider::ChatGpt), LoginState::Unknown);
        }
    }

    #[test]
    fn auth_path_overrides_stale_account_control() {
        let signals = LoginSignals {
            account: true,
            auth_control: false,
            auth_path: true,
            composer: true,
            stable: false,
        };

        assert_eq!(signals.state(Provider::ChatGpt), LoginState::LoggedOut);
    }

    #[test]
    fn gemini_composer_without_account_remains_unknown() {
        let signals = LoginSignals {
            account: false,
            auth_control: false,
            auth_path: false,
            composer: true,
            stable: true,
        };

        assert_eq!(signals.state(Provider::Gemini), LoginState::Unknown);
    }

    #[test]
    fn gemini_hidden_account_marker_is_logged_in() {
        let signals = LoginSignals {
            account: true, // script can detect marker even if hidden
            auth_control: false,
            auth_path: false,
            composer: true,
            stable: true,
        };

        assert_eq!(signals.state(Provider::Gemini), LoginState::LoggedIn);
    }

    #[test]
    fn claude_composer_without_account_remains_unknown() {
        let signals = LoginSignals {
            account: false,
            auth_control: false,
            auth_path: false,
            composer: true,
            stable: true,
        };

        assert_eq!(signals.state(Provider::Claude), LoginState::Unknown);
    }

    #[test]
    fn prefers_logged_in_provider_page_over_selected_page() {
        let pages = [
            PageLoginState {
                id: 2,
                selected: true,
                login_state: LoginState::LoggedOut,
            },
            PageLoginState {
                id: 7,
                selected: false,
                login_state: LoginState::LoggedIn,
            },
        ];

        assert_eq!(preferred_provider_page_id(&pages), Some(7));
    }

    #[test]
    fn falls_back_to_selected_provider_page_when_none_are_logged_in() {
        let pages = [
            PageLoginState {
                id: 2,
                selected: false,
                login_state: LoginState::Unknown,
            },
            PageLoginState {
                id: 7,
                selected: true,
                login_state: LoginState::LoggedOut,
            },
        ];

        assert_eq!(preferred_provider_page_id(&pages), Some(7));
    }

    #[test]
    fn identifies_the_only_new_page_without_reusing_existing_provider_tabs() {
        let before = [
            Page {
                id: 1,
                url: Some("https://chatgpt.com/c/existing".to_string()),
                selected: true,
            },
            Page {
                id: 2,
                url: Some("https://example.com/".to_string()),
                selected: false,
            },
        ];
        let after = [
            Page {
                id: 1,
                url: Some("https://chatgpt.com/c/existing".to_string()),
                selected: false,
            },
            Page {
                id: 2,
                url: Some("https://example.com/".to_string()),
                selected: false,
            },
            Page {
                id: 7,
                url: Some("https://chatgpt.com/".to_string()),
                selected: true,
            },
        ];

        assert_eq!(unique_new_page_id(&before, &after), Ok(7));
    }

    #[test]
    fn refuses_to_guess_when_new_page_identity_is_ambiguous() {
        let before = [Page {
            id: 1,
            url: Some("https://chatgpt.com/c/existing".to_string()),
            selected: true,
        }];
        let after = [
            Page {
                id: 1,
                url: Some("https://chatgpt.com/c/existing".to_string()),
                selected: false,
            },
            Page {
                id: 7,
                url: Some("https://chatgpt.com/".to_string()),
                selected: true,
            },
            Page {
                id: 8,
                url: Some("https://example.com/popup".to_string()),
                selected: false,
            },
        ];

        let error = unique_new_page_id(&before, &after).unwrap_err();
        assert!(error.contains("Could not uniquely identify"));
        assert!(error.contains("[7, 8]"));
    }

    #[test]
    fn refuses_to_reuse_an_existing_page_when_no_new_page_appears() {
        let before = [Page {
            id: 1,
            url: Some("https://chatgpt.com/c/existing".to_string()),
            selected: true,
        }];
        let after = [Page {
            id: 1,
            url: Some("https://chatgpt.com/c/existing".to_string()),
            selected: true,
        }];

        let error = unique_new_page_id(&before, &after).unwrap_err();
        assert!(error.contains("Could not identify the newly opened tab"));
    }

    #[test]
    fn marker_identifies_ask_bridge_chrome_without_profile_argument() {
        let command = r#"chrome.exe --type=browser --ask-bridge-instance"#;

        assert!(command_identifies_ask_chrome(
            command,
            r"C:\Users\Will\.config\ask-bridge\chrome-profile"
        ));
    }

    #[test]
    fn parses_legacy_and_json_chrome_process_records() {
        assert_eq!(
            parse_chrome_process_record("15864\r\n"),
            Some(ChromeProcessRecord {
                pid: 15864,
                browser_id: None,
            })
        );
        assert_eq!(
            parse_chrome_process_record(r#"{"pid":20728,"browser_id":"browser-123"}"#),
            Some(ChromeProcessRecord {
                pid: 20728,
                browser_id: Some("browser-123".to_string()),
            })
        );
    }

    #[test]
    fn extracts_browser_id_from_cdp_version_response() {
        let body = r#"{"Browser":"Chrome/149","webSocketDebuggerUrl":"ws://127.0.0.1:9223/devtools/browser/browser-123"}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length:{}\r\nContent-Type:application/json\r\n\r\n{}",
            body.len(),
            body
        );

        assert_eq!(
            browser_id_from_version_response(&response),
            Some("browser-123".to_string())
        );
        assert!(http_response_is_complete(response.as_bytes()));
        assert!(!http_response_is_complete(
            &response.as_bytes()[..response.len() - 1]
        ));

        let non_success = response.replacen("200 OK", "404 Not Found", 1);
        assert_eq!(browser_id_from_version_response(&non_success), None);
        assert_eq!(browser_id_from_version_response(body), None);

        let foreign_body = body.replace("127.0.0.1:9223", "example.com:9223");
        let foreign_response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length:{}\r\n\r\n{}",
            foreign_body.len(),
            foreign_body
        );
        assert_eq!(browser_id_from_version_response(&foreign_response), None);

        let overflowing_length = format!(
            "HTTP/1.1 200 OK\r\nContent-Length:{}\r\n\r\n{{}}",
            usize::MAX
        );
        assert!(!http_response_is_complete(overflowing_length.as_bytes()));
    }

    #[test]
    fn build_chrome_process_record_prefers_unique_listener_pid() {
        let listeners = vec!["20728".to_string()];
        assert_eq!(
            build_chrome_process_record(&listeners, Some("browser-123")),
            Some(ChromeProcessRecord {
                pid: 20728,
                browser_id: Some("browser-123".to_string()),
            })
        );
    }

    #[test]
    fn build_chrome_process_record_requires_unambiguous_identity() {
        assert_eq!(
            build_chrome_process_record(
                &["20728".to_string(), "30000".to_string()],
                Some("browser-123")
            ),
            None
        );
        assert_eq!(
            build_chrome_process_record(&["20728".to_string()], None),
            None
        );
    }

    #[test]
    fn chrome_record_matches_current_checks_browser_identity_and_scope() {
        let record = ChromeProcessRecord {
            pid: 20728,
            browser_id: Some("browser-123".to_string()),
        };
        let single = vec!["20728".to_string()];
        let multiple = vec!["20728".to_string(), "30000".to_string()];

        assert!(chrome_record_matches_current(
            Some(&record),
            Some("browser-123"),
            &single
        ));
        assert!(!chrome_record_matches_current(
            Some(&record),
            Some("browser-456"),
            &single
        ));
        assert!(!chrome_record_matches_current(
            Some(&record),
            Some("browser-123"),
            &multiple
        ));
    }

    #[test]
    fn force_close_targets_require_the_same_browser_and_owner_identity() {
        let initial = ChromeDebugSnapshot {
            listener_pids: vec!["20728".to_string()],
            record: None,
            browser_id: Some("browser-original".to_string()),
            ask_pids: vec!["18000".to_string()],
        };
        let same = ChromeDebugSnapshot {
            listener_pids: vec!["20728".to_string()],
            record: None,
            browser_id: Some("browser-original".to_string()),
            ask_pids: vec!["18000".to_string()],
        };
        assert_eq!(
            validated_force_kill_pids(&initial, &same),
            Some(vec!["18000".to_string()])
        );

        // The original numeric PID was reused by an unrelated process after
        // graceful close. Re-inspection can no longer prove it as the owner,
        // so no force-kill target may be returned.
        let reused = ChromeDebugSnapshot {
            listener_pids: vec!["20728".to_string()],
            record: None,
            browser_id: Some("browser-original".to_string()),
            ask_pids: Vec::new(),
        };
        assert_eq!(validated_force_kill_pids(&initial, &reused), None);

        // A new browser instance on the same port is also not the one whose
        // graceful shutdown we initiated.
        let replacement_browser = ChromeDebugSnapshot {
            listener_pids: vec!["20728".to_string()],
            record: None,
            browser_id: Some("browser-replacement".to_string()),
            ask_pids: vec!["18000".to_string()],
        };
        assert_eq!(
            validated_force_kill_pids(&initial, &replacement_browser),
            None
        );

        assert!(ask_chrome_pids_are_gone_with(
            &initial.ask_pids,
            "/tmp/profile",
            |_| Some("unrelated --process".to_string()),
            |_| Some(true),
        ));
        assert!(!ask_chrome_pids_are_gone_with(
            &initial.ask_pids,
            "/tmp/profile",
            |_| Some("chrome --remote-debugging-port=9223 --ask-bridge-instance".to_string()),
            |_| Some(true),
        ));
        assert!(!ask_chrome_pids_are_gone_with(
            &initial.ask_pids,
            "/tmp/profile",
            |_| None,
            |_| Some(true),
        ));
        assert!(!ask_chrome_pids_are_gone_with(
            &initial.ask_pids,
            "/tmp/profile",
            |_| None,
            |_| None,
        ));
        assert!(ask_chrome_pids_are_gone_with(
            &initial.ask_pids,
            "/tmp/profile",
            |_| None,
            |_| Some(false),
        ));
    }

    #[test]
    fn force_kill_validation_handles_a_hung_browser_without_cdp_identity() {
        let snapshot_with =
            |browser_id: Option<&str>, ask_pids: Vec<&str>, listeners: Vec<&str>| {
                ChromeDebugSnapshot {
                    listener_pids: listeners.into_iter().map(str::to_string).collect(),
                    record: None,
                    browser_id: browser_id.map(str::to_string),
                    ask_pids: ask_pids.into_iter().map(str::to_string).collect(),
                }
            };

        // A hung browser never answered CDP: no UUID in the pre-TERM snapshot.
        // The ask/listener pid sets were proven via profile/marker command
        // lines, so force-kill must still proceed on unchanged sets.
        let initial_no_id = snapshot_with(None, vec!["18000"], vec!["20728"]);
        let current_no_id = snapshot_with(None, vec!["18000"], vec!["20728"]);
        assert_eq!(
            validated_force_kill_pids(&initial_no_id, &current_no_id),
            Some(vec!["18000".to_string()])
        );

        // CDP died between the snapshot and re-inspection (browser dying/hung):
        // a missing current UUID must not block the kill either.
        let initial_with_id = snapshot_with(Some("browser-original"), vec!["18000"], vec!["20728"]);
        let current_lost_id = snapshot_with(None, vec!["18000"], vec!["20728"]);
        assert_eq!(
            validated_force_kill_pids(&initial_with_id, &current_lost_id),
            Some(vec!["18000".to_string()])
        );

        // When BOTH snapshots carry a UUID, a mismatch still refuses.
        let current_other_id =
            snapshot_with(Some("browser-replacement"), vec!["18000"], vec!["20728"]);
        assert_eq!(
            validated_force_kill_pids(&initial_with_id, &current_other_id),
            None
        );

        // A different NON-EMPTY ask set is not the owner we TERMed (only the
        // ask-set comparison trips here: listeners unchanged, scope single).
        let current_other_ask = snapshot_with(None, vec!["19999"], vec!["20728"]);
        assert_eq!(
            validated_force_kill_pids(&initial_no_id, &current_other_ask),
            None
        );

        // A different single listener is not the one we snapshotted (only the
        // listener-set comparison trips: scope single, ask set unchanged).
        let current_other_listener = snapshot_with(None, vec!["18000"], vec!["30000"]);
        assert_eq!(
            validated_force_kill_pids(&initial_no_id, &current_other_listener),
            None
        );

        // Two listeners make the kill scope ambiguous even when the sets are
        // UNCHANGED (only the ambiguity check trips).
        let initial_two_listeners = snapshot_with(None, vec!["18000"], vec!["20728", "30000"]);
        let current_two_listeners = snapshot_with(None, vec!["18000"], vec!["20728", "30000"]);
        assert_eq!(
            validated_force_kill_pids(&initial_two_listeners, &current_two_listeners),
            None
        );
    }

    #[test]
    fn empty_revalidation_snapshot_means_browser_gone_not_identity_failure() {
        let gone = ChromeDebugSnapshot {
            listener_pids: Vec::new(),
            record: None,
            browser_id: None,
            ask_pids: Vec::new(),
        };
        // The browser finished dying just after the last port poll: close
        // succeeded and must not be reported as an identity failure.
        assert!(snapshot_shows_browser_gone(&gone));

        // Any surviving listener or ask owner is NOT "gone" — those still go
        // through identity validation.
        let listener_left = ChromeDebugSnapshot {
            listener_pids: vec!["20728".to_string()],
            record: None,
            browser_id: None,
            ask_pids: Vec::new(),
        };
        assert!(!snapshot_shows_browser_gone(&listener_left));

        let ask_left = ChromeDebugSnapshot {
            listener_pids: Vec::new(),
            record: None,
            browser_id: None,
            ask_pids: vec!["18000".to_string()],
        };
        assert!(!snapshot_shows_browser_gone(&ask_left));
    }

    #[test]
    fn empty_process_command_requires_proven_process_exit() {
        let pids = vec!["18000".to_string()];

        assert!(!ask_chrome_pids_are_gone_with(
            &pids,
            "/tmp/profile",
            |_| Some(String::new()),
            |_| Some(true),
        ));
        assert!(!ask_chrome_pids_are_gone_with(
            &pids,
            "/tmp/profile",
            |_| Some(String::new()),
            |_| None,
        ));
        assert!(ask_chrome_pids_are_gone_with(
            &pids,
            "/tmp/profile",
            |_| Some(String::new()),
            |_| Some(false),
        ));
    }

    #[test]
    fn windows_netstat_parser_matches_exact_listening_port() {
        let output = concat!(
            "  TCP    127.0.0.1:9223    0.0.0.0:0    LISTENING    20728\r\n",
            "  TCP    127.0.0.1:92230   0.0.0.0:0    LISTENING    30000\r\n",
            "  TCP    [::1]:9223        [::]:0       LISTENING    20728\r\n",
            "  TCP    127.0.0.1:9223    127.0.0.1:50000 ESTABLISHED 40000\r\n",
            "  UDP    127.0.0.1:9223    *:*                       50000\r\n"
        );

        assert_eq!(
            parse_windows_netstat_listener_pids(output, 9223),
            vec!["20728".to_string()]
        );
    }

    #[test]
    fn finds_ask_owner_pids_and_deduplicates_results() {
        let listeners = vec![
            "30000".to_string(),
            "20728".to_string(),
            "20728".to_string(),
        ];
        let commands = std::collections::HashMap::from([
            ("20728", "chrome.exe --type=utility"),
            ("30000", "chrome.exe --type=gpu-process"),
            (
                "18000",
                "chrome.exe --remote-debugging-port=9223 --ask-bridge-instance",
            ),
            (
                "15000",
                "chrome.exe --user-data-dir=C:\\Users\\Chris\\.config\\ask-bridge\\chrome-profile",
            ),
        ]);
        let parents = std::collections::HashMap::from([
            ("20728", "18000"),
            ("30000", "18000"),
            ("18000", "1"),
            ("15000", "1"),
        ]);

        let ask_pids = find_ask_chrome_owner_pids_with(
            &listeners,
            r"C:\Users\Chris\.config\ask-bridge\chrome-profile",
            |pid| commands.get(pid).map(|command| (*command).to_string()),
            |pid| parents.get(pid).map(|parent| (*parent).to_string()),
        );

        assert_eq!(ask_pids, vec!["18000".to_string()]);
    }

    #[test]
    fn parses_wmic_value_after_blank_lines() {
        let output = "CommandLine\r\n\r\n  chrome.exe --remote-debugging-port=9223  \r\n\r\n";

        assert_eq!(
            parse_wmic_column_value(output),
            Some("chrome.exe --remote-debugging-port=9223".to_string())
        );
    }

    #[test]
    fn finds_ask_chrome_owner_in_parent_process_chain() {
        let commands = std::collections::HashMap::from([
            ("100", "chrome.exe --type=utility"),
            (
                "50",
                "chrome.exe --remote-debugging-port=9223 --ask-bridge-instance",
            ),
        ]);
        let parents = std::collections::HashMap::from([("100", "50"), ("50", "1")]);

        let owner = find_ask_chrome_owner_pid_with(
            "100",
            "/tmp/ask-bridge/chrome-profile",
            |pid| commands.get(pid).map(|command| (*command).to_string()),
            |pid| parents.get(pid).map(|parent| (*parent).to_string()),
        );

        assert_eq!(owner, Some("50".to_string()));
    }

    #[test]
    fn rejects_process_chain_without_profile_or_marker() {
        let commands = std::collections::HashMap::from([
            ("100", "chrome.exe --type=utility"),
            ("50", "chrome.exe --remote-debugging-port=9223"),
        ]);
        let parents = std::collections::HashMap::from([("100", "50"), ("50", "1")]);

        let owner = find_ask_chrome_owner_pid_with(
            "100",
            "/tmp/ask-bridge/chrome-profile",
            |pid| commands.get(pid).map(|command| (*command).to_string()),
            |pid| parents.get(pid).map(|parent| (*parent).to_string()),
        );

        assert_eq!(owner, None);
    }

    /// Smallest valid PNG, standing in for an image the page generated.
    const STUB_PNG_DATA_URL: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

    fn stub_generated_images(count: usize) -> Vec<serde_json::Value> {
        (0..count)
            .map(|index| {
                serde_json::json!({
                    "index": index,
                    "src": format!("https://example.invalid/generated-{}.png", index),
                    "alt": "",
                    "dataUrl": STUB_PNG_DATA_URL,
                })
            })
            .collect()
    }

    #[test]
    fn explicit_image_output_that_cannot_be_written_produces_no_artifact() {
        // A caller that passed --image-output is going to read that path next.
        // Prove the save really fails and really leaves nothing behind, so the
        // exit-code contract below is guarding a genuinely missing file rather
        // than a cosmetic error message.
        let dir = tempfile::tempdir().unwrap();
        // A regular file where a parent directory would have to be: no user,
        // root included, can create a directory underneath it.
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, b"regular file").unwrap();
        let requested = blocker.join("shot.png");

        let error = save_generated_images(&stub_generated_images(1), requested.to_str())
            .expect_err("an unwritable --image-output destination must not report success");

        assert!(
            error.contains("not-a-directory"),
            "error should name the destination that failed: {error}"
        );
        assert!(
            !requested.exists(),
            "no artifact should exist at the requested path"
        );
    }

    #[test]
    fn image_download_failure_is_fatal_only_when_the_caller_named_the_path() {
        // --image-output is a promise of a file at a caller-chosen path.
        // Reporting success while that file is missing makes automation read a
        // stale or absent artifact as the answer, so the failure must be fatal.
        assert_eq!(
            image_download_failure_exit_code(Some("/tmp/ask-bridge-test/shot.png")),
            Some(1)
        );
        assert_eq!(image_download_failure_exit_code(Some("out/")), Some(1));
        // 1 is the code every other fatal path in this CLI uses. Anything in
        // the 124..=125 range would collide with `timeout(1)`'s convention,
        // which callers legitimately retry as a flake.
        assert_eq!(image_download_failure_exit_code(Some("x.png")), Some(1));

        // Without the flag the download is a best-effort extra into target/;
        // the answer itself already printed, so the run is still a success.
        // This is upstream behaviour — do not "fix" it into a hard failure.
        assert_eq!(image_download_failure_exit_code(None), None);
    }

    #[test]
    fn writable_explicit_image_output_still_saves_every_image() {
        // Positive control: the fatal path above must not be reachable when the
        // destination works, otherwise the fix would break normal image runs.
        let dir = tempfile::tempdir().unwrap();
        let requested = dir.path().join("nested").join("shot.png");

        save_generated_images(&stub_generated_images(2), requested.to_str())
            .expect("a writable destination should save every image");

        let saved: Vec<_> = std::fs::read_dir(dir.path().join("nested"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert!(saved.contains(&"shot_1.png".to_string()), "{saved:?}");
        assert!(saved.contains(&"shot_2.png".to_string()), "{saved:?}");
    }

    /// An explicit `--image-output` that produces zero files must not exit 0.
    ///
    /// Every one of these shapes used to return `Ok(())` after writing nothing:
    /// an entry without `dataUrl`, a `dataUrl` that is not `<header>,<payload>`,
    /// and a batch where all of them are like that. The caller then read a
    /// missing file, or -- the case that makes this more than cosmetic -- the
    /// file the *previous* run left at the same path, while the exit status said
    /// the artifact was there.
    #[test]
    fn explicit_image_output_with_nothing_to_write_is_a_failure() {
        for (images, why) in [
            (vec![], "an empty batch"),
            (
                vec![serde_json::json!({"index": 0, "src": "x"})],
                "no dataUrl",
            ),
            (
                vec![serde_json::json!({"index": 0, "dataUrl": "data:image/png;base64"})],
                "no comma, so no payload",
            ),
            (
                vec![
                    serde_json::json!({"index": 0, "dataUrl": "data:image/png;base64"}),
                    serde_json::json!({"index": 1, "src": "y"}),
                ],
                "every entry unusable",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let requested = dir.path().join("shot.png");
            // The stale artifact a caller would otherwise read back as this
            // run's answer.
            std::fs::write(&requested, b"stale from the previous run").unwrap();

            let error = save_generated_images(&images, requested.to_str())
                .expect_err(&format!("reported success having written nothing ({why})"));
            assert!(
                error.contains("shot.png"),
                "the failure must name the promised path ({why}): {error}"
            );
            assert_eq!(
                std::fs::read(&requested).unwrap(),
                b"stale from the previous run",
                "({why}) the stale file was rewritten rather than left for the \
                 nonzero exit to disown"
            );
        }
    }

    /// `ask-bridge screenshot` has the same contract as `--image-output` above,
    /// and used to break it the same way: a response with no image item, or
    /// with image items that are not decodable base64, printed a line to stderr
    /// and returned `Ok`. The caller checks the status and reads
    /// `target/screenshot.png`, so exit 0 hands it the file the *previous* run
    /// left there.
    ///
    /// The stderr line was its own problem: it dumped the whole tool response,
    /// which for `take_screenshot` is the base64 of a logged-in page.
    #[test]
    fn a_screenshot_response_with_no_usable_image_is_a_failure() {
        // Stands in for the page contents a real response carries.
        let secret = "session-cookie-abc123";

        for (res, why) in [
            (
                serde_json::json!({"content": [{"type": "text", "text": secret}]}),
                "no image item at all",
            ),
            (
                serde_json::json!({"content": [
                    {"type": "image", "data": "not base64 %%%", "mimeType": "image/png"},
                    {"type": "text", "text": secret},
                ]}),
                "the only image item is not base64",
            ),
            (serde_json::json!({}), "no content array"),
        ] {
            let error = screenshot_png_bytes(&res)
                .expect_err(&format!("reported success with no image ({why})"));
            assert!(
                error.contains("take_screenshot"),
                "the failure must name the step that produced nothing ({why}): {error}"
            );
            assert!(
                !error.contains(secret),
                "the tool response was echoed back out ({why}): {error}"
            );
        }
    }

    /// Positive control for the above, and the shape the fix could most easily
    /// have broken: the first decodable image is still what gets written, even
    /// when an undecodable item comes first.
    #[test]
    fn a_decodable_screenshot_is_still_returned() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let png = b"\x89PNG\r\n\x1a\nnot really a png";
        let res = serde_json::json!({"content": [
            {"type": "text", "text": "Took a screenshot."},
            {"type": "image", "data": "%%%", "mimeType": "image/png"},
            {"type": "image", "data": STANDARD.encode(png), "mimeType": "image/png"},
        ]});

        assert_eq!(screenshot_png_bytes(&res).unwrap(), png);
    }

    /// Lexical, for the same reason as `a_refused_session_aborts_the_run`: the
    /// behaviour above is covered by the two tests before it, but what `main`
    /// does with the `Err` is a single `?` inside a 700-line `fn main` that no
    /// offline end-to-end run can reach (the arm needs a live chrome-devtools
    /// MCP session first). Swallowing it -- `unwrap_or_default()`, or the
    /// original `if !saved { eprintln!(..) }` -- puts exit 0 straight back.
    ///
    /// The decode is only half the promise. The command exists to leave a file
    /// behind, so a swallowed *write* -- `let _ = std::fs::write(..)` -- exits 0
    /// over a missing or stale `target/screenshot.png` just as squarely, and the
    /// caller cannot tell the two apart.
    #[test]
    fn the_screenshot_arm_propagates_the_failure_instead_of_printing_it() {
        // Split literals keep this test from matching its own source text.
        let source = include_str!("main.rs");
        let arm = source
            .split_once(concat!("Commands::", "Screenshot => {"))
            .expect("main should route `screenshot` through its own arm")
            .1;
        let mut depth = 0usize;
        let mut end = None;
        for (offset, character) in arm.char_indices() {
            match character {
                '{' => depth += 1,
                '}' if depth == 0 => {
                    end = Some(offset);
                    break;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        let arm = &arm[..end.expect("the screenshot arm must be brace-balanced")];
        // Whole comment lines are dropped, exactly as
        // `no_updater_path_pipes_a_download_into_a_shell` does it and for the
        // same reason: the arm has to be allowed to *describe* what it does,
        // and a comment quoting the `?` would otherwise satisfy every
        // assertion below while the line beside it swallows the error.
        let arm: String = arm
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            arm.contains(concat!("screenshot_png_bytes(&res)", "?")),
            "the screenshot arm no longer lets a missing image end the run:\n{arm}"
        );
        assert!(
            arm.contains(concat!(
                "std::fs::write(\"target/screenshot.png\", bytes)",
                "?"
            )),
            "the screenshot arm no longer lets a failed write end the run, so it \
             can exit 0 over the file the previous run left:\n{arm}"
        );
        // The one print the arm may still make is the tab-preparation failure,
        // which aborts. What it may not do is format the tool response: that is
        // how the base64 of a logged-in page got into stderr, and both spellings
        // of the dump go through a debug placeholder.
        assert!(
            !arm.contains("{:?}") && !arm.contains("{res"),
            "the screenshot arm formats the tool response back out instead of \
             failing on it:\n{arm}"
        );
    }

    /// Under an explicit destination the batch is all-or-nothing: one unusable
    /// entry must not leave a partial, gap-numbered set at the path.
    #[test]
    fn explicit_image_output_writes_the_whole_batch_or_none_of_it() {
        let dir = tempfile::tempdir().unwrap();
        let requested = dir.path().join("out").join("shot.png");
        let mut images = stub_generated_images(3);
        images[1] = serde_json::json!({"index": 1, "src": "no data url here"});

        let error = save_generated_images(&images, requested.to_str())
            .expect_err("a partially decodable batch reported success");

        assert!(
            error.contains("2 of 3"),
            "the failure must say which: {error}"
        );
        assert!(
            !dir.path().join("out").exists(),
            "a rejected batch must not leave files at the promised path"
        );
    }

    /// Anti-tautology, and the upstream behaviour this must not change: with no
    /// `--image-output` the download is a best-effort extra into `target/`, so
    /// an unusable entry is skipped and the run still succeeds.
    ///
    /// Every entry is unusable on purpose. That is the shape the fix could most
    /// easily have broken (it is the one that now fails under an explicit
    /// destination), and it is also the only shape that touches no filesystem at
    /// all — this must not write into the crate's `target/`, and it must not
    /// change the process-wide cwd to avoid doing so, because the test harness
    /// runs these in parallel threads.
    #[test]
    fn best_effort_image_download_still_skips_unusable_entries() {
        let images = vec![
            serde_json::json!({"index": 0, "src": "no data url here"}),
            serde_json::json!({"index": 1, "dataUrl": "data:image/png;base64"}),
        ];

        assert_eq!(
            save_generated_images(&images, None),
            Ok(()),
            "best-effort mode must not fail the run"
        );
    }

    /// Two runs must not interleave inside the clipboard transaction.
    ///
    /// The OS lock belongs to the open file handle, so a second `open` in this
    /// process conflicts with the first exactly as another process would. That
    /// makes the property testable without spawning anything on either Unix or
    /// Windows, and it is the property that matters: before this, two runs
    /// traded sentinels -- B captured A's sentinel as "the original" and
    /// restored it over the user's clipboard, while A's poll accepted B's
    /// content as its own answer.
    #[test]
    fn the_clipboard_transaction_is_exclusive_across_processes() {
        let dir = tempfile::tempdir().unwrap();

        let held = lock_clipboard_in(dir.path(), Duration::from_millis(50))
            .expect("an uncontended clipboard lock should be available");

        let contended = lock_clipboard_in(dir.path(), Duration::from_millis(100))
            .expect_err("a second holder was let into the clipboard transaction");
        assert!(
            contended.contains("held the clipboard"),
            "the refusal should say what it waited for: {contended}"
        );

        // The OS drops it when the file handle closes -- that is the whole
        // reason this is a file lock and not a PID file, so prove it rather
        // than assert it in a comment.
        drop(held);
        lock_clipboard_in(dir.path(), Duration::from_millis(50))
            .expect("the lock should be free once the holder's descriptor closes");
    }

    fn symlink_swap_was_rejected_at_expected_stage(error: &str, windows: bool) -> bool {
        if windows {
            error.contains("not a regular file")
        } else {
            error.contains("Failed to open") || error.contains("not a regular file")
        }
    }

    #[cfg(any(unix, target_os = "windows"))]
    #[test]
    fn clipboard_lock_rejects_a_leaf_symlink_swapped_in_after_inspection() {
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join(CLIPBOARD_LOCK_NAME);
        let target = dir.path().join("outside-lock-target");
        std::fs::write(&lock_path, b"ordinary lock file").unwrap();
        std::fs::write(&target, b"must not become the lock").unwrap();

        let error = lock_clipboard_in_with_before_open(
            dir.path(),
            Duration::from_millis(0),
            |inspected_path| {
                std::fs::remove_file(inspected_path)
                    .map_err(|error| format!("failed to swap inspected lock: {error}"))?;
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, inspected_path)
                    .map_err(|error| format!("failed to install test symlink: {error}"))?;
                #[cfg(target_os = "windows")]
                std::os::windows::fs::symlink_file(&target, inspected_path)
                    .map_err(|error| format!("failed to install test symlink: {error}"))?;
                Ok(())
            },
        )
        .expect_err("the post-inspection leaf symlink was followed and locked");

        assert!(
            symlink_swap_was_rejected_at_expected_stage(&error, cfg!(target_os = "windows")),
            "the swapped leaf was refused for an unrelated reason: {error}"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"must not become the lock",
            "the rejected symlink target was modified"
        );
    }

    #[test]
    fn windows_symlink_race_contract_requires_handle_metadata_rejection() {
        assert!(symlink_swap_was_rejected_at_expected_stage(
            "Clipboard lock is not a regular file",
            true
        ));
        assert!(
            !symlink_swap_was_rejected_at_expected_stage("Failed to open clipboard lock", true),
            "a Windows open failure does not prove the opened reparse-point handle was inspected"
        );
    }

    /// The lock is not just *taken* -- it is *held* until the transaction ends.
    ///
    /// The OS lock belongs to the open file handle, so a second `open` + lock
    /// from inside the transaction conflicts exactly as a second process would
    /// (`the_clipboard_transaction_is_exclusive_across_processes` above proves
    /// that equivalence). Probing from inside every injected step is what tells
    /// a guard that lives for the transaction apart from one that is dropped on
    /// the line that takes it: `let _ = lock_clipboard_in(..)` releases the lock
    /// immediately, and leaves the call sitting there for any source-level check
    /// to find.
    #[test]
    fn the_clipboard_lock_is_held_for_the_whole_transaction() {
        use std::cell::RefCell;

        let dir = tempfile::tempdir().unwrap();
        let steps: RefCell<Vec<&'static str>> = RefCell::new(Vec::new());
        let free_at: RefCell<Vec<&'static str>> = RefCell::new(Vec::new());
        let probe = |step: &'static str| {
            steps.borrow_mut().push(step);
            if lock_clipboard_in(dir.path(), Duration::from_millis(10)).is_ok() {
                free_at.borrow_mut().push(step);
            }
        };

        let clipboard = RefCell::new(String::from("what the user had copied"));
        let mut read = || -> Result<String, String> {
            probe("read");
            Ok(clipboard.borrow().clone())
        };
        let mut write = |content: &str| -> Result<(), String> {
            probe("write");
            *clipboard.borrow_mut() = content.to_string();
            Ok(())
        };
        let mut click = || -> Result<(), String> {
            probe("click");
            // The browser answering the click is what lands the response on the
            // clipboard.
            *clipboard.borrow_mut() = String::from("the provider's answer");
            Ok(())
        };

        let content = copy_latest_markdown_via_clipboard_with(
            &mut read,
            &mut write,
            &mut click,
            dir.path(),
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .expect("the faked transaction should have run to completion");

        assert_eq!(content, "the provider's answer");
        let observed = steps.borrow().clone();
        // capture the original, stamp the sentinel, click, poll, restore.
        assert_eq!(
            observed,
            vec!["read", "write", "click", "read", "write"],
            "the fake did not drive the whole five-step transaction, so the \
             probes below prove nothing about its middle"
        );

        let free_at = free_at.borrow().clone();
        assert!(
            free_at.is_empty(),
            "a second run could have entered the clipboard transaction during \
             its {free_at:?} step(s). The lock has to outlive the transaction, \
             not just the line that takes it: while it is loose, two runs trade \
             sentinels -- B captures A's sentinel as `the original` and restores \
             it over the user's clipboard, and A's poll accepts B's answer as A's."
        );

        // ...and it must be gone once the transaction returns, or the next run
        // queues behind a lock nobody holds.
        lock_clipboard_in(dir.path(), Duration::from_millis(10))
            .expect("the transaction must release the clipboard when it returns");
    }

    /// The gaps *between* the steps, which the probes above cannot see.
    ///
    /// Each injected step samples the lock from inside itself, so any
    /// implementation that holds the lock while a step runs looks identical to
    /// one that holds it throughout. Per-step locking -- five separate
    /// `let _g = lock_clipboard_in(..)?` scopes, one per step -- therefore
    /// passes the test above while re-opening M2 completely: the four gaps
    /// between the steps are exactly where a second run slips in, captures this
    /// run's sentinel as "the original", and restores it over the user's
    /// clipboard. That mutation was measured passing the whole suite.
    ///
    /// A concurrent watcher is the only thing that can observe those gaps, so
    /// this test runs one. It is armed by the first step and disarmed by the
    /// last, which bounds it to the span where the lock must be continuously
    /// held and keeps the before/after windows -- where the lock legitimately
    /// is free -- out of the sample.
    #[test]
    fn the_clipboard_lock_is_held_continuously_not_re_taken_per_step() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let armed = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let free_samples = Arc::new(AtomicUsize::new(0));

        let watcher = {
            let (dir_path, armed, finished, free_samples) = (
                dir.path().to_path_buf(),
                Arc::clone(&armed),
                Arc::clone(&finished),
                Arc::clone(&free_samples),
            );
            std::thread::spawn(move || {
                while !finished.load(Ordering::SeqCst) {
                    if armed.load(Ordering::SeqCst)
                        && lock_clipboard_in(&dir_path, Duration::from_millis(0)).is_ok()
                    {
                        free_samples.fetch_add(1, Ordering::SeqCst);
                    }
                    std::thread::yield_now();
                }
            })
        };

        let clipboard = std::cell::RefCell::new(String::from("the user's own clipboard"));
        let steps = std::cell::Cell::new(0usize);
        // Arm on the first step, disarm on the last: the watched span is
        // step 1 -> step 5, which contains all four gaps and neither end window.
        let mark = |armed: &AtomicBool| {
            let n = steps.get() + 1;
            steps.set(n);
            if n == 1 {
                armed.store(true, Ordering::SeqCst);
            }
            if n == 5 {
                armed.store(false, Ordering::SeqCst);
            }
            // Give the watcher a real chance to run inside every gap.
            std::thread::sleep(Duration::from_millis(2));
        };

        let mut read = || -> Result<String, String> {
            mark(&armed);
            Ok(clipboard.borrow().clone())
        };
        let mut write = |content: &str| -> Result<(), String> {
            mark(&armed);
            *clipboard.borrow_mut() = content.to_string();
            Ok(())
        };
        let mut click = || -> Result<(), String> {
            mark(&armed);
            *clipboard.borrow_mut() = String::from("the provider's answer");
            Ok(())
        };

        let content = copy_latest_markdown_via_clipboard_with(
            &mut read,
            &mut write,
            &mut click,
            dir.path(),
            Duration::from_millis(1),
            Duration::from_millis(1),
        )
        .expect("the faked transaction should have run to completion");

        finished.store(true, Ordering::SeqCst);
        watcher.join().expect("the watcher thread should not panic");

        assert_eq!(content, "the provider's answer");
        assert_eq!(
            steps.get(),
            5,
            "the fake did not drive all five steps, so the watcher sampled the \
             wrong span"
        );
        assert_eq!(
            free_samples.load(Ordering::SeqCst),
            0,
            "a concurrent run acquired the clipboard lock {} time(s) while this \
             transaction was mid-flight. The lock has to be held ACROSS the \
             steps, not re-taken for each one: the invariant is about the \
             clipboard's contents between steps, which is where the other run \
             swaps in its own sentinel.",
            free_samples.load(Ordering::SeqCst)
        );
    }

    /// Structural, and now the junior partner of the behavioural test above: a
    /// lock taken *after* the original clipboard is captured shows up there as a
    /// free probe on the first `read`. This stays because it is the cheap
    /// tripwire for a rebase that drops the call altogether, and because it
    /// names the ordering directly.
    #[test]
    fn the_clipboard_transaction_takes_the_lock_before_reading_the_clipboard() {
        let source = include_str!("main.rs");
        let body = source
            .split_once(concat!("fn copy_latest_markdown_via_clipboard_", "with<"))
            .expect("the clipboard transaction should exist")
            .1
            .split_once("\nfn ")
            .expect("the transaction should be followed by another item")
            .0;

        let lock_at = body
            .find(concat!("lock_clipboard_", "in("))
            .expect("the clipboard transaction reaches pbpaste without taking the lock");
        let first_read = body
            .find("read_clipboard()")
            .expect("the transaction should still read the clipboard");
        assert!(
            lock_at < first_read,
            "the lock must be taken before the original clipboard is captured; \
             capturing first is what let one run record another run's sentinel \
             as the content to restore"
        );
    }

    /// A scan that produced nothing at all is the same promise broken one step
    /// earlier, and it used to return `Ok(())` unconditionally.
    #[test]
    fn a_scan_that_produced_no_images_fails_only_under_an_explicit_destination() {
        let error = zero_images_error(Some("out/shot.png"), "found no generated images")
            .expect("an explicit destination with no images must be a failure");
        assert!(error.contains("out/shot.png"), "{error}");
        assert!(error.contains("found no generated images"), "{error}");

        // Best-effort mode is upstream behaviour and stays a non-event.
        assert_eq!(zero_images_error(None, "found no generated images"), None);
        assert_eq!(zero_images_error(None, "did not return a list"), None);
    }

    /// The skip/fail decision is the caller's, so the decoder has to report the
    /// three cases apart rather than folding them together.
    #[test]
    fn decode_generated_image_separates_unusable_from_corrupt() {
        // Nothing to write: the two shapes a working browser never produces,
        // because the scan JS only pushes entries whose dataUrl already starts
        // with `data:image/`.
        assert_eq!(
            decode_generated_image(&serde_json::json!({"src": "x"})),
            Ok(None)
        );
        assert_eq!(
            decode_generated_image(&serde_json::json!({"dataUrl": "data:image/png;base64"})),
            Ok(None)
        );

        // Present but corrupt is a different answer: it is never skipped, under
        // either destination mode.
        let error = decode_generated_image(
            &serde_json::json!({"dataUrl": "data:image/png;base64,not valid base64!!"}),
        )
        .expect_err("undecodable base64 must not read as 'nothing to write'");
        assert!(error.contains("decode base64"), "{error}");

        // And the ordinary case still decodes, with the extension taken from
        // the header.
        let (ext, bytes) = decode_generated_image(&stub_generated_images(1)[0])
            .expect("a valid data URL should decode")
            .expect("a valid data URL is not 'nothing to write'");
        assert_eq!(ext, "png");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn a_fatal_image_failure_still_writes_the_requested_output_file() {
        // Regression: the default prompt path used to exit on the image
        // failure *before* writing --output, so
        // `ask --output a.md --image-output b.png '...'` produced neither file.
        // --output is its own promise; losing it because a second artifact
        // failed is strictly worse than the bug we set out to fix.
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("answer.md");

        let code = finish_prompt_artifacts(
            "the assistant answer",
            Some(&markdown_output_at(&output)),
            Some(1), // --image-output failed and the run must die
            true,
            false,
        );

        assert_eq!(code, Some(1), "the image failure must still be fatal");
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            "the assistant answer",
            "--output must be written before the image failure ends the run"
        );
    }

    #[test]
    fn a_successful_run_writes_output_and_reports_no_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("answer.md");

        let code = finish_prompt_artifacts(
            "the assistant answer",
            Some(&markdown_output_at(&output)),
            None,
            true,
            false,
        );

        assert_eq!(code, None);
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            "the assistant answer"
        );
    }

    #[test]
    fn an_unwritable_output_file_is_fatal_on_its_own() {
        // --output is a promise of a file at a caller-chosen path, exactly like
        // --image-output. The prompt path used to print the write error and
        // still exit 0, so automation read a missing or stale answer file as a
        // success. `open`/`get` have always exited 1 here; this is the third
        // path catching up.
        let dir = tempfile::tempdir().unwrap();
        // A directory standing where the file was promised: std::fs::write can
        // never succeed against it, on any platform.
        let blocked = dir.path().join("answer.md");
        std::fs::create_dir(&blocked).unwrap();

        // No image failure at all — the --output failure alone must kill the run.
        let code = finish_prompt_artifacts(
            "the assistant answer",
            Some(&markdown_output_at(&blocked)),
            None,
            true,
            false,
        );

        assert_eq!(
            code,
            Some(1),
            "a failed --output write must fail the command"
        );
    }

    #[test]
    fn a_run_without_output_never_invents_a_failure() {
        // Positive control for the test above: without --output there is no
        // file promise to break, so the run must stay exit 0. A wrapper that
        // fires on the None case would turn every plain `ask '...'` into a
        // failure.
        assert_eq!(
            finish_prompt_artifacts("the assistant answer", None, None, true, false),
            None
        );
    }

    #[test]
    fn the_output_flag_still_parses_into_a_usable_destination() {
        // The type clap parses --output into changed from String to
        // MarkdownOutput to make the path unreachable outside its module. That
        // is only worth anything if the flag still works, so: both spellings
        // parse, and the parsed value still lands the file where the caller
        // pointed. The path cannot be read back out for comparison — that is
        // the whole design — so the file appearing is the assertion.
        let dir = tempfile::tempdir().unwrap();
        for flag in ["--output", "-o"] {
            let requested = dir.path().join(format!("{}.md", flag.trim_matches('-')));
            let cli =
                Cli::try_parse_from(["ask-bridge", flag, requested.to_str().unwrap(), "a prompt"])
                    .unwrap();

            assert_eq!(
                finish_prompt_artifacts(
                    "the assistant answer",
                    cli.output.as_ref(),
                    None,
                    true,
                    false
                ),
                None,
                "{flag} must parse into a writable destination"
            );
            assert_eq!(
                std::fs::read_to_string(&requested).unwrap(),
                "the assistant answer",
                "{flag} must write the file the caller named"
            );
        }
    }

    #[test]
    fn an_output_failure_outranks_an_image_failure_in_the_exit_code() {
        // A process has one exit status and both artifacts can fail in the same
        // run, so one code has to lose. That is a decision, not a side effect of
        // whichever combinator got typed: --output carries the answer, images
        // are attachments, so --output wins and the image code is dropped. Both
        // failures still print their own stderr line, so nothing is lost that
        // the exit code was carrying.
        //
        // The image code here is synthetic (99 is not a code this CLI produces)
        // precisely so the assertion can see which side won — with the real 1
        // on both sides the precedence is invisible.
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("answer.md");
        std::fs::create_dir(&blocked).unwrap();

        let code = finish_prompt_artifacts(
            "the assistant answer",
            Some(&markdown_output_at(&blocked)),
            Some(99),
            true,
            false,
        );

        assert_eq!(
            code,
            Some(1),
            "when both artifacts fail the exit code must report the --output failure"
        );
    }

    #[test]
    fn both_fatal_artifact_paths_still_use_exit_code_one() {
        // The precedence above is unobservable in production only because both
        // producers return exactly 1. This pins that premise: if either path
        // ever gains a distinctive code, the masking becomes real and this test
        // fails, forcing the precedence to be re-decided instead of inherited.
        let dir = tempfile::tempdir().unwrap();
        let blocked = dir.path().join("answer.md");
        std::fs::create_dir(&blocked).unwrap();

        assert_eq!(
            // Reached through finish_prompt_artifacts with no image failure, so
            // this file never spells the entry point's name outside production
            // code — the call-site tripwire below counts those occurrences.
            finish_prompt_artifacts(
                "the assistant answer",
                Some(&markdown_output_at(&blocked)),
                None,
                true,
                false
            ),
            Some(1),
            "a failed --output write is exit 1"
        );
        assert_eq!(
            image_download_failure_exit_code(Some("shot.png")),
            Some(1),
            "a failed --image-output download is exit 1"
        );
    }

    #[test]
    fn a_timed_out_run_still_writes_output_but_fails_the_command() {
        // The wait loop gives up at --timeout with the provider still
        // generating, so the toolbar is never read and the markdown stays
        // empty. The epilogue then wrote that emptiness to the promised file
        // and exited 0 — and the caller's contract is "check the status, then
        // read the file back", so exit 0 over an empty file reads as "the
        // model answered with nothing", not "the run never got an answer".
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("answer.md");

        let (markdown, answer_arrived) = harvest_prompt_answer(Provider::ChatGpt, false, || {
            panic!("a run that timed out must not read the toolbar")
        });
        assert!(!answer_arrived, "a timed-out run delivered no answer");

        let code = finish_prompt_artifacts(
            &markdown,
            Some(&markdown_output_at(&output)),
            None,
            answer_arrived,
            false,
        );

        assert_eq!(code, Some(1), "a run with no answer must not exit 0");
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            "",
            "--output was promised and must still be produced, empty or not"
        );
    }

    #[test]
    fn a_failed_toolbar_copy_still_writes_output_but_fails_the_command() {
        // Same silent success by the other route: the stream did finish, but
        // copying it out of the toolbar failed, which only printed a line to
        // stderr and left the markdown empty.
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("answer.md");

        let (markdown, answer_arrived) = harvest_prompt_answer(Provider::ChatGpt, true, || {
            Err("clipboard read timed out".to_string())
        });
        assert!(!answer_arrived, "a failed copy delivered no answer");

        let code = finish_prompt_artifacts(
            &markdown,
            Some(&markdown_output_at(&output)),
            None,
            answer_arrived,
            false,
        );

        assert_eq!(code, Some(1), "a run with no answer must not exit 0");
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            "",
            "--output was promised and must still be produced, empty or not"
        );
    }

    #[test]
    fn a_copied_answer_is_still_a_successful_run() {
        // Positive control for the two above: a guard that fired on the happy
        // path would turn every run into a failure.
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("answer.md");

        let (markdown, answer_arrived) = harvest_prompt_answer(Provider::ChatGpt, true, || {
            Ok("the assistant answer".to_string())
        });
        assert!(answer_arrived);

        assert_eq!(
            finish_prompt_artifacts(
                &markdown,
                Some(&markdown_output_at(&output)),
                None,
                answer_arrived,
                false
            ),
            None
        );
        assert_eq!(
            std::fs::read_to_string(&output).unwrap(),
            "the assistant answer"
        );
    }

    #[test]
    fn a_missing_answer_outranks_an_image_failure_in_the_exit_code() {
        // Third artifact, same one exit status, so the precedence is a
        // decision: the answer is what the command is for, images are
        // attachments, so a run that produced no answer reports its own code
        // and the image code is dropped. Both still print their own stderr
        // line. 99 is not a code this CLI produces; it is here so the
        // assertion can see which side won.
        assert_eq!(
            finish_prompt_artifacts("", None, Some(99), false, false),
            Some(1),
            "the missing answer must outrank the image failure"
        );
        // And with an answer in hand the image failure is still fatal, so the
        // new arm cannot be masking it.
        assert_eq!(
            finish_prompt_artifacts("the assistant answer", None, Some(99), true, false),
            Some(99)
        );
    }

    #[test]
    fn the_output_path_stays_private_to_its_module() {
        // Scope of this test, stated so it is not mistaken for the guarantee:
        //
        // The guarantee that no code in main.rs can hand-write the --output
        // destination is the compiler's. `MarkdownOutput` keeps the path
        // private to `markdown_output`, so `std::fs::write(<the --output path>,
        // ..)` in these 8000-odd lines does not compile whatever the author
        // calls the variable. The round-1 version of this test grepped for
        // `std::fs::write(output_path` and was evaded by renaming the variable;
        // string matching cannot cover a bug class whose shape is the author's
        // choice of identifier and file API.
        //
        // What is left for a test is the trusted region itself — the one file
        // that is *allowed* to touch the path — plus the API it exposes, since
        // adding a `Display`/`as_str`/`path()` there would silently hand the
        // path back to main.rs and reopen everything. That check is lexical and
        // that is the honest ceiling for a region defined by being permitted.
        // Split literals keep the test from matching its own source text.
        let trusted = include_str!("markdown_output.rs");
        let write_call = concat!("std::fs::", "write(");

        assert_eq!(
            trusted.matches(write_call).count(),
            1,
            "markdown_output.rs is the whole trusted region; it may contain \
             exactly one write of the --output file"
        );
        // A whitelist, not a blacklist: banning `as_str`, `Display` and friends
        // by name is the same mistake as grepping for `output_path`, because the
        // evasion is just a different name. Instead the module's *entire* public
        // surface and trait-impl set is pinned, so anything new — an accessor
        // called `destination`, a `Deref`, a `#[derive(Debug)]` — fails here and
        // has to be argued for rather than slipped in.
        let names = |lines: &str, prefix: &'static str| -> Vec<String> {
            lines
                .lines()
                .map(str::trim)
                .filter(|line| line.starts_with(prefix))
                .map(|line| line.trim_end_matches(" {").to_string())
                .collect()
        };

        assert_eq!(
            names(trusted, "pub "),
            [
                "pub struct MarkdownOutput",
                "pub fn write_if_requested(",
                // Widening this list hands the path back to main.rs and voids
                // the compiler-enforced guarantee; that is the decision being
                // pinned, not the spelling.
            ],
            "unexpected public item in the trusted region"
        );
        assert_eq!(
            names(trusted, "impl "),
            ["impl FromStr for MarkdownOutput"],
            "a trait impl can leak the path as effectively as an accessor \
             (Display, Deref, AsRef<Path>, Into<String>)"
        );
        assert_eq!(
            names(trusted, "#[derive"),
            ["#[derive(Clone)]"],
            "Debug would print the path straight back out"
        );
    }

    #[test]
    fn every_command_path_still_writes_the_requested_output_file() {
        // Complementary to the privacy guarantee, which only stops a path from
        // writing --output *badly*. A rebase that drops the call from `get`
        // altogether would make `--output` silently do nothing there, and the
        // compiler is perfectly happy with that. Counting the call sites is the
        // available guard: it is lexical, it only defends the three paths that
        // exist today, and it cannot tell a real path from a decoy — but a
        // dropped call is exactly the failure mode this fork's rebases produce.
        // Split literals keep the test from matching its own source text.
        let source = include_str!("main.rs");
        let entry = concat!("markdown_output::", "write_if_requested(");
        let call_sites = source.matches(entry).count();

        assert!(
            call_sites >= 3,
            "open <url>, get and the default prompt run must each still write \
             --output; found {call_sites} call site(s)"
        );
    }

    /// Every path that ends in a prompt being typed must first read the
    /// selected tab's live URL.
    ///
    /// The `--session` path used to be the exception, and not for a reason that
    /// shows up in a behavioural test: `open_url_tab` binds the tab by
    /// `unique_new_page_id` (an ID-set difference that reads only `Page::id`)
    /// and `resolve_session_target` has already restricted the URL, so nothing
    /// can be *substituted* for that tab. What was missing is a check on where
    /// the tab went afterwards -- `wait_for_page_load` polls `readyState` and a
    /// DOM-shape probe, `submit_regular_prompt` checks no origin, so a redirect
    /// off the provider's origin was never noticed.
    ///
    /// Lexical, like the two tests below it, and for the same reason: the gap it
    /// guards is a *missing* call, which no type and no behavioural test can
    /// see. It also keeps the `# Call sites` block on
    /// `verify_selected_page_is_provider` honest -- that block enumerates its
    /// sites in prose, and prose cannot count.
    ///
    /// It pins *which* gate each path uses, not just that some gate is called.
    /// The two are not interchangeable: the generic one accepts the sub-domain
    /// rule and a sign-in origin, so putting it back on the `--session` arm
    /// would re-open the hole while leaving this test green if it only counted.
    #[test]
    fn every_prompt_bearing_path_verifies_the_live_url() {
        // Split literals keep this test from matching its own source text.
        let source = include_str!("main.rs");
        let gate = concat!("verify_selected_page_is_", "provider(");
        let session_gate = concat!("verify_session_page_is_", "provider(");
        let call_sites =
            source.matches(gate).count() - source.matches(&format!("fn {gate}")).count();

        assert_eq!(
            call_sites, 2,
            "the `# Call sites` doc block on the generic gate enumerates 2 call \
             sites (adoption, unpinned run); the source has {call_sites}. \
             Update both together -- a doc block that claims completeness it \
             does not have is how the --session path went unchecked."
        );
        // The session gate deliberately gets no count of its own: it is called
        // from the tests below as well as from `main`, and a count that had to
        // be revised every time a test was added would be revised without
        // thought. What matters about it is *which* arm calls it, which the two
        // assertions below pin directly.

        // The one that a rebase onto upstream actually drops: upstream has no
        // gate on this path at all, so a conflict resolution that takes their
        // side removes the call and leaves the other two intact.
        let session_arm = source
            .split_once(concat!(
                "if let Some((session_provider, session_url)) = ",
                "&session_target {"
            ))
            .expect("main should route --session through its own arm")
            .1
            .split_once(concat!("} else if let Err(e) = ", "ensure_provider_tab("))
            .expect("the --session arm should be followed by the ensure_provider_tab arm")
            .0;

        assert!(
            session_arm.contains(session_gate),
            "the --session arm reaches submit_regular_prompt without ever reading \
             the tab's live URL; a redirect off the provider's origin would be \
             typed into. Arm was:\n{session_arm}"
        );
        assert!(
            !session_arm.contains(gate),
            "the --session arm is using the generic gate, whose predicate accepts \
             the sub-domain and sign-in origins resolve_session_target refuses on \
             the command line -- so a redirect hands back exactly what the input \
             check rejected. Arm was:\n{session_arm}"
        );
    }

    /// The `--session` preparation is a sequence, and the second step's refusal
    /// is not advisory: it comes back as an `Err`, after the tab was opened, so
    /// `main` has something to abort on.
    #[test]
    fn a_refused_session_landing_page_is_an_error_not_a_warning() {
        // The ordinary case: navigate, then check, then let the run continue.
        let mut opened = 0;
        let mut verified = 0;
        {
            let mut open = || -> Result<(), String> {
                opened += 1;
                Ok(())
            };
            let mut verify = || -> Result<(), String> {
                verified += 1;
                Ok(())
            };
            assert_eq!(
                open_verified_session_tab(Provider::ChatGpt, &mut open, &mut verify),
                Ok(())
            );
        }
        assert_eq!((opened, verified), (1, 1));

        // The refusal this arm exists for: the browser left the conversation.
        let mut verify_calls = 0;
        {
            let mut open = || -> Result<(), String> { Ok(()) };
            let mut verify = || -> Result<(), String> {
                verify_calls += 1;
                Err("reports https://evil.example/ instead".to_string())
            };
            let error = open_verified_session_tab(Provider::ChatGpt, &mut open, &mut verify)
                .expect_err("a refused landing page must not come back as success");
            assert!(error.contains("ChatGPT"), "{error}");
            assert!(
                error.contains("reports https://evil.example/ instead"),
                "the refusal has to survive to the user, or the run stops with \
                 nothing said about why: {error}"
            );
        }
        assert_eq!(verify_calls, 1);

        // A tab that never opened is not verified at all: there is nothing to
        // verify, and doing it anyway would report the second failure instead of
        // the first.
        let mut verify_after_open_failure = 0;
        {
            let mut open = || -> Result<(), String> { Err("new_page failed".to_string()) };
            let mut verify = || -> Result<(), String> {
                verify_after_open_failure += 1;
                Ok(())
            };
            let error = open_verified_session_tab(Provider::ChatGpt, &mut open, &mut verify)
                .expect_err("a session tab that would not open must fail the run");
            assert!(error.contains("new_page failed"), "{error}");
        }
        assert_eq!(verify_after_open_failure, 0);
    }

    /// A `--session` run whose landing page is refused must *stop*.
    ///
    /// Lexical, deliberately, and this is the justification. The refusal itself
    /// is covered behaviourally by the test above; what is not coverable that
    /// way is what `main` does with it, because the abort is
    /// `std::process::exit` inside a 700-line `fn main`. The two alternatives
    /// were both measured and rejected: running the binary end to end cannot
    /// reach this branch offline (it needs a live chrome-devtools MCP session
    /// before the gate is ever consulted, and `write_mcp_config` overwrites the
    /// config on every run), and injecting the abort as a closure only moves the
    /// untestable line into `main` where this test would no longer be looking
    /// at it.
    ///
    /// The part that is not a compromise is on the production side: the arm's
    /// two browser steps now go through `open_verified_session_tab`, so the arm
    /// has exactly one error path, and this test can count paths against aborts
    /// instead of merely finding *an* `exit` that some other, still-fatal step
    /// happens to contribute.
    #[test]
    fn a_refused_session_aborts_the_run() {
        // Split literals keep this test from matching its own source text.
        let source = include_str!("main.rs");
        let arm = source
            .split_once(concat!(
                "if let Some((session_provider, session_url)) = ",
                "&session_target {"
            ))
            .expect("main should route --session through its own arm")
            .1
            .split_once(concat!("} else if let Err(e) = ", "ensure_provider_tab("))
            .expect("the --session arm should be followed by the ensure_provider_tab arm")
            .0;

        // Comments are stripped before anything is counted. `str::matches` is a
        // raw substring search, so without this the cheapest possible evasion --
        // leaving `// ... std::process::exit(1) felt too harsh.` in a branch
        // that now only warns -- satisfies every count below. Measured passing.
        let arm: String = arm
            .lines()
            .map(|line| match line.find("//") {
                Some(at) => &line[..at],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Counting occurrences anywhere in the arm is not enough either: moving
        // the abort to a *different*, still-fatal branch (an early
        // `if session_url.is_empty() { exit(1) }`) keeps the totals at (1, 1)
        // while the gate's own refusal is downgraded to a warning. Also
        // measured passing. So bind the abort to the gate's error block.
        let block = {
            let needle = concat!("if let Err(e) = open_verified_session_", "tab(");
            let from = arm
                .find(needle)
                .expect("the --session arm must route through the verified-session helper");
            let rest = &arm[from..];
            // The call's arguments are closures with bodies of their own, so
            // "the first `{` after the needle" is one of those, not the `if`
            // body. Let the call's parentheses balance first; the next `{` is
            // the branch. (Getting this wrong is loud, not silent: the previous
            // version matched the `open_url_tab` closure and failed.)
            // Start at the needle's OWN trailing `(`, not at the start of the
            // slice: `if let Err(e) = ...` has a balanced `(e)` before the call
            // opens, and scanning from there declared the call closed after
            // `Err(e)`.
            let call_start = needle.len() - 1;
            debug_assert!(rest[call_start..].starts_with('('));
            let mut parens = 0usize;
            let mut after_call = None;
            for (offset, character) in rest[call_start..].char_indices() {
                match character {
                    '(' => parens += 1,
                    ')' => {
                        parens -= 1;
                        if parens == 0 {
                            after_call = Some(call_start + offset + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let after_call = after_call.expect("the gate call must be paren-balanced");
            let open = after_call
                + rest[after_call..]
                    .find('{')
                    .expect("the gate's error branch must have a block");
            let mut depth = 0usize;
            let mut end = None;
            for (offset, character) in rest[open..].char_indices() {
                match character {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(open + offset + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            rest[open..end.expect("the gate's error branch must be brace-balanced")].to_string()
        };

        assert!(
            block.contains(concat!("std::process::", "exit(1)")),
            "the --session gate's own refusal does not end the run. A refusal \
             that only warns lets the prompt-bearing flow carry on into the \
             page the live-URL gate just rejected -- which is the whole reason \
             the gate is there. Branch was:\n{block}"
        );

        // And still nothing else in the arm may fall through: a second error
        // path added without its own abort is the other way back to the bug.
        let error_paths = arm.matches(concat!("if let ", "Err(e) = ")).count();
        let aborts = arm.matches(concat!("std::process::", "exit(1)")).count();
        assert_eq!(
            (error_paths, aborts),
            (1, 1),
            "every error path in the --session arm has to end the run; found \
             {error_paths} error path(s) and {aborts} abort(s). Arm was:\n{arm}"
        );
    }

    /// Return the rest of the branch a reported failure sits in, together with
    /// whether that branch itself ends the run.
    ///
    /// Brace depth, not indentation: the walk stops at the `}` closing the block
    /// the report is in, so it can never run on into the next step's arm and
    /// count *its* abort.
    fn reported_failure_branch(source: &str, report: &str) -> Result<(String, bool), String> {
        let fatal = concat!("std::process::", "exit(1);");
        let after = source
            .split_once(report)
            .ok_or_else(|| format!("main no longer reports the failure `{report}`"))?
            .1;

        let mut depth = 0usize;
        let mut branch = None;
        for (offset, character) in after.char_indices() {
            match character {
                '{' => depth += 1,
                '}' if depth == 0 => {
                    branch = Some(&after[..offset]);
                    break;
                }
                '}' => depth -= 1,
                _ => {}
            }
        }
        let branch = branch
            .ok_or_else(|| format!("the branch reporting `{report}` is not brace-balanced"))?;

        // Comments are stripped before the abort is looked for. `str::starts_with`
        // is a raw substring search, so without this the cheapest possible
        // evasion -- leaving `// std::process::exit(1); felt too harsh.` in a
        // branch that now only warns -- satisfies the check. Measured passing
        // before this was added.
        let branch: String = branch
            .lines()
            .map(|line| match line.find("//") {
                Some(at) => &line[..at],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Only a depth-0 abort counts: `if command_verbose { exit(1) }` contains
        // the needle while leaving the failure survivable on the ordinary path.
        let mut depth = 0usize;
        let mut aborts = false;
        for (offset, character) in branch.char_indices() {
            match character {
                '{' => depth += 1,
                '}' => depth = depth.saturating_sub(1),
                _ => {
                    if depth == 0 && branch[offset..].starts_with(fatal) {
                        aborts = true;
                    }
                }
            }
        }

        Ok((branch, aborts))
    }

    fn validate_trusted_steps_abort(source: &str) -> Result<(), String> {
        for (step, report) in [
            ("model", concat!("Error switching ", "model: {}")),
            ("reasoning", concat!("Error switching ", "reasoning: {}")),
            (
                "attachment",
                concat!("Error attaching ", "images/files: {}"),
            ),
        ] {
            let (branch, aborts) = reported_failure_branch(source, report)?;
            if !aborts {
                return Err(format!(
                    "the {step} step prints its error and carries on: the prompt is \
                     then typed with the wrong selection, or without the attachment, \
                     and the run still exits 0. Branch was:\n{branch}"
                ));
            }
        }

        Ok(())
    }

    /// A run that was told *which model*, *which reasoning effort* or *which
    /// files* to use must not go on to type the prompt once that step has
    /// failed.
    ///
    /// Lexical, for the same reason as `a_refused_session_aborts_the_run`: the
    /// abort is a `std::process::exit` inside `fn main`, downstream of a live
    /// chrome-devtools MCP session and a login check, so no offline behavioural
    /// test can reach it, and injecting the abort as a closure would only move
    /// the untested line somewhere this test no longer looks.
    ///
    /// `switch_model`, `switch_reasoning` and `upload_attachments_to_provider`
    /// already return `Err` -- the fail-loud machinery underneath is not the
    /// gap. The compiler is equally happy whether `main` dies on that `Err` or
    /// prints it and carries on. Drop one abort and the whole suite stays green
    /// while `--model gpt-5-pro` answers from whatever model the tab already had
    /// selected, and `--file report.pdf` answers about a file the page never
    /// received -- both with exit code 0, the only thing a calling script
    /// (scripts/ask.sh, the Agent Skill, any agent shelling out) ever reads.
    #[test]
    fn a_failed_selection_or_upload_still_aborts_the_run() {
        // Split literals keep this test from matching its own source text.
        let source = include_str!("main.rs").replace("\r\n", "\n");
        validate_trusted_steps_abort(&source)
            .expect("a failed model / reasoning / attachment step must end the run");
    }

    /// Anti-tautology for the guard above: it has to be able to fail, and it has
    /// to fail on the two ways of *looking* like it still aborts. Mutating the
    /// real source in memory proves all three without touching production.
    #[test]
    fn the_trusted_step_guard_rejects_a_step_that_only_warns() {
        let source = include_str!("main.rs").replace("\r\n", "\n");
        let report = concat!("Error switching ", "model: {}");
        let fatal = concat!("std::process::", "exit(1);");

        // Locate the model step's own abort: the first one after its report.
        let at = source
            .find(report)
            .expect("main should still report a failed model step");
        let abort_at = at
            + source[at..]
                .find(fatal)
                .expect("fixture drift: the model step no longer aborts");
        let (before, after) = (&source[..abort_at], &source[abort_at + fatal.len()..]);

        for (evasion, replacement) in [
            ("the abort deleted outright", "".to_string()),
            (
                "the abort left behind as a comment",
                format!("// {fatal} felt too harsh."),
            ),
            (
                "the abort demoted to a verbose-only branch",
                format!("if command_verbose {{ {fatal} }}"),
            ),
        ] {
            let mutant = format!("{before}{replacement}{after}");
            assert_ne!(mutant, source, "{evasion}: the mutation changed nothing");

            match validate_trusted_steps_abort(&mutant) {
                Ok(()) => panic!("a model step with {evasion} was accepted as fatal"),
                Err(error) => assert!(
                    error.contains("the model step"),
                    "unexpected error for {evasion}: {error}"
                ),
            }
        }
    }

    #[test]
    fn every_image_download_goes_through_the_exit_code_wrapper() {
        // Tripwire for a rebase. The --image-output contract lives in three
        // separate command paths, and a rebase onto upstream that drops the
        // wrapper from just one of them restores the silent-success bug while
        // every behavioural test, `cargo fmt --check` and
        // `cargo clippy -D warnings` all stay green. Split literals keep this
        // test from matching its own source text.
        let source = include_str!("main.rs");
        let raw = concat!("download_images_", "from_latest_message(");
        let wrapped = concat!("download_images_", "and_exit_code(");
        let call_sites = |needle: &str| {
            source.matches(needle).count() - source.matches(&format!("fn {needle}")).count()
        };

        assert_eq!(
            call_sites(raw),
            1,
            "the unguarded downloader may only be called by {wrapped} — a direct \
             call bypasses the --image-output exit-code contract"
        );
        assert!(
            call_sites(wrapped) >= 3,
            "open <url>, get and the default prompt run each need the wrapper; found {}",
            call_sites(wrapped)
        );
    }

    #[cfg(unix)]
    #[test]
    fn response_scratch_file_never_follows_a_preplanted_symlink() {
        // The scratch path used to be `ask_chatgpt_<pid>.md` in TMPDIR — a name
        // anything running as this user (or any user, in a shared/sticky
        // TMPDIR) can compute. `std::fs::write` follows symlinks, so a link
        // planted at that name turns the round-trip into an arbitrary
        // overwrite of a file the user owns.
        let dir = tempfile::tempdir().unwrap();
        let sentinel = dir.path().join("precious.txt");
        std::fs::write(&sentinel, "DO NOT MODIFY").unwrap();
        let guessable = dir
            .path()
            .join(format!("ask_chatgpt_{}.md", std::process::id()));
        std::os::unix::fs::symlink(&sentinel, &guessable).unwrap();

        let verified = roundtrip_response_via_temp_file(dir.path(), "assistant response").unwrap();

        assert_eq!(verified, "assistant response");
        assert_eq!(
            std::fs::read_to_string(&sentinel).unwrap(),
            "DO NOT MODIFY",
            "the round-trip wrote through a pre-planted symlink"
        );

        // The scratch file holds the whole response, so it must not outlive the
        // round-trip; only the fixtures planted above may remain.
        let mut left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                format!("ask_chatgpt_{}.md", std::process::id()),
                "precious.txt".to_string()
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn response_scratch_file_is_unguessable_and_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        // Something the constructor must leave strictly alone.
        std::fs::write(dir.path().join("decoy.md"), b"PRE-EXISTING").unwrap();

        let first = create_response_scratch_file(dir.path()).unwrap();
        let second = create_response_scratch_file(dir.path()).unwrap();

        // Randomised: two scratch files in the same directory never collide, so
        // nothing derives from the PID and no name can be planted in advance.
        assert_ne!(first.path(), second.path());
        let guessable = format!("ask_chatgpt_{}.md", std::process::id());
        for scratch in [&first, &second] {
            assert_ne!(
                scratch.path().file_name().unwrap().to_string_lossy(),
                guessable.as_str()
            );
            // 0600: the scratch file holds the full assistant response, which
            // must not be readable by other users of a shared temp directory.
            let mode = std::fs::metadata(scratch.path())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "scratch file {:?} is not owner-only",
                scratch.path()
            );
        }

        // Creating the scratch file must never disturb what is already in the
        // directory — no reuse, no truncation, no writing through a link.
        assert!(
            std::fs::symlink_metadata(first.path())
                .unwrap()
                .file_type()
                .is_file(),
            "the scratch file must be a real file, never a link to one"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("decoy.md")).unwrap(),
            "PRE-EXISTING"
        );
        assert_eq!(std::fs::metadata(first.path()).unwrap().len(), 0);
    }

    #[test]
    fn response_scratch_file_is_created_exclusively() {
        // O_EXCL is not observable from outside `create_response_scratch_file`:
        // the name is random by design, so a test cannot pre-plant anything at
        // the path the call will pick, and `tempfile` retries on collision
        // rather than failing. Pin the implementation instead — a hand-rolled
        // `File::create` / `OpenOptions::create(true)` passes every behavioural
        // test above while silently reintroducing follow-and-truncate.
        let source = include_str!("main.rs").replace("\r\n", "\n");
        let body = source
            .split_once(concat!("fn create_response_", "scratch_file("))
            .expect("the scratch-file constructor should exist")
            .1
            .split_once("\n}\n")
            .expect("the constructor should have a body")
            .0;

        assert!(
            body.contains("tempfile::Builder::new()") && body.contains(".tempfile_in("),
            "the scratch file must come from tempfile's exclusive-create builder \
             (O_CREAT|O_EXCL, 0600); found:\n{body}"
        );
    }
}

fn read_clipboard() -> Result<String, String> {
    let output = Command::new("pbpaste")
        .output()
        .map_err(|e| format!("Failed to run pbpaste: {}", e))?;

    if !output.status.success() {
        return Err(format!("pbpaste exited with status: {}", output.status));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn write_clipboard(content: &str) -> Result<(), String> {
    let mut child = Command::new("pbcopy")
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run pbcopy: {}", e))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(content.as_bytes())
            .map_err(|e| format!("Failed to write clipboard content: {}", e))?;
    }

    let status = child
        .wait()
        .map_err(|e| format!("Failed to wait for pbcopy: {}", e))?;

    if !status.success() {
        return Err(format!("pbcopy exited with status: {}", status));
    }

    Ok(())
}

fn click_latest_copy_button(config_path: &str, provider: Provider) -> Result<(), String> {
    let response_selector = serde_json::to_string(provider.latest_response_selector())
        .map_err(|e| format!("Failed to serialize response selector: {}", e))?;
    let script = r#"() => {
                const isVisible = (el) => {
                    if (!el || el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
                    const style = window.getComputedStyle(el);
                    if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
                    const rect = el.getBoundingClientRect();
                    return rect.width > 0 && rect.height > 0;
                };

                const labelOf = (el) => [
                    el.getAttribute('aria-label'),
                    el.getAttribute('title'),
                    el.getAttribute('data-testid'),
                    el.textContent
                ].filter(Boolean).join(' ');

                const isCopyButton = (el) => {
                    const label = labelOf(el);
                    return /copy|複製|复制|コピー|복사/i.test(label)
                        && !/prompt|提示詞|提示词|入力|table|表格/i.test(label);
                };
                const copyButtonScore = (el) => {
                    const label = labelOf(el);
                    if (!isCopyButton(el) || !isVisible(el)) return -1;
                    if (el.closest('pre, code, [class*="code"], [data-testid*="code"]')) return -1;
                    if (/copy-turn-action-button/i.test(label)) return 100;
                    if (/response|回應|回答|reply/i.test(label)) return 90;
                    if (el.closest('model-response, response-container, [data-message-author-role="assistant"], .agent-turn, [data-is-streaming], .font-claude-response')) return 50;
                    return 10;
                };
                const messages = Array.from(document.querySelectorAll(__RESPONSE_SELECTOR__));
                const latest = messages[messages.length - 1];
                if (!latest) return { ok: false, reason: "No assistant message found" };

                latest.scrollIntoView({ block: 'center', inline: 'nearest' });
                for (const type of ['pointerover', 'mouseover', 'mouseenter']) {
                    latest.dispatchEvent(new MouseEvent(type, { bubbles: true, view: window }));
                }

                const scopes = [
                    latest,
                    latest.closest('article'),
                    latest.closest('[data-testid^="conversation-turn"]'),
                    latest.parentElement,
                    latest.parentElement?.parentElement
                ].filter(Boolean);

                for (const scope of scopes) {
                    const buttons = Array.from(scope.querySelectorAll('button'));
                    const candidates = buttons
                        .map((button) => ({ button, score: copyButtonScore(button) }))
                        .filter((candidate) => candidate.score >= 0)
                        .sort((a, b) => b.score - a.score);
                    if (candidates.length > 0) {
                        const button = candidates[0].button;
                        button.click();
                        return { ok: true, label: labelOf(button) };
                    }
                }

                return { ok: false, reason: "Copy response button not found" };
            }"#
    .replace("__RESPONSE_SELECTOR__", &response_selector);
    let res = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({
            "function": script
        }),
    )?;

    let parsed = parse_script_result(&res)?;
    if parsed["ok"].as_bool().unwrap_or(false) {
        Ok(())
    } else {
        Err(parsed["reason"]
            .as_str()
            .unwrap_or("Failed to click copy response button")
            .to_string())
    }
}

fn wait_for_page_load(config_path: &str, provider: Provider, verbose: bool) -> Result<(), String> {
    if verbose {
        println!("Waiting for page readyState...");
    }

    // Phase 1: Wait for readyState complete or interactive
    let mut ready = false;
    for _ in 0..90 {
        let ready_res = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({
                "function": "() => document.readyState === 'complete' || document.readyState === 'interactive'"
            }),
        );

        if ready_res
            .and_then(|res| parse_script_result(&res))
            .map(|parsed| parsed.as_bool().unwrap_or(false))
            .unwrap_or(false)
        {
            ready = true;
            break;
        }

        thread::sleep(Duration::from_millis(500));
    }

    if !ready {
        return Err("Timeout waiting for page readyState to be loaded".to_string());
    }

    if verbose {
        println!("Waiting for {} page elements...", provider.display_name());
    }

    // Phase 2: Wait for key provider elements to render.
    for _ in 0..60 {
        let element_res = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({
                "function": provider.ready_check_js()
            }),
        );

        if element_res
            .and_then(|res| parse_script_result(&res))
            .map(|parsed| parsed.as_bool().unwrap_or(false))
            .unwrap_or(false)
        {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(250));
    }

    if verbose {
        println!(
            "Warning: Timeout waiting for {} page elements. Proceeding anyway...",
            provider.display_name()
        );
    }
    Ok(())
}

fn open_url_tab(
    config_path: &str,
    provider: Provider,
    url: &str,
    headless: bool,
    verbose: bool,
) -> Result<(), String> {
    if verbose {
        println!("Opening URL: {}", url);
    }

    let list_res = call_mcp_tool(config_path, "list_pages", serde_json::json!({}))?;
    let text = list_res
        .get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|obj| obj.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| format!("Invalid list_pages response structure: {:?}", list_res))?;

    let pages_before = parse_pages(text);
    // `url == None` is "unknown", never "blank": a tab whose listing line did
    // not read back unambiguously is not a blank tab to navigate away.
    let target_page_id = if pages_before.len() == 1
        && pages_before[0].url.as_deref().is_some_and(is_blank_tab_url)
    {
        call_mcp_tool(
            config_path,
            "navigate_page",
            serde_json::json!({
                "url": url
            }),
        )?;
        pages_before[0].id
    } else {
        call_mcp_tool(
            config_path,
            "new_page",
            serde_json::json!({
                "url": url
            }),
        )?;
        let refreshed_pages_res = call_mcp_tool(config_path, "list_pages", serde_json::json!({}))?;
        let refreshed_text = refreshed_pages_res
            .get("content")
            .and_then(|c| c.as_array())
            .and_then(|arr| arr.first())
            .and_then(|obj| obj.get("text"))
            .and_then(|t| t.as_str())
            .ok_or_else(|| {
                format!(
                    "Invalid refreshed list_pages response structure: {:?}",
                    refreshed_pages_res
                )
            })?;
        let refreshed_pages = parse_pages(refreshed_text);
        // Upstream `c1da128`: bind the new tab by page-ID set difference, not
        // by matching its listed URL. That is the stronger rule here -- an ID
        // the browser minted cannot be forged by a page, whereas the URL this
        // used to compare against comes out of the listing prose.
        unique_new_page_id(&pages_before, &refreshed_pages)?
    };

    call_mcp_tool(
        config_path,
        "select_page",
        serde_json::json!({
            "pageId": target_page_id,
            "bringToFront": !headless
        }),
    )?;

    let page_provider = Provider::from_url(url).unwrap_or(provider);
    wait_for_page_load(config_path, page_provider, verbose)
}

fn copy_latest_markdown(config_path: &str, provider: Provider) -> Result<String, String> {
    match copy_latest_markdown_via_clipboard(config_path, provider) {
        Ok(content) => Ok(content),
        Err(_) => scrape_latest_markdown_from_dom(config_path, provider),
    }
}

/// Name of the file whose OS lock serialises the clipboard transaction.
const CLIPBOARD_LOCK_NAME: &str = "ask-bridge-clipboard.lock";

/// Win32 `FILE_FLAG_OPEN_REPARSE_POINT`: open a leaf reparse point itself
/// instead of following it to its target.
#[cfg(target_os = "windows")]
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

/// How long to wait for another run to finish with the clipboard.
///
/// The transaction it guards is bounded by the two 30-iteration polls inside
/// it: ~15s of click retries plus ~3s of clipboard polling, so a healthy holder
/// is gone well inside this. It is long enough to queue behind one, and short
/// enough that a wedged holder does not hang a run indefinitely.
const CLIPBOARD_LOCK_WAIT: Duration = Duration::from_secs(45);

/// Holds the clipboard lock for as long as it is alive.
///
/// An OS file lock rather than a PID file on purpose: the OS drops the lock when
/// the file handle closes, which includes the process being killed, so there is
/// no stale-lock state to detect, age out, or get wrong. Rust maps this to
/// `flock` on Unix and `LockFileEx` on Windows. Nothing is written into the file
/// -- its only job is to be a thing two processes can name.
#[derive(Debug)]
struct ClipboardGuard {
    _file: std::fs::File,
}

/// Take the clipboard lock in `dir`, waiting up to `wait` for a holder to
/// finish.
///
/// # Why the clipboard needs a lock
///
/// [`copy_latest_markdown_via_clipboard`] is a five-step transaction on a
/// single machine-wide resource: read what is there, replace it with a
/// PID-stamped sentinel, click, poll until the clipboard changes, put the
/// original back. Two runs overlapping on it -- which is what happens the
/// moment a user asks two questions at once, or a script fans out -- break it
/// in two distinct ways, and the PID in the sentinel does not prevent either:
///
/// * B's "original" is captured after A has already written A's sentinel, so
///   when B restores it the user's clipboard is left holding
///   `__ASK_CHATGPT_COPY_PENDING_<A>__`; A's own restore may already have
///   happened, so nothing puts the real content back;
/// * A's poll accepts any content that is non-empty and not A's *own*
///   sentinel, so B's sentinel, or the response B copied, satisfies it. A then
///   returns B's answer as A's.
///
/// The lock covers the whole transaction rather than each step, because the
/// invariant is about the resource's *contents across* steps.
fn lock_clipboard_in(dir: &Path, wait: Duration) -> Result<ClipboardGuard, String> {
    lock_clipboard_in_with_before_open(dir, wait, |_| Ok(()))
}

/// Deterministic race seam for [`lock_clipboard_in`]. Production passes a
/// no-op; the regression test swaps the already-inspected leaf immediately
/// before open, which is the interleaving the platform no-follow flags close.
fn lock_clipboard_in_with_before_open<F>(
    dir: &Path,
    wait: Duration,
    before_open: F,
) -> Result<ClipboardGuard, String>
where
    F: FnOnce(&Path) -> Result<(), String>,
{
    let path = dir.join(CLIPBOARD_LOCK_NAME);
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(format!(
                "Refusing to use the clipboard lock through a symbolic link: {:?}",
                path
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "Failed to inspect the clipboard lock {:?}: {}",
                path, error
            ));
        }
    }
    before_open(&path)?;

    let mut options = std::fs::OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            // TMPDIR can be shared, and a lock on a file someone else chose is
            // not a lock on this one. Windows rejects a pre-existing symlink
            // above; Unix additionally closes the inspect/open race here.
            .custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // The pre-open inspection above gives a useful error for a stable
        // symlink. This flag closes the check/open race: if the leaf is swapped
        // for any name-surrogate reparse point, the handle names that reparse
        // point and the handle-metadata check below rejects it as non-regular.
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(&path)
        .map_err(|e| format!("Failed to open the clipboard lock {:?}: {}", path, e))?;
    if !file
        .metadata()
        .map_err(|error| {
            format!(
                "Failed to inspect opened clipboard lock {:?}: {}",
                path, error
            )
        })?
        .file_type()
        .is_file()
    {
        return Err(format!("Clipboard lock is not a regular file: {:?}", path));
    }

    let deadline = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(ClipboardGuard { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => {}
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(format!("Failed to lock {:?}: {}", path, error));
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Another ask-bridge process has held the clipboard for more than \
                 {}s; refusing to interleave with it rather than trade sentinels",
                wait.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// How long to wait before retrying the copy button while a Single Page App is
/// still rendering the message.
const CLIPBOARD_CLICK_RETRY_INTERVAL: Duration = Duration::from_millis(500);

/// How long to wait between clipboard polls after the copy button was clicked.
const CLIPBOARD_POLL_INTERVAL: Duration = Duration::from_millis(100);

fn copy_latest_markdown_via_clipboard(
    config_path: &str,
    provider: Provider,
) -> Result<String, String> {
    copy_latest_markdown_via_clipboard_with(
        &mut || read_clipboard(),
        &mut |content: &str| write_clipboard(content),
        &mut || click_latest_copy_button(config_path, provider),
        &std::env::temp_dir(),
        CLIPBOARD_CLICK_RETRY_INTERVAL,
        CLIPBOARD_POLL_INTERVAL,
    )
}

/// Test seam for [`copy_latest_markdown_via_clipboard`]: the three things the
/// transaction does to the world outside this process -- read the clipboard,
/// write it, click the provider's copy button -- go through injected closures,
/// and both waits are parameters. A test can therefore drive the whole
/// transaction against fakes and, from inside one of them, try to take the
/// clipboard lock the way a second `ask-bridge` process would.
///
/// That probe is the only way to see the property the lock exists for. The lock
/// being *taken* is visible in the source; the lock still being *held* three
/// steps later is not, and binding the guard to `_` instead of
/// `_clipboard_guard` releases it on the line that takes it while leaving the
/// call -- and every source-level check that looks for it -- exactly as it was.
fn copy_latest_markdown_via_clipboard_with<R, W, C>(
    read_clipboard: &mut R,
    write_clipboard: &mut W,
    click_copy_button: &mut C,
    temp_dir: &Path,
    click_retry_interval: Duration,
    clipboard_poll_interval: Duration,
) -> Result<String, String>
where
    R: FnMut() -> Result<String, String>,
    W: FnMut(&str) -> Result<(), String>,
    C: FnMut() -> Result<(), String>,
{
    // Held for the whole transaction below; released when this function returns
    // by any path, including the early `return Err` in the click-retry arm.
    let _clipboard_guard = lock_clipboard_in(temp_dir, CLIPBOARD_LOCK_WAIT)?;

    let clipboard_before = read_clipboard().unwrap_or_default();
    let sentinel = format!("__ASK_CHATGPT_COPY_PENDING_{}__", std::process::id());
    write_clipboard(&sentinel)?;

    // Click the copy button, retrying if the message or button is not found yet (due to asynchronous rendering of Single Page App)
    let mut click_err = None;
    for _ in 0..30 {
        match click_copy_button() {
            Ok(_) => {
                click_err = None;
                break;
            }
            Err(e) => {
                click_err = Some(e);
                thread::sleep(click_retry_interval);
            }
        }
    }

    if let Some(err) = click_err {
        // Restore clipboard before returning error
        let _ = write_clipboard(&clipboard_before);
        return Err(format!("Error copying latest response Markdown: {}", err));
    }

    let mut copied_content = None;
    for _ in 0..30 {
        thread::sleep(clipboard_poll_interval);
        match read_clipboard() {
            Ok(content) if !content.trim().is_empty() && content != sentinel => {
                copied_content = Some(content);
                break;
            }
            _ => {}
        }
    }

    // Always restore the original clipboard
    let _ = write_clipboard(&clipboard_before);

    let content = copied_content
        .ok_or_else(|| "Timed out waiting for clipboard content after clicking copy".to_string())?;

    roundtrip_response_via_temp_file(temp_dir, &content)
}

/// Create the scratch file the copied response is round-tripped through.
///
/// Randomised name + `O_EXCL` + 0600 instead of the old fixed
/// `ask_chatgpt_<pid>.md`: that name is computable by anyone, and
/// `std::fs::write` follows symlinks, so a link planted at it in a shared or
/// sticky `TMPDIR` (or by any process running as this user) redirected the
/// write onto an arbitrary file the user could write. The exclusive create
/// also refuses to reuse whatever is already sitting at the path, and 0600
/// keeps the response body out of other users' reach.
fn create_response_scratch_file(dir: &Path) -> Result<tempfile::NamedTempFile, String> {
    tempfile::Builder::new()
        .prefix(".ask_chatgpt.")
        .suffix(".md")
        .tempfile_in(dir)
        .map_err(|e| format!("Failed to create temporary file: {}", e))
}

/// Write the copied response to a scratch file and read it back, then remove it.
fn roundtrip_response_via_temp_file(dir: &Path, content: &str) -> Result<String, String> {
    let mut scratch = create_response_scratch_file(dir)?;

    // Write the copied content immediately to the temporary file
    scratch
        .write_all(content.as_bytes())
        .and_then(|()| scratch.flush())
        .map_err(|e| format!("Failed to write to temporary file: {}", e))?;

    // Read the content back from the temporary file to output to the terminal
    let verified_content = std::fs::read_to_string(scratch.path())
        .map_err(|e| format!("Failed to read from temporary file: {}", e))?;

    // Clean up temporary file (NamedTempFile removes it on drop)
    Ok(verified_content)
}

fn scrape_latest_markdown_from_dom(
    config_path: &str,
    provider: Provider,
) -> Result<String, String> {
    let latest_selector = serde_json::to_string(provider.latest_response_selector())
        .map_err(|e| format!("Failed to serialize response selector: {}", e))?;
    let content_selector = serde_json::to_string(provider.response_content_selector())
        .map_err(|e| format!("Failed to serialize response content selector: {}", e))?;
    let inspect_js = r#"() => {
        const latestSelector = __LATEST_SELECTOR__;
        const contentSelector = __CONTENT_SELECTOR__;
        const messages = Array.from(document.querySelectorAll(latestSelector))
            .filter((el) => ((el.innerText || el.textContent || '').trim().length > 0));
        const latest = messages[messages.length - 1];
        if (!latest) return 'No assistant message found';
        const turn = contentSelector ? (latest.querySelector(contentSelector) || latest) : latest;
        
        const elementToMarkdown = (element) => {
            let markdown = '';
            const processedSrcs = new Set();
            const walk = (node) => {
                if (node.nodeType === Node.TEXT_NODE) {
                    markdown += node.textContent;
                    return;
                }
                if (node.nodeType !== Node.ELEMENT_NODE) return;

                const tag = node.tagName.toLowerCase();
                
                const classText = Array.from(node.classList || []).join(' ');
                if (node.classList.contains('sr-only') ||
                    /screen-reader|visually-hidden|cdk-visually-hidden/.test(classText) ||
                    tag === 'button' || tag === 'style' || tag === 'script') {
                    return;
                }

                // Code blocks
                if (tag === 'pre') {
                    const codeEl = node.querySelector('code');
                    const langClass = codeEl ? Array.from(codeEl.classList).find(c => c.startsWith('language-')) : '';
                    const lang = langClass ? langClass.replace('language-', '') : '';
                    const codeText = codeEl ? codeEl.textContent : node.textContent;
                    markdown += '\n```' + lang + '\n' + codeText + '\n```\n';
                    return;
                }

                // Inline code
                if (tag === 'code') {
                    if (!node.closest('pre')) {
                        markdown += '`' + node.textContent + '`';
                        return;
                    }
                }

                // Bold
                if (tag === 'strong' || tag === 'b') {
                    markdown += '**';
                    for (const child of node.childNodes) walk(child);
                    markdown += '**';
                    return;
                }

                // Italics
                if (tag === 'em' || tag === 'i') {
                    markdown += '*';
                    for (const child of node.childNodes) walk(child);
                    markdown += '*';
                    return;
                }

                // Links
                if (tag === 'a') {
                    const href = node.getAttribute('href') || '';
                    const text = node.textContent || '';
                    if (href && text) {
                        markdown += '[' + text + '](' + href + ')';
                        return;
                    }
                }

                // Paragraphs, headers, list items
                if (tag === 'p') markdown += '\n';
                if (tag === 'br') markdown += '\n';
                if (tag === 'h1') markdown += '\n# ';
                if (tag === 'h2') markdown += '\n## ';
                if (tag === 'h3') markdown += '\n### ';
                if (tag === 'h4') markdown += '\n#### ';
                if (tag === 'h5') markdown += '\n##### ';
                if (tag === 'h6') markdown += '\n###### ';
                if (tag === 'li') markdown += '\n* ';

                // Images
                if (tag === 'img') {
                    const src = node.getAttribute('src') || '';
                    const alt = node.getAttribute('alt') || 'image';
                    if (src && !src.includes('avatar') && !src.includes('profile')) {
                        if (processedSrcs.has(src)) return;
                        processedSrcs.add(src);
                        markdown += '\n![' + alt + '](' + src + ')\n';
                        return;
                    }
                }

                for (const child of node.childNodes) {
                    walk(child);
                }

                if (['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li'].includes(tag)) {
                    markdown += '\n';
                }
            };

            walk(element);
            return markdown.trim().replace(/\n{3,}/g, '\n\n');
        };
        
        return elementToMarkdown(turn);
    }"#
    .replace("__LATEST_SELECTOR__", &latest_selector)
    .replace("__CONTENT_SELECTOR__", &content_selector);

    let res = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({
            "function": inspect_js
        }),
    )?;

    let val = parse_script_result(&res)?;
    let content = val
        .as_str()
        .ok_or_else(|| "DOM scraper returned non-string result".to_string())?
        .to_string();

    if content == "No assistant message found" {
        return Err(format!(
            "No assistant message found on {} page",
            provider.display_name()
        ));
    }

    Ok(content)
}

fn download_images_from_latest_message(
    config_path: &str,
    provider: Provider,
    image_output: Option<&str>,
    verbose: bool,
) -> Result<(), String> {
    if verbose {
        println!("Checking for generated images in the latest assistant response...");
    }
    let latest_selector = serde_json::to_string(provider.latest_response_selector())
        .map_err(|e| format!("Failed to serialize response selector: {}", e))?;
    let image_scan_js = r#"() => {
                window.__downloaded_images_status = "pending";
                window.__downloaded_images = null;
                (async () => {
                    try {
                        const messages = document.querySelectorAll(__LATEST_SELECTOR__);
                        const latestMessage = messages[messages.length - 1];
                        if (!latestMessage) {
                            window.__downloaded_images = [];
                            window.__downloaded_images_status = "success";
                            return;
                        }
                        
                        const imgs = Array.from(latestMessage.querySelectorAll('img'));
                        const seenSrcs = new Set();
                        const candidateImgs = imgs.filter(img => {
                            const src = img.src || '';
                            if (src.includes('avatar') || src.includes('profile')) return false;
                            const width = img.naturalWidth || img.width || 0;
                            const height = img.naturalHeight || img.height || 0;
                            if (width > 0 && width < 100) return false;
                            if (height > 0 && height < 100) return false;
                            if (!src.startsWith('http') && !src.startsWith('blob:') && !src.startsWith('data:image/')) return false;
                            if (seenSrcs.has(src)) return false;
                            seenSrcs.add(src);
                            return true;
                        });

                        const imagesData = [];
                        for (let i = 0; i < candidateImgs.length; i++) {
                            const img = candidateImgs[i];
                            try {
                                if (!img.complete) {
                                    await new Promise((resolve) => {
                                        img.addEventListener('load', resolve);
                                        img.addEventListener('error', resolve);
                                        setTimeout(resolve, 10000);
                                    });
                                }

                                let dataUrl = "";
                                if ((img.src || '').startsWith('data:image/')) {
                                    dataUrl = img.src;
                                } else {
                                    try {
                                        const response = await fetch(img.src);
                                        const blob = await response.blob();
                                        dataUrl = await new Promise((resolve, reject) => {
                                            const reader = new FileReader();
                                            reader.onloadend = () => resolve(reader.result);
                                            reader.onerror = reject;
                                            reader.readAsDataURL(blob);
                                        });
                                    } catch (fetchErr) {
                                        const canvas = document.createElement('canvas');
                                        canvas.width = img.naturalWidth || img.width || 512;
                                        canvas.height = img.naturalHeight || img.height || 512;
                                        const ctx = canvas.getContext('2d');
                                        ctx.drawImage(img, 0, 0);
                                        dataUrl = canvas.toDataURL('image/png');
                                    }
                                }

                                if (dataUrl && dataUrl.startsWith('data:image/')) {
                                    imagesData.push({
                                        index: i,
                                        src: img.src,
                                        alt: img.alt || "",
                                        dataUrl: dataUrl
                                    });
                                }
                            } catch (err) {
                                // ignore
                            }
                        }
                        window.__downloaded_images = imagesData;
                        window.__downloaded_images_status = "success";
                    } catch (e) {
                        window.__downloaded_images_status = "error: " + e.message;
                    }
                })();
                return { ok: true };
            }"#
    .replace("__LATEST_SELECTOR__", &latest_selector);

    let start_res = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({
            "function": image_scan_js
        }),
    )?;

    let start_parsed = parse_script_result(&start_res)?;
    if !start_parsed["ok"].as_bool().unwrap_or(false) {
        return Err("Failed to initiate image scanning script".to_string());
    }

    let mut wait_cycles = 0;
    let mut status = String::from("pending");
    while status == "pending" && wait_cycles < 150 {
        thread::sleep(Duration::from_millis(100));
        let check_res = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({
                "function": "() => window.__downloaded_images_status || 'pending'"
            }),
        )?;
        if let Some(s) = parse_script_result(&check_res)
            .ok()
            .and_then(|p| p.as_str().map(|str_ref| str_ref.to_string()))
        {
            status = s;
        }
        wait_cycles += 1;
    }

    if status.starts_with("error:") {
        return Err(format!("Image scanning failed: {}", status));
    }

    if status == "pending" {
        return Err("Timed out waiting for images to download in browser".to_string());
    }

    let get_res = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({
            "function": r#"() => {
                const res = window.__downloaded_images || [];
                delete window.__downloaded_images;
                delete window.__downloaded_images_status;
                return res;
            }"#
        }),
    )?;

    let parsed = parse_script_result(&get_res)?;
    // Zero artifacts is a *failure* when `--image-output` named a path, and a
    // non-event otherwise. See `save_generated_images` for the contract; these
    // two branches are the same rule applied before there is a list to hand it.
    let images = match parsed.as_array() {
        Some(arr) => arr,
        None => {
            if let Some(error) = zero_images_error(image_output, "did not return a list") {
                return Err(error);
            }
            return Ok(());
        }
    };

    if images.is_empty() {
        if let Some(error) = zero_images_error(image_output, "found no generated images") {
            return Err(error);
        }
        if verbose {
            println!("No generated images found in the latest response.");
        }
        return Ok(());
    }

    save_generated_images(images, image_output)
}

/// What "the scan produced no images at all" means, or `None` to carry on.
///
/// Same rule as [`image_download_failure_exit_code`], one step earlier: an
/// explicit `--image-output` is a path the caller will read back, so producing
/// nothing there is a failure, while without the flag it is a non-event.
///
/// A function rather than the two inline branches it replaces, because those
/// branches sit behind `call_mcp_tool` and no test can reach them; this way the
/// decision itself is checkable and both call sites share one answer.
fn zero_images_error(image_output: Option<&str>, what_happened: &str) -> Option<String> {
    image_output.map(|destination| {
        format!(
            "The image scan {}, so nothing was written to the --image-output \
             path {}",
            what_happened, destination
        )
    })
}

/// Exit code a command must terminate with after an image download failed, or
/// `None` to carry on.
///
/// `--image-output` names a path the caller intends to read back, so a failed
/// download leaves automation consuming a missing or stale file while the exit
/// status says the artifact is there — the same contract `--output` already
/// enforces for the Markdown file. Without the flag the download is a
/// best-effort extra into `target/`; the answer itself has already been
/// printed, so the run still succeeded and stays exit 0 (upstream behaviour).
fn image_download_failure_exit_code(image_output: Option<&str>) -> Option<i32> {
    image_output.map(|_| 1)
}

/// Download any generated images, report a failure, and return the exit code
/// the command must terminate with (`None` = carry on).
///
/// The only supported way to reach the downloader: the `--image-output`
/// contract has to hold on all three command paths (`open <url>`, `get`, and
/// the default prompt run), and this fork is rebased onto upstream repeatedly.
/// One wrapper means a rebase cannot leave the check on two paths and drop it
/// from the third — the structural test in this module enforces that.
///
/// The exit code is returned rather than taken here so callers can finish
/// writing the artifacts they already promised (`--output`) before dying.
fn download_images_and_exit_code(
    config_path: &str,
    provider: Provider,
    image_output: Option<&str>,
    verbose: bool,
) -> Option<i32> {
    match download_images_from_latest_message(config_path, provider, image_output, verbose) {
        Ok(()) => None,
        Err(e) => {
            eprintln!("Error downloading images: {}", e);
            image_download_failure_exit_code(image_output)
        }
    }
}

/// Collect the answer a prompt run waited for, and say whether one arrived.
///
/// Two shapes of run end with nothing in hand: the stream was still generating
/// when `--timeout` expired, and the toolbar copy failed. Both used to print a
/// line to stderr and fall through, leaving the epilogue to write an empty
/// `--output` file and exit 0 — and the caller's contract is to check the exit
/// status and then read that file back, so a zero over an empty file reads as
/// "the answer was empty", not "there was no answer". The empty string is still
/// returned, because the file was promised and must still be produced; the flag
/// is what the epilogue turns into a non-zero exit.
///
/// Test seam: the toolbar copy is injected, so both failure shapes are testable
/// without a browser.
fn harvest_prompt_answer<C>(provider: Provider, finished: bool, copy: C) -> (String, bool)
where
    C: FnOnce() -> Result<String, String>,
{
    if !finished {
        return (String::new(), false);
    }
    match copy() {
        Ok(content) => (content, true),
        Err(e) => {
            eprintln!(
                "Error copying response from {} toolbar: {}",
                provider.display_name(),
                e
            );
            (String::new(), false)
        }
    }
}

/// Write the Markdown artifacts a prompt run promised, then hand back whichever
/// failure must end the run.
///
/// Ordering of the *work*: a failed `--image-output` must not also cost the
/// caller the `--output` file, which is why the write happens here and the
/// process exit is left to the caller. `open`/`get` already write `--output`
/// before touching images; this keeps the default prompt path in line.
///
/// Ordering of the *exit code* is a separate, deliberate decision, because a
/// process has one exit status and both artifacts can fail in the same run.
/// `--output` carries the command's actual product — the answer — while
/// `--image-output` carries attachments, so when both fail the exit code
/// reports the `--output` failure and the image code is dropped. Nothing is
/// lost by that: both failures print their own line to stderr regardless, so
/// the exit code only has to answer "did every promised artifact arrive?".
///
/// Today the choice is unobservable, because both producers return exactly 1 —
/// `image_download_failure_exit_code` and `markdown_output::write_if_requested`
/// are pinned to that by `both_fatal_artifact_paths_still_use_exit_code_one`.
/// If either ever gains a distinctive code, that test fails and this precedence
/// must be re-decided rather than inherited.
///
/// `answer_arrived` is the third claimant on that one exit status, and it slots
/// between the other two: a `--output` write that failed is the more specific
/// fact about the same artifact (the file the caller is about to read is not
/// there at all), while an answer that never arrived still leaves a readable —
/// if empty — file, and images remain attachments. Its own code is 1 for the
/// same reason as the other two.
fn finish_prompt_artifacts(
    markdown: &str,
    output: Option<&MarkdownOutput>,
    image_exit_code: Option<i32>,
    answer_arrived: bool,
    verbose: bool,
) -> Option<i32> {
    let missing_answer = (!answer_arrived).then_some(1);
    markdown_output::write_if_requested(output, markdown, verbose)
        .or(missing_answer)
        .or(image_exit_code)
}

/// Decode one scanned image into `(extension, bytes)`.
///
/// `Ok(None)` is "this entry carries nothing to write" — no `dataUrl`, or one
/// that is not `<header>,<payload>`. The scan JS only pushes entries whose
/// `dataUrl` already starts with `data:image/`, so neither shape comes from a
/// working browser; they are the defensive cases, and what to do about them is
/// the caller's decision, not this function's.
fn decode_generated_image(img: &Value) -> Result<Option<(&'static str, Vec<u8>)>, String> {
    let Some(data_url) = img["dataUrl"].as_str() else {
        return Ok(None);
    };

    let parts: Vec<&str> = data_url.splitn(2, ',').collect();
    if parts.len() != 2 {
        return Ok(None);
    }

    let header = parts[0];
    let base64_data = parts[1];

    let ext = if header.contains("image/png") {
        "png"
    } else if header.contains("image/jpeg") || header.contains("image/jpg") {
        "jpg"
    } else if header.contains("image/webp") {
        "webp"
    } else {
        "png"
    };

    let decoded = general_purpose::STANDARD
        .decode(base64_data)
        .map_err(|e| format!("Failed to decode base64 data: {}", e))?;

    Ok(Some((ext, decoded)))
}

/// Decode the scanned images and write them out, honouring an explicit
/// `--image-output` destination. Split out of the browser-driven scan above so
/// the destination handling — the part a caller's automation depends on — is
/// reachable without a browser.
///
/// # The `--image-output` contract
///
/// An explicit destination is a promise the caller's automation will read back,
/// exactly as `--output` is for the Markdown (see
/// [`image_download_failure_exit_code`]). So under an explicit destination this
/// either writes **every** scanned image or writes **none** and returns `Err`:
///
/// * an entry with no usable `dataUrl` fails the batch rather than being
///   skipped — previously every entry could be skipped and the function still
///   returned `Ok(())`, so a caller got exit 0 and then read a missing file, or
///   worse, the previous run's file;
/// * decoding happens for the whole batch before the first byte is written, so
///   a failure partway through can no longer leave a half-written set at the
///   path the caller is about to read.
///
/// Without a destination the download is a best-effort extra into `target/`
/// (upstream's behaviour): unusable entries are skipped, and the surviving ones
/// keep their original index in the file name so what does get written is named
/// exactly as before.
fn save_generated_images(images: &[Value], image_output: Option<&str>) -> Result<(), String> {
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let total = images.len();
    let mut decoded_images: Vec<(usize, &'static str, Vec<u8>)> = Vec::new();
    for (idx, img) in images.iter().enumerate() {
        match decode_generated_image(img)? {
            Some((ext, decoded)) => decoded_images.push((idx, ext, decoded)),
            None => {
                if let Some(destination) = image_output {
                    return Err(format!(
                        "Generated image {} of {} carries no usable data: URL, so \
                         the set promised at the --image-output path {} cannot be \
                         written; nothing was written",
                        idx + 1,
                        total,
                        destination
                    ));
                }
            }
        }
    }

    if decoded_images.is_empty()
        && let Some(destination) = image_output
    {
        return Err(format!(
            "None of the {} scanned images could be decoded, so nothing was \
             written to the --image-output path {}",
            total, destination
        ));
    }

    for (idx, ext, decoded) in decoded_images {
        let file_path = match image_output {
            Some(output_str) => {
                let path = std::path::Path::new(output_str);
                let is_dir = path.is_dir()
                    || output_str.ends_with('/')
                    || output_str.ends_with('\\')
                    || path.extension().is_none();

                if is_dir {
                    std::fs::create_dir_all(path)
                        .map_err(|e| format!("Failed to create directory {:?}: {}", path, e))?;
                    path.join(format!("generated_{}_{}.{}", epoch, idx, ext))
                } else {
                    let parent = path.parent().unwrap_or_else(|| std::path::Path::new(""));
                    if !parent.as_os_str().is_empty() {
                        std::fs::create_dir_all(parent).map_err(|e| {
                            format!("Failed to create parent directory {:?}: {}", parent, e)
                        })?;
                    }
                    let file_stem = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .ok_or_else(|| "Invalid file name".to_string())?;
                    let file_ext = path.extension().and_then(|e| e.to_str()).unwrap_or(ext);

                    if total <= 1 {
                        parent.join(format!("{}.{}", file_stem, file_ext))
                    } else {
                        parent.join(format!("{}_{}.{}", file_stem, idx + 1, file_ext))
                    }
                }
            }
            None => {
                std::fs::create_dir_all("target")
                    .map_err(|e| format!("Failed to create target/ directory: {}", e))?;
                std::path::PathBuf::from(format!("target/generated_{}_{}.{}", epoch, idx, ext))
            }
        };

        std::fs::write(&file_path, decoded)
            .map_err(|e| format!("Failed to write image file {:?}: {}", file_path, e))?;

        println!(
            "Downloaded and saved generated image to: {}",
            file_path.to_string_lossy()
        );
    }

    Ok(())
}

/// Display an image in the terminal using kitty's icat protocol.
/// Silently skips if kitty icat is not available.
fn display_image_in_terminal(image_path: &str) {
    let _ = Command::new("kitty").args(["icat", image_path]).status();
}

fn wait_for_attachment_indicator(
    config_path: &str,
    provider: Provider,
    path: &str,
    verbose: bool,
) -> Result<(), String> {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path);
    let file_stem = Path::new(path)
        .file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or(file_name);
    let file_name_json = serde_json::to_string(file_name)
        .map_err(|e| format!("Failed to serialize file name: {}", e))?;
    let file_stem_json = serde_json::to_string(file_stem)
        .map_err(|e| format!("Failed to serialize file stem: {}", e))?;
    let js = r#"() => {
        const fileName = __FILE_NAME__;
        const fileStem = __FILE_STEM__;
        const text = document.body.innerText || '';
        return text.includes(fileName) || text.includes(fileStem);
    }"#
    .replace("__FILE_NAME__", &file_name_json)
    .replace("__FILE_STEM__", &file_stem_json);

    for _ in 0..30 {
        let check_res = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({ "function": js }),
        )?;
        if parse_script_result(&check_res)
            .ok()
            .and_then(|p| p.as_bool())
            .unwrap_or(false)
        {
            if verbose {
                println!(
                    "{} accepted attachment '{}'",
                    provider.display_name(),
                    file_name
                );
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(500));
    }

    Err(format!(
        "Timed out waiting for {} to show attachment '{}'",
        provider.display_name(),
        file_name
    ))
}

fn upload_attachments_via_file_chooser(
    config_path: &str,
    provider: Provider,
    image_paths: &[String],
    file_paths: &[String],
    verbose: bool,
) -> Result<(), String> {
    for (path, verify_filename) in image_paths
        .iter()
        .map(|path| (path, false))
        .chain(file_paths.iter().map(|path| (path, true)))
    {
        let canonical_path = std::fs::canonicalize(path)
            .map_err(|e| format!("Failed to resolve file '{}': {}", path, e))?;
        let file_path = canonical_path.to_string_lossy().to_string();

        let snapshot = take_snapshot_text(config_path)?;
        let menu_uid = match provider {
            Provider::Gemini => {
                find_snapshot_uid(&snapshot, &["上傳與工具"], &["更多", "雲端", "drive"])
                    .or_else(|| find_snapshot_uid(&snapshot, &["upload"], &["drive"]))
            }
            Provider::ChatGpt => find_snapshot_uid(&snapshot, &["attach"], &["settings", "menu"]),
            Provider::Claude => find_snapshot_uid(&snapshot, &["attach"], &["settings", "menu"])
                .or_else(|| find_snapshot_uid(&snapshot, &["upload"], &["drive"])),
        }
        .ok_or_else(|| {
            format!(
                "Could not find {} upload menu in page snapshot",
                provider.display_name()
            )
        })?;

        call_mcp_tool(
            config_path,
            "click",
            serde_json::json!({
                "uid": menu_uid,
                "includeSnapshot": false
            }),
        )?;
        thread::sleep(Duration::from_millis(500));

        let snapshot = take_snapshot_text(config_path)?;
        let upload_uid = match provider {
            Provider::Gemini => find_snapshot_uid(&snapshot, &["上傳檔案"], &["雲端", "drive"])
                .or_else(|| find_snapshot_uid(&snapshot, &["upload", "file"], &["drive"])),
            Provider::ChatGpt => find_snapshot_uid(&snapshot, &["file"], &["drive", "connect"]),
            Provider::Claude => {
                find_snapshot_uid(&snapshot, &["upload", "file"], &["drive", "connect"])
                    .or_else(|| find_snapshot_uid(&snapshot, &["file"], &["drive", "connect"]))
            }
        }
        .unwrap_or_else(|| menu_uid.clone());

        if verbose {
            println!(
                "Uploading attachment '{}' to {}...",
                file_path,
                provider.display_name()
            );
        }
        call_mcp_tool(
            config_path,
            "upload_file",
            serde_json::json!({
                "uid": upload_uid,
                "filePath": file_path,
                "includeSnapshot": false
            }),
        )?;
        if verify_filename {
            wait_for_attachment_indicator(config_path, provider, path, verbose)?;
        } else {
            thread::sleep(Duration::from_millis(800));
        }
    }

    Ok(())
}

/// Map a file extension to a MIME type. Covers common image and document formats.
/// `ext` is expected to already be lowercased by the caller.
fn mime_type_for_extension(ext: &str) -> &'static str {
    match ext {
        // Images
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "bmp" => "image/bmp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        // Documents
        "pdf" => "application/pdf",
        "doc" => "application/msword",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xls" => "application/vnd.ms-excel",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "ppt" => "application/vnd.ms-powerpoint",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "odt" => "application/vnd.oasis.opendocument.text",
        "ods" => "application/vnd.oasis.opendocument.spreadsheet",
        "odp" => "application/vnd.oasis.opendocument.presentation",
        "rtf" => "application/rtf",
        "csv" => "text/csv",
        "tsv" => "text/tab-separated-values",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "html" | "htm" => "text/html",
        "xml" => "application/xml",
        "json" => "application/json",
        "yaml" | "yml" => "text/yaml",
        "ts" => "text/typescript",
        "tsx" => "text/typescript",
        "js" | "mjs" | "cjs" => "text/javascript",
        "jsx" => "text/javascript",
        "css" => "text/css",
        "py" => "text/x-python",
        "rb" => "text/x-ruby",
        "go" => "text/x-go",
        "rs" => "text/x-rust",
        "java" => "text/x-java",
        "kt" => "text/x-kotlin",
        "c" => "text/x-c",
        "h" => "text/x-c",
        "cpp" | "cc" | "cxx" => "text/x-c++",
        "hpp" => "text/x-c++",
        "cs" => "text/x-csharp",
        "swift" => "text/x-swift",
        "php" => "text/x-php",
        "sh" => "application/x-sh",
        "bash" => "application/x-sh",
        "zsh" => "application/x-sh",
        "sql" => "application/sql",
        "toml" => "application/toml",
        "ini" => "text/plain",
        "log" => "text/plain",
        // Archives
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "bz2" => "application/x-bzip2",
        "7z" => "application/x-7z-compressed",
        // Audio
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "m4a" => "audio/mp4",
        "flac" => "audio/flac",
        "ogg" => "audio/ogg",
        // Video
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        _ => "application/octet-stream",
    }
}

/// Upload local image and/or document files to the provider prompt composer using the
/// best available provider-specific upload mechanism.
/// Returns an error string if any attachment fails to upload.
fn upload_attachments_to_provider(
    config_path: &str,
    provider: Provider,
    image_paths: &[String],
    file_paths: &[String],
    verbose: bool,
) -> Result<(), String> {
    let total = image_paths.len() + file_paths.len();
    if total == 0 {
        return Ok(());
    }

    let data_transfer_image_paths: &[String] = if provider == Provider::Gemini
        && !image_paths.is_empty()
    {
        match upload_attachments_via_file_chooser(config_path, provider, image_paths, &[], verbose)
        {
            Ok(()) => &[],
            Err(e) => {
                if verbose {
                    eprintln!(
                        "Warning: {} image file chooser upload failed, trying DataTransfer fallback: {}",
                        provider.display_name(),
                        e
                    );
                }
                image_paths
            }
        }
    } else {
        image_paths
    };

    let data_transfer_total = data_transfer_image_paths.len() + file_paths.len();
    if data_transfer_total == 0 {
        return Ok(());
    }

    if verbose {
        println!(
            "Attaching {} attachment(s) ({} image(s), {} file(s)) to the prompt...",
            data_transfer_total,
            data_transfer_image_paths.len(),
            file_paths.len()
        );
    }

    // Build a JSON array of { name, mime, base64 } objects. Images first, then other files.
    // We pass raw base64 + mime and decode in JS to avoid `fetch(data:...)` which ChatGPT's
    // Content-Security-Policy blocks (results in "Failed to fetch").
    let mut files_json = Vec::new();
    for path in data_transfer_image_paths.iter().chain(file_paths.iter()) {
        let bytes =
            std::fs::read(path).map_err(|e| format!("Failed to read file '{}': {}", path, e))?;
        let ext = Path::new(path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        let mime = mime_type_for_extension(&ext);
        let b64 = general_purpose::STANDARD.encode(&bytes);
        let file_name = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("attachment")
            .to_string();
        files_json.push(serde_json::json!({
            "name": file_name,
            "mime": mime,
            "base64": b64
        }));
    }

    let files_json_str = serde_json::to_string(&files_json)
        .map_err(|e| format!("Failed to serialize attachment data: {}", e))?;
    let composer_selectors = provider.composer_selectors_json();
    // Build JS without raw strings to avoid r#"..."# termination conflicts
    let js = "() => {\n".to_string()
        + "    window.__upload_images_status = 'pending';\n"
        + "    (async () => {\n"
        + "        try {\n"
        + &format!("            const filesData = {};\n", files_json_str)
        + "            const decodeB64 = (b64) => {\n"
        + "                const bin = atob(b64);\n"
        + "                const len = bin.length;\n"
        + "                const bytes = new Uint8Array(len);\n"
        + "                for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);\n"
        + "                return bytes;\n"
        + "            };\n"
        + "            const fileObjects = filesData.map((f) => {\n"
        + "                const bytes = decodeB64(f.base64);\n"
        + "                const blob = new Blob([bytes], { type: f.mime || 'application/octet-stream' });\n"
        + "                return new File([blob], f.name, { type: blob.type });\n"
        + "            });\n"
        + &format!(
            "            const composerSelectors = {};\n",
            composer_selectors
        )
        + "            const el = composerSelectors.map((s) => document.querySelector(s)).find(Boolean);\n"
        + "            if (!el) {\n"
        + "                window.__upload_images_status = 'error: composer not found';\n"
        + "                return;\n"
        + "            }\n"
        + "            el.focus();\n"
        + "            const fileInputs = Array.from(document.querySelectorAll('input[type=\"file\"]'));\n"
        + "            // Pick the file input whose `accept` attribute covers every attached file.\n"
        + "            // An input accepts a file when accept is empty, contains `*/*` or a matching\n"
        + "            // wildcard (e.g. `image/*`), or lists the file's exact MIME type.\n"
        + "            const accepts = (input, file) => {\n"
        + "                const acc = (input.getAttribute('accept') || '').trim();\n"
        + "                if (!acc) return true;\n"
        + "                const parts = acc.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);\n"
        + "                const mime = (file.type || '').toLowerCase();\n"
        + "                const top = mime.split('/')[0];\n"
        + "                return parts.some(p => p === '*/*' || p === mime || (p.endsWith('/*') && top && p === top + '/*'));\n"
        + "            };\n"
        + "            const fileInput = fileInputs.find(i => fileObjects.every(f => accepts(i, f)))\n"
        + "                || fileInputs.find(i => !i.getAttribute('accept'))\n"
        + "                || fileInputs[0];\n"
        + "            if (fileInput) {\n"
        + "                const dt = new DataTransfer();\n"
        + "                for (const f of fileObjects) dt.items.add(f);\n"
        + "                fileInput.files = dt.files;\n"
        + "                fileInput.dispatchEvent(new Event('change', { bubbles: true }));\n"
        + "                window.__upload_images_status = 'success:file-input';\n"
        + "                return;\n"
        + "            }\n"
        + "            const dt = new DataTransfer();\n"
        + "            for (const f of fileObjects) dt.items.add(f);\n"
        + "            const targets = [el, el.closest('form'), document.querySelector('main'), document.body].filter(Boolean);\n"
        + "            for (const target of targets) {\n"
        + "                for (const type of ['dragenter', 'dragover', 'drop']) {\n"
        + "                    target.dispatchEvent(new DragEvent(type, {\n"
        + "                        bubbles: true, cancelable: true, dataTransfer: dt\n"
        + "                    }));\n"
        + "                }\n"
        + "            }\n"
        + "            const pasteEvent = new ClipboardEvent('paste', {\n"
        + "                bubbles: true, cancelable: true, clipboardData: dt\n"
        + "            });\n"
        + "            el.dispatchEvent(pasteEvent);\n"
        + "            window.__upload_images_status = 'success:drop';\n"
        + "        } catch (e) {\n"
        + "            window.__upload_images_status = 'error: ' + e.message;\n"
        + "        }\n"
        + "    })();\n"
        + "    return true;\n"
        + "}";

    let start_res = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({ "function": js }),
    )?;

    let start_parsed = parse_script_result(&start_res)?;
    if !start_parsed.as_bool().unwrap_or(false) {
        return Err("Failed to initiate attachment upload script".to_string());
    }

    // Poll for completion. Allow up to ~60s for large document uploads.
    let mut wait_cycles = 0;
    let mut status = String::from("pending");
    while status == "pending" && wait_cycles < 300 {
        thread::sleep(Duration::from_millis(200));
        let check_res = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({ "function": "() => window.__upload_images_status || 'pending'" }),
        )?;
        if let Some(s) = parse_script_result(&check_res)
            .ok()
            .and_then(|p| p.as_str().map(|r| r.to_string()))
        {
            status = s;
        }
        wait_cycles += 1;
    }

    if status.starts_with("error:") {
        return Err(format!("Attachment upload failed: {}", status));
    }
    if status == "pending" {
        return Err("Timed out waiting for attachments to upload".to_string());
    }

    if verbose {
        println!("Attachments attached successfully ({})", status);
    }

    // Give the UI a moment to render the attachments before typing the prompt
    thread::sleep(Duration::from_millis(800));

    if provider == Provider::Gemini {
        // Gemini renders image attachments as thumbnails without a stable filename in
        // the accessible text. Text/document chips do expose their filename, so keep
        // the stricter post-upload check for `--file` attachments only.
        for path in file_paths {
            if let Err(e) = wait_for_attachment_indicator(config_path, provider, path, verbose) {
                if verbose {
                    eprintln!(
                        "Warning: {} DataTransfer upload was not detected, trying file chooser fallback: {}",
                        provider.display_name(),
                        e
                    );
                }
                return upload_attachments_via_file_chooser(
                    config_path,
                    provider,
                    image_paths,
                    file_paths,
                    verbose,
                );
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
enum SelectionKind {
    Model,
    Reasoning,
}

impl SelectionKind {
    fn display_name(self) -> &'static str {
        match self {
            SelectionKind::Model => "model",
            SelectionKind::Reasoning => "reasoning",
        }
    }
}

fn switch_semantic_option(
    config_path: &str,
    provider: Provider,
    target_aliases: &[&str],
    verification_aliases: &[&str],
    kind: SelectionKind,
    verbose: bool,
) -> Result<(), String> {
    if provider == Provider::Claude {
        return Err("Semantic option selection is not supported for Claude".to_string());
    }
    let primary_target = target_aliases
        .first()
        .ok_or_else(|| format!("No {} target was provided", kind.display_name()))?;
    if verification_aliases.is_empty() {
        return Err(format!(
            "No {} verification aliases were provided",
            kind.display_name()
        ));
    }

    let request = serde_json::json!({
        "provider": provider.to_string(),
        "targetAliases": target_aliases,
        "verificationAliases": verification_aliases,
    });
    let request_json = serde_json::to_string(&request)
        .map_err(|error| format!("Failed to serialize selection request: {error}"))?;
    let helper = include_str!("model-selection.cjs");
    let js = format!(
        r#"() => {{
            {helper}
            window.__ask_bridge_selection_status = 'pending';
            (async () => {{
                try {{
                    const result = await globalThis.AskBridgeModelSelection.selectProviderOption({request_json});
                    if (result.ok) {{
                        window.__ask_bridge_selection_status = 'success:' + result.selected;
                    }} else {{
                        const available = result.available && result.available.length
                            ? '; available options: ' + result.available.join(', ')
                            : '';
                        window.__ask_bridge_selection_status = 'error: ' + result.error + available;
                    }}
                }} catch (error) {{
                    window.__ask_bridge_selection_status = 'error: ' + error.message;
                }}
            }})();
            return true;
        }}"#
    );

    if verbose {
        println!(
            "Switching {} {} to '{}'...",
            provider.display_name(),
            kind.display_name(),
            primary_target
        );
    }

    let start_result = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({ "function": js }),
    )?;
    let start_parsed = parse_script_result(&start_result)?;
    if !start_parsed.as_bool().unwrap_or(false) {
        return Err(format!(
            "Failed to initiate {} switch script",
            kind.display_name()
        ));
    }

    let mut wait_cycles = 0;
    let mut status = String::from("pending");
    // ChatGPT may wait up to 5s for the picker and traverse six nested levels
    // twice when post-click verification must reopen the menu.
    while status == "pending" && wait_cycles < 180 {
        thread::sleep(Duration::from_millis(200));
        let check_result = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({
                "function": "() => window.__ask_bridge_selection_status || 'pending'"
            }),
        )?;
        status = parse_script_result(&check_result)?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("Invalid {} switch status", kind.display_name()))?;
        wait_cycles += 1;
    }

    if status.starts_with("error:") {
        return Err(format!("{} switch failed: {}", kind.display_name(), status));
    }
    if status == "pending" {
        return Err(format!(
            "Timed out waiting for {} switch",
            kind.display_name()
        ));
    }
    if !status.starts_with("success:") {
        return Err(format!(
            "Unexpected {} switch status: {status}",
            kind.display_name()
        ));
    }

    if verbose {
        println!("{} switched successfully ({status})", kind.display_name());
    }
    thread::sleep(Duration::from_millis(500));

    Ok(())
}

fn claude_model_switch_script(target_json: &str) -> String {
    let template = r#"() => {
        window.__switch_model_status = 'pending';
        (async () => {
            try {
                const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
                const norm = (s) => (s || '').toLowerCase().replace(/[\s.\-_]/g, '');
                const labelOf = (el) => ((el.innerText || el.textContent || '').split('\n')[0] || '').trim();
                const target = norm(__TARGET_MODEL__);
                if (!target) { window.__switch_model_status = 'error: empty target'; return; }
                document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', keyCode: 27, bubbles: true }));
                await sleep(300);
                let trigger = document.querySelector('[data-testid="model-selector-dropdown"]');
                if (!trigger) {
                    trigger = Array.from(document.querySelectorAll('button')).find((button) => {
                        const popup = button.getAttribute('aria-haspopup');
                        if (popup !== 'menu' && popup !== 'listbox') return false;
                        const label = [button.getAttribute('aria-label'), button.textContent].filter(Boolean).join(' ');
                        return /model|claude|opus|sonnet|haiku|fable/i.test(label);
                    });
                }
                if (!trigger) { window.__switch_model_status = 'error: Claude model selector not found'; return; }
                trigger.click();
                await sleep(800);
                const visited = new Set();
                let clicked = false;
                let chosen = '';
                for (let depth = 0; depth < 4 && !clicked; depth++) {
                    const items = Array.from(document.querySelectorAll('[role="menuitem"], [role="option"], [role="menuitemradio"]'));
                    const leaves = items.filter((it) => it.getAttribute('aria-haspopup') !== 'menu');
                    let match = leaves.find((it) => norm(labelOf(it)) === target);
                    if (!match) match = leaves.find((it) => norm(labelOf(it)).startsWith(target));
                    if (match) {
                        match.click();
                        clicked = true;
                        chosen = labelOf(match);
                        break;
                    }
                    const trigs = items.filter((it) => it.getAttribute('aria-haspopup') === 'menu');
                    const trig = trigs.find((it) => !visited.has(norm(it.innerText)));
                    if (!trig) break;
                    visited.add(norm(trig.innerText));
                    trig.dispatchEvent(new MouseEvent('pointerenter', { bubbles: true }));
                    trig.dispatchEvent(new MouseEvent('mouseover', { bubbles: true }));
                    trig.click();
                    await sleep(700);
                }
                document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', keyCode: 27, bubbles: true }));
                if (!clicked) {
                    window.__switch_model_status = 'error: model not found in menu';
                    return;
                }
                await sleep(400);
                window.__switch_model_status = 'success:' + chosen;
            } catch (e) {
                window.__switch_model_status = 'error: ' + e.message;
            }
        })();
        return true;
    }"#;
    template.replace("__TARGET_MODEL__", target_json)
}

/// Switch the selected provider to the specified model. ChatGPT and Gemini use
/// exact primary-label matching; Claude retains its existing selector path.
fn switch_model(
    config_path: &str,
    provider: Provider,
    model: &str,
    verbose: bool,
) -> Result<(), String> {
    if model.trim().is_empty() {
        return Err("Empty model name".to_string());
    }
    if provider != Provider::Claude {
        return switch_semantic_option(
            config_path,
            provider,
            &[model.trim()],
            &[model.trim()],
            SelectionKind::Model,
            verbose,
        );
    }
    let target_json = serde_json::to_string(model.trim())
        .map_err(|e| format!("Failed to serialize model name: {}", e))?;

    if verbose {
        println!(
            "Switching {} model to '{}'...",
            provider.display_name(),
            model.trim()
        );
    }

    let js = claude_model_switch_script(&target_json);

    let start_res = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({ "function": js }),
    )?;
    let start_parsed = parse_script_result(&start_res)?;
    if !start_parsed.as_bool().unwrap_or(false) {
        return Err("Failed to initiate model switch script".to_string());
    }

    let mut wait_cycles = 0;
    let mut status = String::from("pending");
    while status == "pending" && wait_cycles < 60 {
        thread::sleep(Duration::from_millis(200));
        let check_res = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({ "function": "() => window.__switch_model_status || 'pending'" }),
        )?;
        if let Some(s) = parse_script_result(&check_res)
            .ok()
            .and_then(|p| p.as_str().map(|r| r.to_string()))
        {
            status = s;
        }
        wait_cycles += 1;
    }

    if status.starts_with("error:") {
        return Err(format!("Model switch failed: {}", status));
    }
    if status == "pending" {
        return Err("Timed out waiting for model switch".to_string());
    }

    if verbose {
        println!("Model switched successfully ({})", status);
    }

    // Give the UI a moment to settle after switching models
    thread::sleep(Duration::from_millis(500));

    Ok(())
}

fn switch_reasoning(
    config_path: &str,
    provider: Provider,
    reasoning: ReasoningRequest,
    verbose: bool,
) -> Result<(), String> {
    switch_semantic_option(
        config_path,
        provider,
        reasoning.target_aliases(),
        reasoning.verification_aliases(),
        SelectionKind::Reasoning,
        verbose,
    )
}

fn wait_for_submit_status(config_path: &str) -> Result<String, String> {
    let mut wait_cycles = 0;
    let mut status = String::from("pending");

    // Page-side submission scripts may wait up to 15s for ChatGPT/Gemini to
    // enable the send button, so keep this host-side polling window longer.
    while status == "pending" && wait_cycles < 180 {
        thread::sleep(Duration::from_millis(100));
        let check_res = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({
                "function": "() => window.__submit_status || 'pending'"
            }),
        )?;
        if let Some(s) = parse_script_result(&check_res)
            .ok()
            .and_then(|p| p.as_str().map(|str_ref| str_ref.to_string()))
        {
            status = s;
        }
        wait_cycles += 1;
    }

    if status.starts_with("error:") {
        return Err(status);
    }

    if status == "pending" {
        return Err("Timed out waiting for send button to activate and submit".to_string());
    }

    Ok(status)
}

fn focus_and_clear_composer(config_path: &str, provider: Provider) -> Result<(), String> {
    let js = r#"() => {
            const composerSelectors = __COMPOSER_SELECTORS__;
            const el = composerSelectors.map((s) => document.querySelector(s)).find(Boolean);
            if (!el) {
                return { ok: false, error: 'composer not found' };
            }

            el.focus();
            try {
                const range = document.createRange();
                range.selectNodeContents(el);
                const sel = window.getSelection();
                sel.removeAllRanges();
                sel.addRange(range);
                document.execCommand('delete');
            } catch (e) {}

            const currentText = typeof el.value !== 'undefined' ? el.value : (el.innerText || el.textContent || '');
            if ((currentText || '').trim().length > 0) {
                if (typeof el.value !== 'undefined') {
                    el.value = '';
                    if (el._valueTracker) {
                        el._valueTracker.setValue('');
                    }
                } else {
                    el.innerHTML = '<p><br></p>';
                }
                el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'deleteContentBackward' }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
            }

            el.focus();
            return { ok: true };
        }"#
    .replace("__COMPOSER_SELECTORS__", provider.composer_selectors_json());

    let res = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({ "function": js }),
    )?;
    let parsed = parse_script_result(&res)?;
    if parsed
        .get("ok")
        .and_then(|ok| ok.as_bool())
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(parsed
            .get("error")
            .and_then(|err| err.as_str())
            .unwrap_or("failed to focus and clear composer")
            .to_string())
    }
}

fn wait_for_chatgpt_agent_menu(config_path: &str) -> Result<(), String> {
    let js = r#"() => {
            const isVisible = (el) => {
                if (!el) return false;
                const style = window.getComputedStyle(el);
                if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
                const rect = el.getBoundingClientRect();
                return rect.width > 0 && rect.height > 0;
            };
            const composer = document.querySelector('#prompt-textarea');
            const composerRect = composer ? composer.getBoundingClientRect() : null;
            const isNearComposer = (el) => {
                if (!composerRect) return true;
                const rect = el.getBoundingClientRect();
                const itemCenterX = (rect.left + rect.right) / 2;
                const composerCenterX = (composerRect.left + composerRect.right) / 2;
                const maxHorizontalDistance = Math.max(500, composerRect.width);
                return Math.abs(itemCenterX - composerCenterX) <= maxHorizontalDistance &&
                    Math.abs(rect.top - composerRect.bottom) <= 500;
            };
            const items = Array.from(document.querySelectorAll(
                '.popover .__menu-item, [class*="popover"] .__menu-item, [role="menuitem"], [role="option"], [cmdk-item]'
            ))
                .filter((el) => isVisible(el) && isNearComposer(el))
                .map((el) => (el.innerText || el.textContent || '').trim())
                .filter(Boolean);

            return { ok: items.length > 0, items: items.slice(0, 5) };
        }"#;

    let mut last_state = String::new();
    for _ in 0..40 {
        thread::sleep(Duration::from_millis(125));
        let res = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({ "function": js }),
        )?;
        let parsed = parse_script_result(&res)?;
        if parsed
            .get("ok")
            .and_then(|ok| ok.as_bool())
            .unwrap_or(false)
        {
            return Ok(());
        }
        last_state = parsed.to_string();
    }

    Err(format!(
        "Timed out waiting for ChatGPT agent menu after typing mention ({})",
        last_state
    ))
}

fn wait_for_chatgpt_agent_selection(config_path: &str) -> Result<(), String> {
    let js = r#"() => {
            const composer = document.querySelector('#prompt-textarea');
            if (!composer) {
                return { ok: false, error: 'composer not found' };
            }
            const agentPill = composer.querySelector(
                '[data-id="agent"], [data-system-hint-type="agent"], [data-symbol="ecosystemMention"], [data-inline-selection-pill][contenteditable="false"]'
            );
            return {
                ok: Boolean(agentPill),
                text: (composer.innerText || composer.textContent || '').trim(),
                keyword: agentPill ? (agentPill.getAttribute('data-keyword') || agentPill.textContent || '').trim() : ''
            };
        }"#;

    let mut last_state = String::new();
    for _ in 0..40 {
        thread::sleep(Duration::from_millis(125));
        let res = call_mcp_tool(
            config_path,
            "evaluate_script",
            serde_json::json!({ "function": js }),
        )?;
        let parsed = parse_script_result(&res)?;
        if parsed
            .get("ok")
            .and_then(|ok| ok.as_bool())
            .unwrap_or(false)
        {
            return Ok(());
        }
        last_state = parsed.to_string();
    }

    Err(format!(
        "Timed out waiting for ChatGPT agent selection after Tab ({})",
        last_state
    ))
}

fn submit_regular_prompt(
    config_path: &str,
    provider: Provider,
    prompt: &str,
) -> Result<String, String> {
    let prompt_json = serde_json::to_string(prompt)
        .map_err(|e| format!("Failed to serialize prompt text: {}", e))?;
    let set_and_submit_js = r#"() => {
            window.__submit_status = 'pending';
            (async () => {
                try {
                    const composerSelectors = __COMPOSER_SELECTORS__;
                    const sendSelectors = __SEND_SELECTORS__;
                    const el = composerSelectors.map((s) => document.querySelector(s)).find(Boolean);
                    if (!el) {
                        window.__submit_status = 'error: composer not found';
                        return;
                    }
                    el.focus();

                    const value = __PROMPT__;
                    el.focus();

                    try {
                        const range = document.createRange();
                        range.selectNodeContents(el);
                        const sel = window.getSelection();
                        sel.removeAllRanges();
                        sel.addRange(range);
                    } catch (e) {}

                    let pasted = false;
                    try {
                        const dataTransfer = new DataTransfer();
                        dataTransfer.setData('text/plain', value);
                        const event = new ClipboardEvent('paste', {
                            bubbles: true,
                            cancelable: true
                        });
                        Object.defineProperty(event, 'clipboardData', {
                            value: dataTransfer,
                            writable: false,
                            configurable: true
                        });
                        el.dispatchEvent(event);

                        const currentText = typeof el.value !== 'undefined' ? el.value : el.textContent;
                        if (currentText && currentText.trim().length > 0) {
                            pasted = true;
                        }
                    } catch (e) {}

                    if (!pasted) {
                        const success = document.execCommand('insertText', false, value);
                        if (!success) {
                            if (typeof el.value !== 'undefined') {
                                el.value = value;
                                if (el._valueTracker) {
                                    el._valueTracker.setValue('');
                                }
                            } else {
                                el.innerText = value;
                            }
                            el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: value }));
                            el.dispatchEvent(new Event('change', { bubbles: true }));
                        }
                    }

                    const isVisible = (el) => {
                        if (!el || el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
                        const rect = el.getBoundingClientRect();
                        return rect.width > 0 && rect.height > 0;
                    };
                    const findAndClickSendButton = () => {
                        let btn = null;
                        for (const s of sendSelectors) {
                            btn = document.querySelector(s);
                            if (isVisible(btn)) break;
                        }

                        if (btn && !btn.disabled && btn.getAttribute('aria-disabled') !== 'true') {
                            btn.click();
                            return { ok: true, clicked: true, buttonLabel: btn.getAttribute('aria-label') };
                        }
                        return null;
                    };

                    let result = findAndClickSendButton();
                    if (result) {
                        window.__submit_status = 'success:' + JSON.stringify(result);
                        return;
                    }

                    for (let i = 0; i < 150; i++) {
                        await new Promise(r => setTimeout(r, 100));
                        result = findAndClickSendButton();
                        if (result) {
                            window.__submit_status = 'success:' + JSON.stringify(result);
                            return;
                        }
                    }

                    window.__submit_status = 'error: Send button did not become active/enabled';
                } catch (e) {
                    window.__submit_status = 'error: ' + e.message;
                }
            })();
            return true;
        }"#
    .replace("__COMPOSER_SELECTORS__", provider.composer_selectors_json())
    .replace("__SEND_SELECTORS__", provider.send_button_selectors_json())
    .replace("__PROMPT__", &prompt_json);

    let start_res = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({
            "function": set_and_submit_js
        }),
    )?;

    let start_parsed = parse_script_result(&start_res)?;
    if !start_parsed.as_bool().unwrap_or(false) {
        return Err("Failed to initiate text entry and submission script".to_string());
    }

    wait_for_submit_status(config_path)
}

fn submit_chatgpt_agent_prompt(
    config_path: &str,
    parts: &ChatGptAgentPrompt<'_>,
    verbose: bool,
) -> Result<String, String> {
    if verbose {
        println!(
            "Selecting ChatGPT agent '{}' before submitting prompt...",
            parts.agent_mention
        );
    }

    focus_and_clear_composer(config_path, Provider::ChatGpt)?;
    call_mcp_tool(
        config_path,
        "type_text",
        serde_json::json!({
            "text": parts.agent_mention
        }),
    )?;
    wait_for_chatgpt_agent_menu(config_path)?;
    call_mcp_tool(
        config_path,
        "press_key",
        serde_json::json!({
            "key": "Tab",
            "includeSnapshot": false
        }),
    )?;
    wait_for_chatgpt_agent_selection(config_path)?;

    let body_json = serde_json::to_string(parts.body)
        .map_err(|e| format!("Failed to serialize prompt body: {}", e))?;
    let paste_and_submit_js = r#"() => {
            window.__submit_status = 'pending';
            (async () => {
                try {
                    const sendSelectors = __SEND_SELECTORS__;
                    const el = document.querySelector('#prompt-textarea');
                    if (!el) {
                        window.__submit_status = 'error: composer not found';
                        return;
                    }
                    const agentPill = el.querySelector(
                        '[data-id="agent"], [data-system-hint-type="agent"], [data-symbol="ecosystemMention"], [data-inline-selection-pill][contenteditable="false"]'
                    );
                    if (!agentPill) {
                        window.__submit_status = 'error: ChatGPT agent was not selected into the composer';
                        return;
                    }

                    const body = __BODY__;
                    const currentText = el.textContent || '';
                    const value = currentText && !/\s$/.test(currentText) ? ' ' + body : body;
                    el.focus();

                    try {
                        const range = document.createRange();
                        range.selectNodeContents(el);
                        range.collapse(false);
                        const sel = window.getSelection();
                        sel.removeAllRanges();
                        sel.addRange(range);
                    } catch (e) {}

                    let pasted = false;
                    try {
                        const dataTransfer = new DataTransfer();
                        dataTransfer.setData('text/plain', value);
                        const event = new ClipboardEvent('paste', {
                            bubbles: true,
                            cancelable: true
                        });
                        Object.defineProperty(event, 'clipboardData', {
                            value: dataTransfer,
                            writable: false,
                            configurable: true
                        });
                        el.dispatchEvent(event);
                        const afterPasteText = el.innerText || el.textContent || '';
                        pasted = afterPasteText.includes(body);
                    } catch (e) {}

                    if (!pasted) {
                        const success = document.execCommand('insertText', false, value);
                        if (!success) {
                            el.appendChild(document.createTextNode(value));
                            el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: value }));
                            el.dispatchEvent(new Event('change', { bubbles: true }));
                        }
                    }

                    const afterText = el.innerText || el.textContent || '';
                    if (!afterText.includes(body)) {
                        window.__submit_status = 'error: prompt body was not pasted after ChatGPT agent selection';
                        return;
                    }

                    const isVisible = (el) => {
                        if (!el || el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
                        const rect = el.getBoundingClientRect();
                        return rect.width > 0 && rect.height > 0;
                    };
                    const findAndClickSendButton = () => {
                        let btn = null;
                        for (const s of sendSelectors) {
                            btn = document.querySelector(s);
                            if (isVisible(btn)) break;
                        }
                        if (btn && !btn.disabled && btn.getAttribute('aria-disabled') !== 'true') {
                            btn.click();
                            return { ok: true, clicked: true, buttonLabel: btn.getAttribute('aria-label') };
                        }
                        return null;
                    };

                    let result = findAndClickSendButton();
                    if (result) {
                        window.__submit_status = 'success:' + JSON.stringify(result);
                        return;
                    }

                    for (let i = 0; i < 150; i++) {
                        await new Promise(r => setTimeout(r, 100));
                        result = findAndClickSendButton();
                        if (result) {
                            window.__submit_status = 'success:' + JSON.stringify(result);
                            return;
                        }
                    }

                    window.__submit_status = 'error: Send button did not become active/enabled';
                } catch (e) {
                    window.__submit_status = 'error: ' + e.message;
                }
            })();
            return true;
        }"#
    .replace(
        "__SEND_SELECTORS__",
        Provider::ChatGpt.send_button_selectors_json(),
    )
    .replace("__BODY__", &body_json);

    let start_res = call_mcp_tool(
        config_path,
        "evaluate_script",
        serde_json::json!({
            "function": paste_and_submit_js
        }),
    )?;
    let start_parsed = parse_script_result(&start_res)?;
    if !start_parsed.as_bool().unwrap_or(false) {
        return Err("Failed to initiate ChatGPT agent prompt submission script".to_string());
    }

    wait_for_submit_status(config_path)
}

fn submit_prompt_to_provider(
    config_path: &str,
    provider: Provider,
    prompt: &str,
    verbose: bool,
) -> Result<String, String> {
    if provider == Provider::ChatGpt
        && let Some(parts) = parse_chatgpt_agent_prompt(prompt)
    {
        return submit_chatgpt_agent_prompt(config_path, &parts, verbose);
    }

    submit_regular_prompt(config_path, provider, prompt)
}

/// IDs present in `after` that were not in `before_ids` -- i.e. the tabs that
/// appeared since the snapshot. When more than one appeared (a provider popup,
/// a restored session) the provider-owned one wins, so the caller still gets a
/// single unambiguous answer. An empty or still-ambiguous result is the
/// caller's cue to fail rather than guess.
fn fresh_page_ids(before_ids: &[usize], after: &[Page], provider: Provider) -> Vec<usize> {
    let fresh: Vec<usize> = after
        .iter()
        .filter(|p| !before_ids.contains(&p.id))
        .map(|p| p.id)
        .collect();
    if fresh.len() > 1 {
        let owned: Vec<usize> = after
            .iter()
            .filter(|p| {
                fresh.contains(&p.id) && p.url.as_deref().is_some_and(|url| provider.owns_url(url))
            })
            .map(|p| p.id)
            .collect();
        if owned.len() == 1 {
            return owned;
        }
    }
    fresh
}

/// The fresh tab **this** run's `new_page` created, named causally rather than
/// by what its URL looks like.
///
/// [`fresh_page_ids`] answers "which new tab is on the provider", and that is
/// not the same question. Two ask-bridge runs share the browser's page-ID
/// space, so when the other run's tab has already settled on the provider and
/// this run's is still blank, mid-redirect or on the auth host, the only
/// provider-owned fresh ID is the *other* run's -- an answer that reads
/// unambiguous and is wrong in the one way that matters.
///
/// The causal fact is in the listing this client got back. In
/// chrome-devtools-mcp 1.5.0 -- the version [`MCP_PACKAGE_SPEC`] pins -- the
/// `new_page` handler calls `context.newPage()` (tools/pages.js), which ends
/// `this.selectPage(this.#getMcpPage(page))` (McpContext.js:210), and the
/// response it echoes marks that page `[selected]` (McpResponse.js:666, via
/// `isPageSelected`, McpContext.js:387). `#selectedPage` lives on the
/// `McpContext` and is compared by page identity, so it is per-connection and
/// index-free: each ask-bridge run drives its own chrome-devtools-mcp child, and
/// no *explicit* selection made by one child is visible in another's listing.
///
/// That is not the same as "another child's tab is never `[selected]` here",
/// which is what an earlier version of this comment claimed. There is one
/// implicit selection: `McpContext.createPagesSnapshot()` ends with
///
/// ```text
/// if ((!this.#selectedPage || this.#pages.indexOf(...) === -1) && this.#pages[0])
///     this.selectPage(this.#getMcpPage(this.#pages[0]));
/// ```
///
/// so when this client's own selected page is *gone*, the next snapshot selects
/// whatever is first in the list. The reachable shape: run B's `--new` closes
/// run A's tab, and A -- having taken the second `list_pages` because the
/// `new_page` echo was ambiguous -- gets a listing in which B's fresh tab is the
/// first page and therefore `[selected]`, so A reads it as its own. Narrow (it
/// needs the re-list path, B closing A's tab, and A's other tabs gone), not
/// modelled by `FakeMcp`, and it is disclosed rather than closed: closing it
/// needs `new_page` to name the page it created, which is an upstream change to
/// chrome-devtools-mcp -- nothing in the response identifies it today.
///
/// A page whose line ends in a forged `[selected]` (an untitled `data:` URL can
/// carry a space and the marker, see `parse_pages`) does not turn this into a
/// guess either: two claimants is `None`, which the caller must treat as
/// "cannot identify", not as "pick one".
fn created_page_id(before_ids: &[usize], after: &[Page]) -> Option<usize> {
    let claimants: Vec<usize> = after
        .iter()
        .filter(|p| p.selected && !before_ids.contains(&p.id))
        .map(|p| p.id)
        .collect();
    match claimants.as_slice() {
        [id] => Some(*id),
        _ => None,
    }
}

/// Close `ids`, returning `(id, error)` for each tab that refused to close.
///
/// Closing is best effort -- a tab that will not close is no longer a hazard
/// once the replacement tab is pinned by ID -- but the failures are handed back
/// as data rather than dropped inside the loop, and travel out of
/// [`ensure_provider_tab_with`] in [`TabOutcome`] so a test can assert the
/// caller was actually told.
///
/// `#[must_use]` is a nudge, **not** a guarantee: `let _ = close_tabs(..)` is
/// the idiomatic way to silence it and neither `cargo test` nor
/// `clippy -D warnings` would notice. What is genuinely enforced is that the
/// failures reach `TabOutcome`; the final `eprintln!` in `ensure_provider_tab`
/// is a presentation detail no test observes (libtest intercepts `eprintln!`
/// before fd 2, so capturing it is not possible in-process).
#[must_use = "a tab that refused to close must be surfaced, not discarded"]
fn close_tabs<F>(
    call: &mut F,
    ids: &[usize],
    provider: Provider,
    verbose: bool,
) -> Vec<(usize, String)>
where
    F: FnMut(&str, Value) -> Result<Value, String>,
{
    let mut failures = Vec::new();
    for &id in ids {
        if verbose {
            println!(
                "Closing old {} tab (ID: {})...",
                provider.display_name(),
                id
            );
        }
        if let Err(e) = call(
            "close_page",
            serde_json::json!({
                "pageId": id
            }),
        ) {
            failures.push((id, e));
        }
    }
    failures
}

fn ensure_provider_tab(
    config_path: &str,
    provider: Provider,
    force_new: bool,
    headless: bool,
    verbose: bool,
) -> Result<(), String> {
    let outcome = ensure_provider_tab_with(
        &mut |tool: &str, args: Value| call_mcp_tool(config_path, tool, args),
        provider,
        force_new,
        headless,
        verbose,
        READY_POLL_INTERVAL,
    )?;
    for (id, e) in outcome.close_failures {
        eprintln!("Warning: failed to close old tab (ID: {}): {}", id, e);
    }
    Ok(())
}

/// What a tab-preparation run committed to, plus the cleanup it could not
/// finish.
///
/// The failures travel out as data instead of being printed where they happen,
/// so "the caller was told" is an assertion a test can make rather than a claim
/// in a comment.
#[derive(Debug)]
struct TabOutcome {
    close_failures: Vec<(usize, String)>,
}

/// How long to wait between readiness probes while a provider page loads.
const READY_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The probe [`verify_selected_page_is_provider`] sends. `location` is
/// `[LegacyUnforgeable]`, so a page can neither shadow nor redefine it.
const LIVE_URL_PROBE_JS: &str = "() => location.href";

/// Ask the tab that is currently selected who it is, and refuse to go on unless
/// the answer is `provider`.
///
/// This is the second lock on the same door, and deliberately not made of the
/// same material as the first. Everything else in this module learns a tab's
/// identity from [`parse_pages`], i.e. from prose that chrome-devtools-mcp
/// formats and a page partly writes; [`page_url_from_label`] can only ever be
/// as right as its model of how URLs serialise. `location.href` is
/// `[LegacyUnforgeable]` in the HTML spec -- a page cannot shadow, redefine or
/// proxy it -- and `evaluate_script` returns it as JSON rather than as prose,
/// so this answer does not pass through the ambiguous grammar at all.
///
/// # Call sites
///
/// Every path on which a prompt can reach a composer, and what each one is
/// guarding against. The first two are about *identity* -- a tab this run did
/// not choose:
///
/// 1. **Adoption.** A tab inherited from a previous run, identified by reading
///    the listing -- that reading is what is being checked.
/// 2. **An unpinned run.** `new_page` came back without an identifiable fresh
///    ID, so nothing was ever committed to and the readiness probe runs against
///    whichever tab happens to be selected.
///
/// The third prompt-bearing path, `--session`, is about *drift* -- the right
/// tab, at the wrong URL -- and it does **not** use this gate. It has its own,
/// [`verify_session_page_is_provider`], because this one's predicate is wider
/// than the contract [`resolve_session_target`] enforced on the input: it would
/// accept back, after a redirect, the sub-domain and sign-in origins that were
/// refused on the command line. See that function for the argument.
///
/// A `--new` run that pinned a tab it navigated itself is not checked -- both
/// the freshly opened tab and the reused blank tab, which that run navigates to
/// [`Provider::home_url`] before pinning. Neither identity came from the
/// listing, and unlike case 3 the URL is [`Provider::home_url`] itself, a
/// constant rather than user input.
///
/// This enumeration is lexical prose and cannot notice a fourth path being
/// added; `every_prompt_bearing_path_verifies_the_live_url` is the half that
/// can, and it fails if the count here stops matching the source.
///
/// # Why a sign-in origin passes
///
/// [`Provider::owns_auth_url`] is accepted as well as [`Provider::owns_url`],
/// and that is load-bearing rather than lenient. Case 2 is reachable exactly
/// when a logged-out session redirects the fresh tab to a sign-in host *and*
/// something else opened a tab at the same time; refusing there replaced
/// [`check_login_status`]'s actionable "run `ask-bridge login`" message with a
/// bare refusal (measured on Gemini and ChatGPT). Nothing is given away: an
/// attacker cannot serve `auth.openai.com`, and `accounts.google.com` only
/// counts when the URL itself names this provider as its destination.
///
/// The safety here rests on that origin restriction alone. It is tempting to
/// add "and a sign-in page has no composer anyway", but nothing enforces that:
/// [`main`] proceeds on both `Ok(Unknown)` and `Err(_)` from
/// [`check_login_status`], so a page that this gate blesses AND that presents a
/// composer-shaped DOM would be typed into. Widening what passes here widens
/// exactly that -- weigh any future change against the origin check, not
/// against an assumption about the page's contents.
///
/// Failure is an error rather than a silent re-open: the listing having lied
/// about a tab is not a condition to paper over, and the prompt -- which is
/// what gets typed into whatever tab this call blesses -- has not been sent
/// yet.
fn verify_selected_page_is_provider<F>(call: &mut F, provider: Provider) -> Result<(), String>
where
    F: FnMut(&str, Value) -> Result<Value, String>,
{
    let res = call(
        "evaluate_script",
        serde_json::json!({ "function": LIVE_URL_PROBE_JS }),
    )?;
    let href = parse_script_result(&res)?;
    let href = href.as_str().ok_or_else(|| {
        format!(
            "Could not read the URL of the tab picked as {}'s; refusing to drive it",
            provider.display_name()
        )
    })?;
    if provider.owns_url(href) || provider.owns_auth_url(href) {
        return Ok(());
    }
    Err(format!(
        "The tab listed as {}'s reports {} instead; refusing to drive it",
        provider.display_name(),
        href
    ))
}

/// The `--session` variant of [`verify_selected_page_is_provider`]: after
/// navigation, require the same canonical conversation identity the command
/// line selected.
///
/// # Why the generic gate is the wrong one here
///
/// The two gates answer different questions, exactly as
/// [`Provider::owns_url`] and [`Provider::owns_session_origin`] do.
///
/// The generic gate asks "is this tab the provider's?", so it uses the
/// sub-domain rule and additionally accepts a sign-in origin -- both correct
/// for a tab *found* in the browser, and the sign-in arm is load-bearing (see
/// that function's `Why a sign-in origin passes`).
///
/// `--session` asks something narrower: "did the browser stay on the exact
/// conversation this run was told to continue?". [`resolve_session_target`]
/// refuses `https://evil.chatgpt.com/c/x`, `https://chatgpt.com:8443/c/x` and
/// `https://auth.openai.com/...` on the command line. Verifying the landing
/// page with the *generic* predicate accepted all three back again the moment
/// a redirect produced one, which made the input restriction decorative: the
/// prompt is typed into whatever page this call blesses, and [`main`] proceeds
/// through [`check_login_status`] on both `Ok(Unknown)` and `Err(_)`, so a
/// composer-shaped DOM on such a page would be typed into.
///
/// So this gate derives a [`ConversationIdentity`] from both the original
/// target and the live `location.href`, then requires them to match. Query
/// strings and fragments are not part of that identity, and `Url` normalises
/// an explicitly written default port. The provider, conversation ID and
/// explicit route context (including a custom GPT ID or Gemini account index)
/// must remain identical. A bare Gemini `/app/<id>` target may acquire a
/// numeric `/u/N/` selector during navigation because the caller did not choose
/// an account index; the reverse and cross-account cases remain fail-closed.
///
/// # The sign-in landing is reported, not accepted
///
/// A session URL that redirects to this provider's own sign-in origin is the
/// ordinary expired-session case, and it deserves the actionable message
/// [`check_login_status`] would have given rather than a bare refusal. It gets
/// one -- but as an error that stops the run, not as a pass. The prompt is
/// never typed either way; only the wording differs.
fn verify_session_page_is_provider<F>(
    call: &mut F,
    provider: Provider,
    expected_href: &str,
) -> Result<(), String>
where
    F: FnMut(&str, Value) -> Result<Value, String>,
{
    let expected_url = Url::parse(expected_href).map_err(|_| {
        format!(
            "Could not identify the requested {} conversation from {}; refusing to drive it",
            provider.display_name(),
            expected_href
        )
    })?;
    let expected_identity = provider
        .conversation_identity(&expected_url)
        .ok_or_else(|| {
            format!(
                "Could not identify the requested {} conversation from {}; refusing to drive it",
                provider.display_name(),
                expected_href
            )
        })?;

    let res = call(
        "evaluate_script",
        serde_json::json!({ "function": LIVE_URL_PROBE_JS }),
    )?;
    let href = parse_script_result(&res)?;
    let href = href.as_str().ok_or_else(|| {
        format!(
            "Could not read the URL of the {} session tab; refusing to drive it",
            provider.display_name()
        )
    })?;

    if let Ok(url) = Url::parse(href)
        && let Some(live_identity) = provider.conversation_identity(&url)
        && expected_identity.matches_live(&live_identity)
    {
        return Ok(());
    }

    if provider.owns_auth_url(href) {
        return Err(format!(
            "The {} session redirected to the sign-in page ({}); the session has \
             most likely expired. Run `ask-bridge --provider {} login`, then run \
             your query again.",
            provider.display_name(),
            href,
            provider
        ));
    }

    Err(format!(
        "The {} session tab left the conversation it was opened at and reports \
         {} instead; refusing to type the prompt into it",
        provider.display_name(),
        href
    ))
}

/// Put the browser on the conversation a `--session` run named, and prove it is
/// still there.
///
/// The two steps are one unit because the second is only meaningful about the
/// first: navigating is what can drift, and reading the live URL afterwards is
/// what notices. Folding them together also leaves the `--session` arm of
/// [`main`] with exactly one failure path, so "a refusal ends the run" is a
/// single `exit` to account for rather than one per step.
///
/// Test seam: both browser steps are injected, so the sequencing -- navigate
/// first, check second, and a check that refuses comes back as `Err` rather
/// than as something the caller can read as success -- is testable without a
/// browser. See `a_refused_session_landing_page_is_an_error_not_a_warning`, and
/// `a_refused_session_aborts_the_run` for the half that lives in [`main`].
fn open_verified_session_tab<O, V>(
    provider: Provider,
    open: &mut O,
    verify: &mut V,
) -> Result<(), String>
where
    O: FnMut() -> Result<(), String>,
    V: FnMut() -> Result<(), String>,
{
    open().map_err(|e| format!("Error opening {} session: {}", provider.display_name(), e))?;
    verify().map_err(|e| format!("Error opening {} session: {}", provider.display_name(), e))
}

/// Test seam for [`ensure_provider_tab`]: every browser interaction goes
/// through `call` and the readiness poll interval is injectable, so the tab
/// bookkeeping can be exercised against a fake MCP without ever starting a
/// browser and without waiting out real poll intervals.
fn ensure_provider_tab_with<F>(
    call: &mut F,
    provider: Provider,
    force_new: bool,
    headless: bool,
    verbose: bool,
    poll_interval: Duration,
) -> Result<TabOutcome, String>
where
    F: FnMut(&str, Value) -> Result<Value, String>,
{
    if verbose {
        println!("Checking open Chrome tabs...");
    }
    let mut close_failures: Vec<(usize, String)> = Vec::new();
    let list_res = call("list_pages", serde_json::json!({}))?;
    let pages = pages_from_tool_result(&list_res, "list_pages")?;

    // The tab this call commits to driving, pinned by ID. Everything after
    // this point re-selects *that* tab rather than re-deriving "a tab whose URL
    // looks like the provider", which is what let a stale tab (one that failed
    // to close) or a lookalike tab take over the session.
    let pinned_page_id: Option<usize>;

    if force_new {
        let before_ids: Vec<usize> = pages.iter().map(|p| p.id).collect();
        // `--new` is documented -- README.md "### 3. 開啟全新對話" and
        // README.en.md "### 3. Open a Brand New Session (`--new`)", pinned by
        // `the_new_flag_docs_still_describe_the_disposal_this_code_performs` --
        // to clean up the *same provider's* previous tabs. Other providers'
        // tabs and the user's unrelated tabs are not ours to close. Blank tabs
        // and tabs parked on this provider's auth host carry no user content
        // and were
        // both disposed of by the pre-fix "close everything" behaviour, so they
        // stay on the list -- dropping them would make tabs accumulate one per
        // run (blank: once per browser session; auth: every run, once the
        // session expires).
        let disposable_ids: Vec<usize> = pages
            .iter()
            .filter(|p| {
                // A tab whose line did not read back (`url == None`) is left
                // alone. The rule above is that tabs which are not this
                // provider's are not ours to close, and a tab we cannot name
                // has not been shown to be ours. That is a real difference from
                // the pre-guard behaviour, which did close it -- but only as a
                // side effect of mis-reading it as the provider's, which is the
                // same mis-reading that got the prompt typed into it.
                p.url.as_deref().is_some_and(|url| {
                    provider.owns_url(url) || provider.owns_auth_url(url) || is_blank_tab_url(url)
                })
            })
            .map(|p| p.id)
            .collect();

        if verbose {
            println!("Opening a brand new {} session...", provider.display_name());
        }
        let new_page_res = call(
            "new_page",
            serde_json::json!({
                "url": provider.home_url()
            }),
        )?;

        // chrome-devtools-mcp hands out monotonically increasing page IDs and
        // never reuses them, so "the ID that was not there before" identifies
        // the tab just opened exactly. `new_page` echoes the page list; if a
        // build ever stops doing that, ask again before anything is closed.
        let mut after = pages_from_tool_result(&new_page_res, "new_page").unwrap_or_default();
        let mut fresh = fresh_page_ids(&before_ids, &after, provider);
        if fresh.len() != 1 {
            let listed = call("list_pages", serde_json::json!({}))?;
            after = pages_from_tool_result(&listed, "list_pages")?;
            fresh = fresh_page_ids(&before_ids, &after, provider);
        }
        // Which of those IDs this run actually opened, read off the same
        // listing the IDs came from -- `new_page` moved *this* client's
        // selection onto the tab it created, and nothing between here and there
        // moves it back.
        let created = created_page_id(&before_ids, &after);
        let new_page_id = match fresh.as_slice() {
            [id] => *id,
            _ => {
                return Err(format!(
                    "Could not identify the new {} tab after new_page (candidate IDs: {:?}); refusing to drive an existing tab",
                    provider.display_name(),
                    fresh
                ));
            }
        };
        // ...and the ID that survived that must be the ID this run was told it
        // created. Without this, the asymmetric two-run interleaving (this
        // run's tab still blank, the other run's already on the provider) pins
        // the other run's conversation, and everything downstream -- the
        // readiness re-focus, the prompt, the copy -- lands there.
        //
        // It does *not* additionally throw away this run's own tab: probed with
        // this guard disabled, `--new` reports `closed=[1]` -- the pre-existing
        // blank tab -- and leaves this run's tab open. `disposable_ids` is built
        // from `pages`, the snapshot taken before `new_page`, and page IDs are
        // never reused, so the tab this run just opened cannot be in it. An
        // earlier version of this comment claimed otherwise.
        if created != Some(new_page_id) {
            return Err(format!(
                "The new {} tab (ID: {}) is not the tab this run opened (opened: {:?}); another ask-bridge run is most likely driving the same browser, so refusing to drive a tab that may be its conversation",
                provider.display_name(),
                new_page_id,
                created
            ));
        }

        let doomed: Vec<usize> = disposable_ids
            .into_iter()
            .filter(|id| *id != new_page_id)
            .collect();
        close_failures.extend(close_tabs(call, &doomed, provider, verbose));

        if verbose {
            println!(
                "Selecting new {} tab (ID: {})...",
                provider.display_name(),
                new_page_id
            );
        }
        call(
            "select_page",
            serde_json::json!({
                "pageId": new_page_id,
                "bringToFront": !headless
            }),
        )?;
        pinned_page_id = Some(new_page_id);
    } else {
        // Known gap, disclosed rather than closed: from here down the tab is
        // *adopted*, and adoption has no identity check at all -- only
        // `verify_selected_page_is_provider`, which asks about the origin.
        // A provider tab that another ask-bridge run is in the middle of using
        // is indistinguishable from the user's own idle tab, which is the case
        // this branch exists to reuse. The causal identity used above is
        // unavailable by construction: it comes from this client's `new_page`,
        // and an already-settled tab was never opened by this run.
        //
        // What it costs is pinned by
        // `known_gap_h10_the_adopt_path_drives_another_runs_conversation_tab`
        // -- named, not located: the `tests` module is thousands of lines
        // *above* this branch, and an earlier version of this comment said
        // "below". Two more `known_gap_h10_*` tests beside it pin the two
        // smaller residuals (`--new` disposing of another run's conversation,
        // and every identity refusal leaking the tab it opened -- the leak that
        // makes this branch's adoption more likely).
        let provider_pages: Vec<&Page> = pages
            .iter()
            .filter(|page| {
                page.url
                    .as_deref()
                    .is_some_and(|url| provider.owns_url(url))
            })
            .collect();

        let provider_page_id = if provider_pages.len() > 1 {
            let mut page_states = Vec::with_capacity(provider_pages.len());
            for page in &provider_pages {
                call(
                    "select_page",
                    serde_json::json!({
                        "pageId": page.id,
                        "bringToFront": false
                    }),
                )?;
                let login_state =
                    check_login_status_with(call, provider, verbose).unwrap_or(LoginState::Unknown);
                page_states.push(PageLoginState {
                    id: page.id,
                    selected: page.selected,
                    login_state,
                });
            }
            preferred_provider_page_id(&page_states)
        } else {
            provider_pages.first().map(|page| page.id)
        };

        pinned_page_id = match provider_page_id {
            Some(page_id) => {
                let page = provider_pages
                    .iter()
                    .find(|page| page.id == page_id)
                    .ok_or_else(|| "Selected provider page disappeared".to_string())?;
                if verbose {
                    println!(
                        "Found {} tab (ID: {}, selected: {}). Selecting/focusing...",
                        provider.display_name(),
                        page.id,
                        page.selected
                    );
                }
                call(
                    "select_page",
                    serde_json::json!({
                        "pageId": page.id,
                        "bringToFront": !headless
                    }),
                )?;
                verify_selected_page_is_provider(call, provider)?;
                Some(page.id)
            }
            None => {
                // No provider tab. If there is only one blank tab, navigate it. Otherwise open a new page.
                if pages.len() == 1 && pages[0].url.as_deref().is_some_and(is_blank_tab_url) {
                    if verbose {
                        println!(
                            "Navigating existing blank tab to {}...",
                            provider.display_name()
                        );
                    }
                    call(
                        "navigate_page",
                        serde_json::json!({
                            "url": provider.home_url()
                        }),
                    )?;
                    Some(pages[0].id)
                } else {
                    if verbose {
                        println!("Opening a new tab for {}...", provider.display_name());
                    }
                    let before_ids: Vec<usize> = pages.iter().map(|p| p.id).collect();
                    let opened = call(
                        "new_page",
                        serde_json::json!({
                            "url": provider.home_url()
                        }),
                    )?;
                    // Nothing stale can be re-selected here (the tab was just
                    // created), so an unidentifiable ID usually only costs the
                    // pinning -- with one exception that costs correctness, and
                    // it is the one below.
                    let mut after = pages_from_tool_result(&opened, "new_page").unwrap_or_default();
                    let mut fresh = fresh_page_ids(&before_ids, &after, provider);
                    if fresh.len() != 1 {
                        // Ask again before deciding, exactly as the `--new`
                        // branch does: the list `new_page` echoes is a snapshot,
                        // and a tab that was still settling in it may have
                        // resolved by now.
                        let listed = call("list_pages", serde_json::json!({}))?;
                        after = pages_from_tool_result(&listed, "list_pages")?;
                        fresh = fresh_page_ids(&before_ids, &after, provider);
                    }
                    // See [`created_page_id`]: which of those IDs this run
                    // opened, read off the same listing the IDs came from.
                    let created = created_page_id(&before_ids, &after);
                    // Two fresh tabs that are *both* this provider's is the
                    // shape a second ask-bridge run makes: each run has its own
                    // chrome-devtools-mcp child, but they share the browser's
                    // page-ID space. Nothing downstream can tell them apart --
                    // the readiness re-focus falls back to the first
                    // provider-owned tab and the final gate checks the origin,
                    // never the identity -- so an unpinned run here types its
                    // prompt into the other run's conversation and copies back
                    // whichever message was latest. Refuse instead, like `--new`
                    // already does with the same ambiguity.
                    let owned_fresh: Vec<usize> = after
                        .iter()
                        .filter(|p| {
                            fresh.contains(&p.id)
                                && p.url.as_deref().is_some_and(|url| provider.owns_url(url))
                        })
                        .map(|p| p.id)
                        .collect();
                    if owned_fresh.len() > 1 {
                        return Err(format!(
                            "Could not tell which of these fresh {} tabs this run opened (candidate IDs: {:?}); another ask-bridge run is most likely driving the same browser, so refusing to type the prompt into a tab that may be its conversation",
                            provider.display_name(),
                            owned_fresh
                        ));
                    }
                    let opened_id = match fresh.as_slice() {
                        [id] => Some(*id),
                        _ => None,
                    };
                    // The asymmetric shape of the same collision, which the
                    // guard above cannot see because one is not "more than
                    // one": this run's own tab is still blank, mid-redirect or
                    // on the auth host while the other run's has already
                    // settled on the provider, so the single provider-owned
                    // fresh ID *is* the other run's. Pinning is a commitment to
                    // drive that tab from here on -- it even suppresses the
                    // origin check at the return -- so it may only ever name
                    // the tab this run was told it created.
                    if let Some(id) = opened_id
                        && created != Some(id)
                    {
                        return Err(format!(
                            "The only fresh {} tab (ID: {}) is not the tab this run opened (opened: {:?}); another ask-bridge run is most likely driving the same browser, so refusing to type the prompt into a tab that may be its conversation",
                            provider.display_name(),
                            id,
                            created
                        ));
                    }

                    // Reaching here means no provider tab was found, which is
                    // also what happens when the previous run's tab drifted to
                    // the login host -- so without this the default path opens
                    // one more tab on every invocation, forever. Disposing is
                    // safe where *adopting* was not: the tab we drive is the
                    // one just opened and already pinned above, so a login page
                    // is never selected, never probed for readiness, and never
                    // receives the prompt.
                    let stale_auth: Vec<usize> = pages
                        .iter()
                        .filter(|p| {
                            p.url
                                .as_deref()
                                .is_some_and(|url| provider.owns_auth_url(url))
                        })
                        .map(|p| p.id)
                        // Belt and braces on a destructive call. Redundant
                        // today -- `pages` is the snapshot taken before
                        // `new_page`, and page IDs are allocated monotonically
                        // and never reused, so the tab just opened cannot
                        // appear in it -- but never closing the tab we are
                        // about to drive is worth stating locally rather than
                        // inferring from two invariants declared elsewhere.
                        .filter(|id| Some(*id) != opened_id)
                        .collect();
                    close_failures.extend(close_tabs(call, &stale_auth, provider, verbose));

                    opened_id
                }
            }
        };
    }

    // Wait for the provider composer to be present.
    if verbose {
        println!("Waiting for {} to load...", provider.display_name());
    }
    for attempt in 0..90 {
        if attempt > 0 && attempt % 10 == 0 {
            let listed = call("list_pages", serde_json::json!({}))
                .ok()
                .and_then(|res| pages_from_tool_result(&res, "list_pages").ok());
            if let Some(listed) = listed {
                let target = match pinned_page_id {
                    // Re-focus the tab this call committed to. If it is gone,
                    // there is nothing safe to fall back to: the readiness
                    // probe would run against whichever page happens to be
                    // selected, and the Gemini/Claude probes accept a generic
                    // "Sign in|登入" on any page at all.
                    Some(id) => {
                        if !listed.iter().any(|p| p.id == id) {
                            return Err(format!(
                                "The {} tab (ID: {}) disappeared while waiting for it to load",
                                provider.display_name(),
                                id
                            ));
                        }
                        Some(id)
                    }
                    None => listed
                        .iter()
                        .find(|p| p.url.as_deref().is_some_and(|url| provider.owns_url(url)))
                        .map(|p| p.id),
                };
                if let Some(page_id) = target {
                    let _ = call(
                        "select_page",
                        serde_json::json!({
                            "pageId": page_id,
                            "bringToFront": !headless
                        }),
                    );
                }
            }
        }

        let ready_res = call(
            "evaluate_script",
            serde_json::json!({
                "function": provider.ready_check_js()
            }),
        );
        let ready_res = match ready_res {
            Ok(res) => res,
            Err(e) => {
                if verbose {
                    eprintln!(
                        "Warning: Failed to check {} readiness: {}",
                        provider.display_name(),
                        e
                    );
                }
                thread::sleep(poll_interval);
                continue;
            }
        };
        if let Ok(parsed) = parse_script_result(&ready_res) {
            let is_ready = parsed.as_bool().unwrap_or(false);
            if is_ready {
                // No pinned ID means this call never managed to identify the
                // tab it opened, so the tab that just passed the readiness
                // probe is whichever one happened to be selected -- possibly
                // one re-derived from the listing prose a few lines above.
                // That is the one path out of here whose target was never
                // verified against anything but the parser, so verify it now,
                // before the caller starts typing.
                if pinned_page_id.is_none() {
                    verify_selected_page_is_provider(call, provider)?;
                }
                return Ok(TabOutcome { close_failures });
            }
        }
        thread::sleep(poll_interval);
    }

    Err(format!(
        "Timeout waiting for {} page to load",
        provider.display_name()
    ))
}

fn check_login_status(
    config_path: &str,
    provider: Provider,
    verbose: bool,
) -> Result<LoginState, String> {
    check_login_status_with(
        &mut |tool: &str, args: Value| call_mcp_tool(config_path, tool, args),
        provider,
        verbose,
    )
}

fn check_login_status_with<F>(
    call: &mut F,
    provider: Provider,
    verbose: bool,
) -> Result<LoginState, String>
where
    F: FnMut(&str, Value) -> Result<Value, String>,
{
    let res = call(
        "evaluate_script",
        serde_json::json!({
            "function": provider.login_signals_js()
        }),
    )?;

    let parsed = parse_script_result(&res)?;
    let signals: LoginSignals = serde_json::from_value(parsed)
        .map_err(|e| format!("Failed to parse login signals: {}", e))?;
    if verbose {
        println!(
            "{} login signals: account={}, auth_control={}, auth_path={}, composer={}, stable={}",
            provider.display_name(),
            signals.account,
            signals.auth_control,
            signals.auth_path,
            signals.composer,
            signals.stable
        );
    }
    Ok(signals.state(provider))
}

fn wait_for_login_completion(
    config_path: &str,
    provider: Provider,
    timeout_seconds: u64,
    verbose: bool,
) -> (LoginState, bool) {
    let timeout = Duration::from_secs(timeout_seconds.max(1));
    let start = Instant::now();
    let display_name = provider.display_name();

    if verbose {
        println!(
            "Waiting for {} login status every second (timeout: {} seconds)...",
            display_name,
            timeout_seconds.max(1)
        );
    } else {
        println!("Waiting for login completion (checking every second)...");
    }

    loop {
        let state = match check_login_status(config_path, provider, verbose) {
            Ok(state) => state,
            Err(e) => {
                if verbose {
                    println!(
                        "Warning: Failed to check {} login status: {}",
                        display_name, e
                    );
                }
                LoginState::Unknown
            }
        };

        if state == LoginState::LoggedIn {
            return (LoginState::LoggedIn, false);
        }

        if start.elapsed() >= timeout {
            return (state, true);
        }

        thread::sleep(Duration::from_secs(1));
    }
}

fn print_chrome_diagnostics(profile_path: &str) {
    let snapshot = inspect_chrome_debug_port(profile_path);
    let recorded_pid = read_chrome_pid().unwrap_or_else(|| "unknown".to_string());

    println!("Chrome diagnostics:");
    println!("  profile: {}", profile_path);
    println!("  recorded PID: {}", recorded_pid);
    println!("  listener PIDs: {:?}", snapshot.listener_pids);
    println!("  ask-bridge owner PIDs: {:?}", snapshot.ask_pids);
    println!(
        "  CDP browser identity recorded: {}",
        snapshot
            .record
            .and_then(|record| record.browser_id)
            .is_some()
    );
}

/// How long to wait for a non-tty stdin to produce its first byte (or EOF)
/// when a prompt argument was already provided. Agent harnesses (Claude Code,
/// Codex) run commands with a pipe they may never close; blocking on EOF hung
/// whole runs (2026-07-11).
const STDIN_PIPE_GRACE: Duration = Duration::from_secs(2);

enum StdinProbe {
    Data,
    Eof,
}

/// Read stdin on a helper thread, signalling the first byte (or EOF) on one
/// channel and the full content on another, so the caller can bound how long
/// it waits for a pipe that might never deliver anything.
fn spawn_stdin_reader() -> (
    std::sync::mpsc::Receiver<StdinProbe>,
    std::sync::mpsc::Receiver<std::io::Result<String>>,
) {
    let (probe_tx, probe_rx) = std::sync::mpsc::channel();
    let (data_tx, data_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut stdin = io::stdin();
        let mut first = [0u8; 1];
        match stdin.read(&mut first) {
            Ok(0) => {
                let _ = probe_tx.send(StdinProbe::Eof);
                let _ = data_tx.send(Ok(String::new()));
            }
            Ok(_) => {
                let _ = probe_tx.send(StdinProbe::Data);
                let mut bytes = vec![first[0]];
                let result = stdin.read_to_end(&mut bytes).and_then(|_| {
                    String::from_utf8(bytes)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
                });
                let _ = data_tx.send(result);
            }
            Err(e) => {
                let _ = probe_tx.send(StdinProbe::Eof);
                let _ = data_tx.send(Err(e));
            }
        }
    });
    (probe_rx, data_rx)
}

/// With a prompt argument in hand piped stdin is an optional supplement: wait
/// up to `grace` for the pipe's first byte, then read a live pipe to EOF as
/// before; a silent pipe (agent harness holding it open) is treated as "no
/// piped input". Without a prompt argument stdin IS the prompt, so wait
/// unbounded exactly like upstream.
fn recv_piped_stdin(
    probe_rx: &std::sync::mpsc::Receiver<StdinProbe>,
    data_rx: &std::sync::mpsc::Receiver<std::io::Result<String>>,
    grace: Duration,
    has_prompt_argument: bool,
) -> std::io::Result<String> {
    if !has_prompt_argument {
        // stdin IS the prompt: wait unbounded like upstream, but after the
        // grace window tell the user what we are blocked on (an agent harness
        // holding the pipe open would otherwise hang here with no diagnostic).
        return match data_rx.recv_timeout(grace) {
            Ok(result) => result,
            Err(_) => {
                eprintln!(
                    "Waiting for a prompt on stdin (pipe is open; close it or pass a prompt argument)..."
                );
                data_rx.recv().unwrap_or(Ok(String::new()))
            }
        };
    }
    match probe_rx.recv_timeout(grace) {
        Ok(_) => data_rx.recv().unwrap_or(Ok(String::new())),
        Err(_) => {
            eprintln!(
                "No piped stdin data within {}s; continuing with the prompt argument only.",
                grace.as_secs()
            );
            Ok(String::new())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cli = Cli::parse();
    if cli.command.is_none() {
        let is_stdin_terminal = io::stdin().is_terminal();
        if is_stdin_terminal && cli.prompt.as_deref() == Some("update") {
            cli.command = Some(Commands::Update);
        }
    }

    let command_verbose = match &cli.command {
        Some(Commands::Get { verbose, .. }) => cli.verbose || *verbose,
        _ => cli.verbose,
    };

    FORWARD_MCP_STDERR.store(command_verbose, std::sync::atomic::Ordering::Relaxed);

    if matches!(cli.command, Some(Commands::Config)) {
        if let Err(e) = run_config_command(cli.provider, cli.browser.clone()) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }

        return Ok(());
    }
    if matches!(cli.command, Some(Commands::Update)) {
        if let Err(e) = run_update_command() {
            eprintln!("Update failed: {}", e);
            std::process::exit(1);
        }
        return Ok(());
    }

    let mut provider = match resolve_provider(cli.provider) {
        Ok(provider) => provider,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let session_target = match cli.session.as_deref() {
        Some(session) => match resolve_session_target(provider, cli.provider.is_some(), session) {
            Ok(target) => {
                provider = target.0;
                Some(target)
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },
        None => None,
    };

    if let Err(e) = validate_provider_feature_support(provider, &cli) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let selection_plan =
        match resolve_selection_plan(provider, cli.model.as_deref(), cli.reasoning.as_deref()) {
            Ok(plan) => plan,
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        };
    if selection_plan.used_legacy_model {
        eprintln!(
            "Warning: reasoning-like --model values are deprecated; use --reasoning instead."
        );
    }

    if !command_verbose {
        // SAFETY: Called before spawning other threads and before loading MCP config.
        unsafe {
            std::env::remove_var("MCP_DEBUG");
        }
    }
    if std::env::var("MCP_TIMEOUT").is_err() {
        // SAFETY: Called before spawning other threads and before loading MCP config.
        unsafe {
            std::env::set_var("MCP_TIMEOUT", "20");
        }
    }

    let is_terminal = io::stdout().is_terminal();
    let use_glow = is_terminal && is_glow_available();

    let is_headless = match &cli.command {
        Some(Commands::Login) => false, // Force headful only for login command so user can see it to log in
        Some(Commands::Get { .. }) => false, // Default get to headful for debugging by default
        _ => cli.headless, // Respect --headless (defaults to true) for all other commands (including Open)
    };

    if matches!(cli.command, Some(Commands::Close)) {
        let profile_path = match chrome_profile_path() {
            Ok(path) => path,
            Err(e) => {
                eprintln!("Error locating Chrome profile: {}", e);
                std::process::exit(1);
            }
        };

        match close_ask_chrome_on_debug_port(&profile_path) {
            Ok(true) => println!("Closed ask-bridge Chrome browser instance."),
            Ok(false) => println!("No ask-bridge Chrome browser instance is running."),
            Err(e) => {
                eprintln!("Error closing ask-bridge Chrome browser instance: {}", e);
                std::process::exit(1);
            }
        }

        return Ok(());
    }

    if let Err(e) = check_node_runtime() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let config_path = match write_mcp_config(!command_verbose, is_headless) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let browser_override = match resolve_browser_override(cli.browser.clone()) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) =
        start_chrome_if_needed(is_headless, command_verbose, browser_override.as_deref())
    {
        eprintln!("Error starting browser: {}", e);
        std::process::exit(1);
    }

    if let Some(command) = cli.command {
        match command {
            Commands::Open { url } => {
                if let Some(url) = url {
                    let page_provider = Provider::from_url(&url).unwrap_or(provider);
                    if let Err(e) = open_url_tab(
                        &config_path,
                        page_provider,
                        &url,
                        is_headless,
                        command_verbose,
                    ) {
                        eprintln!("Error opening URL: {}", e);
                        std::process::exit(1);
                    }

                    match copy_latest_markdown(&config_path, page_provider) {
                        Ok(markdown) => {
                            if let Some(code) = markdown_output::write_if_requested(
                                cli.output.as_ref(),
                                &markdown,
                                command_verbose,
                            ) {
                                std::process::exit(code);
                            }
                            if let Err(e) = render_markdown(&markdown, use_glow) {
                                eprintln!("Error rendering Markdown: {}", e);
                                std::process::exit(1);
                            }
                            if let Some(code) = download_images_and_exit_code(
                                &config_path,
                                page_provider,
                                cli.image_output.as_deref(),
                                command_verbose,
                            ) {
                                std::process::exit(code);
                            }
                        }
                        Err(e) => {
                            eprintln!("Error copying latest response Markdown: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    if let Err(e) = ensure_provider_tab(
                        &config_path,
                        provider,
                        false,
                        is_headless,
                        command_verbose,
                    ) {
                        eprintln!("Error ensuring {} tab: {}", provider.display_name(), e);
                        std::process::exit(1);
                    }
                    println!("Successfully opened {}!", provider.display_name());
                }
                return Ok(());
            }
            Commands::Get { url, .. } => {
                let mut page_provider = provider;
                if let Some(url) = url {
                    page_provider = Provider::from_url(&url).unwrap_or(provider);
                    if let Err(e) = open_url_tab(
                        &config_path,
                        page_provider,
                        &url,
                        is_headless,
                        command_verbose,
                    ) {
                        eprintln!("Error opening URL: {}", e);
                        std::process::exit(1);
                    }
                } else {
                    if let Err(e) = ensure_provider_tab(
                        &config_path,
                        provider,
                        false,
                        is_headless,
                        command_verbose,
                    ) {
                        eprintln!("Error ensuring {} tab: {}", provider.display_name(), e);
                        std::process::exit(1);
                    }
                }

                match copy_latest_markdown(&config_path, page_provider) {
                    Ok(markdown) => {
                        if let Some(code) = markdown_output::write_if_requested(
                            cli.output.as_ref(),
                            &markdown,
                            command_verbose,
                        ) {
                            std::process::exit(code);
                        }
                        if let Err(e) = render_markdown(&markdown, use_glow) {
                            eprintln!("Error rendering Markdown: {}", e);
                            std::process::exit(1);
                        }
                        if let Some(code) = download_images_and_exit_code(
                            &config_path,
                            page_provider,
                            cli.image_output.as_deref(),
                            command_verbose,
                        ) {
                            std::process::exit(code);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error copying latest response Markdown: {}", e);
                        std::process::exit(1);
                    }
                }
                return Ok(());
            }
            Commands::Login => {
                if let Err(e) =
                    ensure_provider_tab(&config_path, provider, false, is_headless, command_verbose)
                {
                    eprintln!("Error ensuring {} tab: {}", provider.display_name(), e);
                    std::process::exit(1);
                }
                println!("\n========================================================");
                println!("Please complete the login manually in the Chrome window.");
                println!("The tool will automatically detect when login is complete every second.");
                println!("========================================================\n");

                let (login_state, timed_out) =
                    wait_for_login_completion(&config_path, provider, cli.timeout, command_verbose);

                match (login_state, timed_out) {
                    (LoginState::LoggedIn, _) => println!(
                        "Success: Logged in successfully! You can now use the `ask-bridge` command."
                    ),
                    (LoginState::LoggedOut, true) => println!(
                        "Warning: Login timeout reached ({} seconds). Login still appears incomplete.",
                        cli.timeout
                    ),
                    (LoginState::Unknown, true) => println!(
                        "Warning: Timeout reached ({} seconds). Login status is still unknown; please verify manually.",
                        cli.timeout
                    ),
                    (LoginState::LoggedOut, false) | (LoginState::Unknown, false) => println!(
                        "Warning: Login status changed while waiting. Please verify the result and rerun if needed."
                    ),
                }
                if command_verbose {
                    match chrome_profile_path() {
                        Ok(profile_path) => print_chrome_diagnostics(&profile_path),
                        Err(e) => eprintln!("Warning: Failed to locate Chrome profile: {}", e),
                    }
                }
                return Ok(());
            }
            Commands::Close => unreachable!("close command is handled before Chrome startup"),
            Commands::Config => unreachable!("config command is handled before Chrome startup"),
            Commands::Update => unreachable!("update command is handled before Chrome startup"),
            Commands::Dump => {
                let list_res = call_mcp_tool(&config_path, "list_pages", serde_json::json!({}))?;
                println!("All pages: {:?}", list_res);
                if let Err(e) =
                    ensure_provider_tab(&config_path, provider, false, is_headless, command_verbose)
                {
                    eprintln!("Error ensuring {} tab: {}", provider.display_name(), e);
                    std::process::exit(1);
                }
                let url_res = call_mcp_tool(
                    &config_path,
                    "evaluate_script",
                    serde_json::json!({
                        "function": "() => window.location.href"
                    }),
                )?;
                println!("Current page URL: {:?}", parse_script_result(&url_res));
                let res = call_mcp_tool(
                    &config_path,
                    "evaluate_script",
                    serde_json::json!({
                        "function": "() => document.body.innerHTML"
                    }),
                )?;
                let html = parse_script_result(&res)?
                    .as_str()
                    .unwrap_or("")
                    .to_string();
                std::fs::create_dir_all("target").unwrap();
                std::fs::write("target/dump.html", html)?;
                println!("Dumped HTML to target/dump.html");
                return Ok(());
            }
            Commands::Screenshot => {
                if let Err(e) =
                    ensure_provider_tab(&config_path, provider, false, is_headless, command_verbose)
                {
                    eprintln!("Error ensuring {} tab: {}", provider.display_name(), e);
                    std::process::exit(1);
                }
                let res = call_mcp_tool(&config_path, "take_screenshot", serde_json::json!({}))?;

                let bytes = screenshot_png_bytes(&res)?;
                std::fs::create_dir_all("target")?;
                std::fs::write("target/screenshot.png", bytes)?;
                println!("Saved screenshot to target/screenshot.png");
                return Ok(());
            }
        }
    }

    // Read prompt from arguments and optionally append piped stdin content.
    let mut stdin_prompt = String::new();

    // Check if stdin is a pipe (not a tty)
    if !std::io::stdin().is_terminal() {
        let (probe_rx, data_rx) = spawn_stdin_reader();
        stdin_prompt =
            recv_piped_stdin(&probe_rx, &data_rx, STDIN_PIPE_GRACE, cli.prompt.is_some())?;
    }

    let prompt = match cli.prompt {
        Some(mut p) => {
            if !stdin_prompt.is_empty() {
                p.push_str("\n\n");
                p.push_str(&stdin_prompt);
            }
            p
        }
        None => stdin_prompt,
    };

    let prompt = prompt.trim().to_string();
    if prompt.is_empty() {
        // No prompt and no command, print help
        let mut cmd = Cli::command();
        if let Some(version) = cmd.get_version() {
            println!("ask-bridge {}", version);
        } else {
            println!("ask-bridge {}", env!("CARGO_PKG_VERSION"));
        }
        cmd.print_help()?;
        println!();
        std::process::exit(0);
    }

    if let Some((session_provider, session_url)) = &session_target {
        // `open_url_tab` binds the tab by ID, so nothing can *substitute* a tab
        // here -- but nothing on this path ever reads the tab's live URL
        // either. `wait_for_page_load` polls `document.readyState` and
        // `Provider::ready_check_js`, a DOM-shape probe any page can satisfy,
        // and `submit_regular_prompt` checks no origin at all. So between
        // `new_page(session_url)` and the prompt being typed, the only thing
        // tying the composer to the provider is the browser having honoured the
        // URL we handed it -- which a redirect off the provider's origin
        // breaks. This is the same script-eval the reuse and unpinned paths
        // already pay.
        //
        // Deliberately at the call site, not inside `open_url_tab`: `open <url>`
        // and `get <url>` share that function and pass a URL that need not be
        // the provider's (`Provider::from_url(&url).unwrap_or(provider)`), and
        // neither reaches the composer. Verifying inside would refuse those two
        // commands for a behaviour they never had.
        //
        // The refusal ends the run. It is not a warning to proceed through:
        // everything after this point types the prompt into whatever tab is
        // selected, so continuing past a rejected landing page is exactly the
        // hole the check was added to close.
        if let Err(e) = open_verified_session_tab(
            *session_provider,
            &mut || {
                open_url_tab(
                    &config_path,
                    *session_provider,
                    session_url,
                    is_headless,
                    command_verbose,
                )
            },
            &mut || {
                verify_session_page_is_provider(
                    &mut |tool, args| call_mcp_tool(&config_path, tool, args),
                    *session_provider,
                    session_url,
                )
            },
        ) {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    } else if let Err(e) = ensure_provider_tab(
        &config_path,
        provider,
        cli.new,
        is_headless,
        command_verbose,
    ) {
        eprintln!("Error ensuring {} tab: {}", provider.display_name(), e);
        std::process::exit(1);
    }

    // Show attached images in the terminal before sending
    if !cli.images.is_empty() {
        for img_path in &cli.images {
            display_image_in_terminal(img_path);
        }
    }

    // Verify login
    match check_login_status(&config_path, provider, command_verbose) {
        Ok(LoginState::LoggedOut) => {
            eprintln!(
                "\nError: You are not logged in to {}.",
                provider.display_name()
            );
            eprintln!(
                "Please run `ask-bridge --provider {} login` to log in manually first, and then run your query again.\n",
                provider
            );
            std::process::exit(1);
        }
        Ok(LoginState::Unknown) => {
            eprintln!(
                "Warning: Could not confirm the {} account menu. Attempting to proceed...",
                provider.display_name()
            );
        }
        Ok(LoginState::LoggedIn) => {}
        Err(e) if command_verbose => {
            eprintln!(
                "Warning: Failed to verify login status: {}. Attempting to proceed...",
                e
            );
        }
        Err(_) => {}
    }

    // Switch model if requested (before uploading attachments / typing the prompt)
    if let Some(m) = &selection_plan.model
        && let Err(e) = switch_model(&config_path, provider, m, command_verbose)
    {
        eprintln!("Error switching model: {}", e);
        std::process::exit(1);
    }
    if let Some(reasoning) = selection_plan.reasoning
        && let Err(e) = switch_reasoning(&config_path, provider, reasoning, command_verbose)
    {
        eprintln!("Error switching reasoning: {}", e);
        std::process::exit(1);
    }

    // Upload any attached images/files before counting messages (so the UI is ready)
    if (!cli.images.is_empty() || !cli.files.is_empty())
        && let Err(e) = upload_attachments_to_provider(
            &config_path,
            provider,
            &cli.images,
            &cli.files,
            command_verbose,
        )
    {
        eprintln!("Error attaching images/files: {}", e);
        std::process::exit(1);
    }

    // Get initial number of assistant messages before submitting the prompt
    let assistant_selector = serde_json::to_string(provider.assistant_selector())
        .map_err(|e| format!("Failed to serialize assistant selector: {}", e))?;
    let count_res = call_mcp_tool(
        &config_path,
        "evaluate_script",
        serde_json::json!({
            "function": format!("() => document.querySelectorAll({}).length", assistant_selector)
        }),
    )?;
    let initial_assistant_count = parse_script_result(&count_res)
        .ok()
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    if command_verbose {
        println!("Setting prompt text and submitting...");
    }
    let status = submit_prompt_to_provider(&config_path, provider, &prompt, command_verbose)
        .map_err(|e| format!("Text entry or submission failed: {}", e))?;

    if command_verbose {
        println!("Prompt submitted successfully: {}", status);
    }

    if command_verbose {
        println!("Waiting for {} response...", provider.display_name());
    }

    let mut finished = false;
    let mut wait_cycles = 0;
    let mut stable_done_checks = 0;
    let spinner_frames = vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let mut spinner_idx = 0;

    let max_wait_cycles: usize =
        usize::try_from(cli.timeout.saturating_mul(10)).unwrap_or(usize::MAX);
    while !finished && wait_cycles < max_wait_cycles {
        // Max wait time: timeout seconds (timeout * 10 * 100ms)
        if is_terminal {
            let frame = spinner_frames[spinner_idx % spinner_frames.len()];
            print!(
                "\r\x1b[1;36m{}\x1b[0m 正在等待 {} 回應...",
                frame,
                provider.display_name()
            );
            io::stdout().flush()?;
            spinner_idx += 1;
        }

        if wait_cycles % 5 == 0 {
            let stop_selectors = provider.stop_button_selectors_json();
            let assistant_selector = serde_json::to_string(provider.assistant_selector())
                .map_err(|e| format!("Failed to serialize assistant selector: {}", e))?;
            let response_check_js = r#"() => {
                    const stopSelectors = __STOP_SELECTORS__;
                    const isVisible = (el) => {
                        if (!el || el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
                        const style = window.getComputedStyle(el);
                        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
                        const rect = el.getBoundingClientRect();
                        return rect.width > 0 && rect.height > 0;
                    };
                    const stopButton = stopSelectors.map((selector) => document.querySelector(selector)).find(isVisible);
                    const messages = document.querySelectorAll(__ASSISTANT_SELECTOR__);
                    const isNew = messages.length > __INITIAL_COUNT__;
                    
                    if (isVisible(stopButton)) {
                        return { status: "generating", isNew: isNew };
                    }
                    
                    if (isNew) {
                        return { status: "done", isNew: isNew };
                    }
                    
                    return { status: "waiting", isNew: isNew };
                }"#
            .replace("__STOP_SELECTORS__", stop_selectors)
            .replace("__ASSISTANT_SELECTOR__", &assistant_selector)
            .replace("__INITIAL_COUNT__", &initial_assistant_count.to_string());
            let check_res = match call_mcp_tool(
                &config_path,
                "evaluate_script",
                serde_json::json!({
                    "function": response_check_js
                }),
            ) {
                Ok(res) => res,
                Err(e) => {
                    if command_verbose {
                        eprintln!(
                            "Warning: Failed to poll {} response: {}",
                            provider.display_name(),
                            e
                        );
                    }
                    thread::sleep(Duration::from_millis(100));
                    wait_cycles += 1;
                    continue;
                }
            };

            if let Ok(parsed) = parse_script_result(&check_res) {
                let status = parsed["status"].as_str().unwrap_or("waiting");
                let is_new = parsed["isNew"].as_bool().unwrap_or(false);

                if status == "done" && is_new {
                    stable_done_checks += 1;
                    if stable_done_checks >= 3 {
                        finished = true;
                    }
                } else {
                    stable_done_checks = 0;
                }
            }
        }

        thread::sleep(Duration::from_millis(100));
        wait_cycles += 1;
    }

    if is_terminal {
        print!("\r\x1b[K");
        io::stdout().flush()?;
    }

    if !finished {
        eprintln!(
            "\nWarning: Output stream did not complete within the timeout period ({} seconds).",
            cli.timeout
        );
    }

    if finished && command_verbose {
        println!(
            "Copying final response from {} toolbar...",
            provider.display_name()
        );
    }
    let (last_markdown, answer_arrived) = harvest_prompt_answer(provider, finished, || {
        copy_latest_markdown(&config_path, provider)
    });

    if let Err(e) = render_markdown(&last_markdown, use_glow) {
        eprintln!("Error rendering Markdown: {}", e);
    }

    // Held, not acted on: the Thread Link and the `--output` file below were
    // already promised to the caller and must still be produced.
    let mut image_exit_code = None;
    if finished {
        image_exit_code = download_images_and_exit_code(
            &config_path,
            provider,
            cli.image_output.as_deref(),
            command_verbose,
        );
    }

    // Print the URL link of the current conversation thread
    let url_opt = call_mcp_tool(
        &config_path,
        "evaluate_script",
        serde_json::json!({
            "function": "() => window.location.href"
        }),
    )
    .ok()
    .and_then(|url_val| parse_script_result(&url_val).ok())
    .and_then(|u| u.as_str().map(|s| s.to_string()));

    if let Some(url) = url_opt {
        if is_terminal {
            println!("\n🌐 \x1b[1mThread Link:\x1b[0m \x1b[4;36m{}\x1b[0m", url);
        } else {
            println!("\nThread Link: {}", url);
        }
    }

    if let Some(code) = finish_prompt_artifacts(
        &last_markdown,
        cli.output.as_ref(),
        image_exit_code,
        answer_arrived,
        command_verbose,
    ) {
        std::process::exit(code);
    }

    Ok(())
}
