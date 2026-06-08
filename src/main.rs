use std::io::{self, Read, Write, IsTerminal};
use std::net::TcpStream;
use std::process::Command;
use std::thread;
use std::time::Duration;
use clap::{Parser, Subcommand, CommandFactory};
use serde_json::Value;


#[derive(Parser)]
#[command(name = "ask")]
#[command(version = "0.1.0")]
#[command(about = "ChatGPT Browser Automation CLI in Rust", long_about = None)]
struct Cli {
    /// The prompt to send to ChatGPT. If empty, reads from standard input.
    prompt: Option<String>,

    /// Run Chrome in headless mode. Defaults to true.
    #[arg(long, require_equals = true, num_args = 0..=1, default_value = "true", default_missing_value = "true")]
    headless: bool,

    /// Create a brand new ChatGPT session by opening a new tab and closing old ones.
    #[arg(long, default_value_t = false)]
    new: bool,

    /// Print verbose debugging status messages.
    #[arg(long, short, default_value_t = false)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Clone)]
enum Commands {
    /// Open Chrome browser and focus on ChatGPT
    Open,
    /// Open Chrome browser and wait for manual login
    Login,
}

struct Page {
    id: usize,
    url: String,
    selected: bool,
}

fn get_mcp_cli_path() -> String {
    if let Some(mut home_dir) = home::home_dir() {
        home_dir.push(".local/bin/mcp-cli");
        if home_dir.exists() {
            return home_dir.to_string_lossy().to_string();
        }
    }
    "mcp-cli".to_string()
}

fn write_mcp_config() -> Result<String, String> {
    let mut config_dir = home::home_dir().ok_or("Could not locate home directory")?;
    config_dir.push(".config/ask-chatgpt");
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config directory: {}", e))?;
        
    config_dir.push("mcp_servers.json");
    let config_path = config_dir.to_string_lossy().to_string();
    
    let config_content = serde_json::json!({
        "mcpServers": {
            "chrome-devtools": {
                "command": "npx",
                "args": [
                    "-y",
                    "chrome-devtools-mcp@latest",
                    "--browserUrl",
                    "http://127.0.0.1:9223"
                ]
            }
        }
    });
    
    let content_str = serde_json::to_string_pretty(&config_content)
        .map_err(|e| e.to_string())?;
        
    std::fs::write(&config_path, content_str)
        .map_err(|e| format!("Failed to write mcp_servers.json: {}", e))?;
        
    Ok(config_path)
}

fn start_chrome_if_needed(headless: bool, verbose: bool) -> Result<(), String> {
    if TcpStream::connect("127.0.0.1:9223").is_ok() {
        return Ok(());
    }
    
    if verbose {
        println!("Chrome is not running on port 9223. Starting Chrome with remote debugging (headless: {})...", headless);
    }
    
    let mut profile_dir = home::home_dir().ok_or("Could not locate home directory")?;
    profile_dir.push(".config/ask-chatgpt/chrome-profile");
    std::fs::create_dir_all(&profile_dir)
        .map_err(|e| format!("Failed to create chrome profile directory: {}", e))?;
        
    let profile_path = profile_dir.to_string_lossy().to_string();
    
    let chrome_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    if !std::path::Path::new(chrome_path).exists() {
        return Err("Google Chrome not found at /Applications/Google Chrome.app".to_string());
    }
    
    let mut cmd = Command::new(chrome_path);
    cmd.arg("--remote-debugging-port=9223")
        .arg(format!("--user-data-dir={}", profile_path))
        .arg("--no-first-run")
        .arg("--no-default-browser-check");
        
    if headless {
        cmd.arg("--headless=new");
    }
    
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start Google Chrome: {}", e))?;
        
    // Wait for Chrome to listen on port 9223
    for _ in 0..50 {
        if TcpStream::connect("127.0.0.1:9223").is_ok() {
            if verbose {
                println!("Chrome started and listening on port 9223.");
            }
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    
    Err("Timed out waiting for Chrome to start on port 9223".to_string())
}

fn call_mcp_tool(config_path: &str, tool: &str, args: Value) -> Result<Value, String> {
    let args_str = serde_json::to_string(&args).map_err(|e| e.to_string())?;
    let mcp_cli_path = get_mcp_cli_path();
    
    let output = Command::new(&mcp_cli_path)
        .arg("-c")
        .arg(config_path)
        .arg("call")
        .arg("chrome-devtools")
        .arg(tool)
        .arg(&args_str)
        .output()
        .map_err(|e| format!("Failed to execute mcp-cli: {}", e))?;
        
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("mcp-cli call failed (exit status {}): {}", output.status, stderr));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let val: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse JSON from stdout: {}\nRaw output: {}", e, stdout))?;
        
    Ok(val)
}

fn parse_pages(text: &str) -> Vec<Page> {
    let mut pages = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("##") {
            continue;
        }
        if let Some((id_str, rest)) = line.split_once(':') {
            if let Ok(id) = id_str.trim().parse::<usize>() {
                let rest = rest.trim();
                let (url, selected) = if rest.ends_with("[selected]") {
                    let url = rest.strip_suffix("[selected]").unwrap().trim().to_string();
                    (url, true)
                } else {
                    (rest.to_string(), false)
                };
                pages.push(Page { id, url, selected });
            }
        }
    }
    pages
}

fn parse_script_result(val: &Value) -> Result<Value, String> {
    let text = val.get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.get(0))
        .and_then(|obj| obj.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| format!("Could not extract text field from evaluate_script result: {:?}", val))?;
        
    let start_tag = "```json";
    let end_tag = "```";
    
    if let Some(start_pos) = text.find(start_tag) {
        let json_start = start_pos + start_tag.len();
        if let Some(end_pos) = text[json_start..].find(end_tag) {
            let json_str = text[json_start..json_start + end_pos].trim();
            let parsed: Value = serde_json::from_str(json_str)
                .map_err(|e| format!("JSON parsing error: {}\nJSON content: {}", e, json_str))?;
            return Ok(parsed);
        }
    }
    
    Err(format!("Could not find JSON fencing in script result:\n{}", text))
}

fn get_diff<'a>(old: &str, new: &'a str) -> &'a str {
    let mut last_valid_byte_idx = 0;
    let mut old_chars = old.chars();
    let mut new_chars = new.char_indices();
    
    while let Some(old_c) = old_chars.next() {
        if let Some((idx, new_c)) = new_chars.next() {
            if old_c == new_c {
                last_valid_byte_idx = idx + new_c.len_utf8();
            } else {
                break;
            }
        } else {
            break;
        }
    }
    
    &new[last_valid_byte_idx..]
}

fn ensure_chatgpt_tab(config_path: &str, force_new: bool, verbose: bool) -> Result<(), String> {
    if verbose {
        println!("Checking open Chrome tabs...");
    }
    let list_res = call_mcp_tool(config_path, "list_pages", serde_json::json!({}))?;
    
    let text = list_res.get("content")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.get(0))
        .and_then(|obj| obj.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| format!("Invalid list_pages response structure: {:?}", list_res))?;
        
    let pages = parse_pages(text);
    
    if force_new {
        let old_chatgpt_ids: Vec<usize> = pages.iter()
            .filter(|p| p.url.contains("chatgpt.com"))
            .map(|p| p.id)
            .collect();
            
        if verbose {
            println!("Opening a brand new ChatGPT session...");
        }
        call_mcp_tool(config_path, "new_page", serde_json::json!({
            "url": "https://chatgpt.com/"
        }))?;
        
        for id in old_chatgpt_ids {
            if verbose {
                println!("Closing old ChatGPT tab (ID: {})...", id);
            }
            let _ = call_mcp_tool(config_path, "close_page", serde_json::json!({
                "pageId": id
            }));
        }
    } else {
        // Find any existing chatgpt page
        let chatgpt_page = pages.iter().find(|p| p.url.contains("chatgpt.com"));
        
        match chatgpt_page {
            Some(page) => {
                if page.selected {
                    if verbose {
                        println!("Found ChatGPT tab (selected).");
                    }
                } else {
                    if verbose {
                        println!("Found ChatGPT tab (ID: {}). Selecting tab...", page.id);
                    }
                    call_mcp_tool(config_path, "select_page", serde_json::json!({
                        "pageId": page.id,
                        "bringToFront": true
                    }))?;
                }
            }
            None => {
                // No ChatGPT tab. If there is only one blank tab, we navigate it. Otherwise, open a new page.
                if pages.len() == 1 && (pages[0].url == "about:blank" || pages[0].url.contains("new-tab-page") || pages[0].url.contains("chrome://welcome")) {
                    if verbose {
                        println!("Navigating existing blank tab to ChatGPT...");
                    }
                    call_mcp_tool(config_path, "navigate_page", serde_json::json!({
                        "url": "https://chatgpt.com/"
                    }))?;
                } else {
                    if verbose {
                        println!("Opening a new tab for ChatGPT...");
                    }
                    call_mcp_tool(config_path, "new_page", serde_json::json!({
                        "url": "https://chatgpt.com/"
                    }))?;
                }
            }
        }
    }
    
    // Wait for the prompt textarea to be present (the page is loaded)
    if verbose {
        println!("Waiting for ChatGPT to load...");
    }
    for _ in 0..30 {
        let ready_res = call_mcp_tool(config_path, "evaluate_script", serde_json::json!({
            "function": "() => document.getElementById('prompt-textarea') !== null"
        }))?;
        if let Ok(parsed) = parse_script_result(&ready_res) {
            if parsed.as_bool().unwrap_or(false) {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    
    Err("Timeout waiting for ChatGPT page to load".to_string())
}

fn check_login_status(config_path: &str) -> Result<bool, String> {
    let res = call_mcp_tool(config_path, "evaluate_script", serde_json::json!({
        "function": "() => document.querySelector('[data-testid=\"login-button\"]') === null"
    }))?;
    
    if let Ok(parsed) = parse_script_result(&res) {
        Ok(parsed.as_bool().unwrap_or(false))
    } else {
        Ok(false)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    let config_path = match write_mcp_config() {
        Ok(path) => path,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };
    
    let is_headless = if cli.command.is_some() {
        false // Force headful for login/open commands so user can see it
    } else {
        cli.headless
    };
    
    if let Err(e) = start_chrome_if_needed(is_headless, cli.verbose) {
        eprintln!("Error starting Chrome: {}", e);
        std::process::exit(1);
    }
    
    if let Some(command) = cli.command {
        match command {
            Commands::Open => {
                if let Err(e) = ensure_chatgpt_tab(&config_path, false, cli.verbose) {
                    eprintln!("Error ensuring ChatGPT tab: {}", e);
                    std::process::exit(1);
                }
                println!("Successfully opened ChatGPT!");
                return Ok(());
            }
            Commands::Login => {
                if let Err(e) = ensure_chatgpt_tab(&config_path, false, cli.verbose) {
                    eprintln!("Error ensuring ChatGPT tab: {}", e);
                    std::process::exit(1);
                }
                println!("\n========================================================");
                println!("Please complete the login manually in the Chrome window.");
                println!("Once you have successfully logged in, press [Enter] here.");
                println!("========================================================\n");
                
                let mut buffer = String::new();
                io::stdin().read_line(&mut buffer)?;
                
                match check_login_status(&config_path) {
                    Ok(true) => println!("Success: Logged in successfully! You can now use the `ask` command."),
                    _ => println!("Warning: We still detected a login button on the page. You might not be fully logged in. Please verify."),
                }
                return Ok(());
            }
        }
    }
    
    // Read prompt from arguments or stdin
    let mut prompt = String::new();
    if let Some(p) = cli.prompt {
        prompt = p;
    } else {
        // Check if stdin is a pipe (not a tty)
        if !std::io::stdin().is_terminal() {
            io::stdin().read_to_string(&mut prompt)?;
        }
    }
    
    let prompt = prompt.trim().to_string();
    if prompt.is_empty() {
        // No prompt and no command, print help
        let mut cmd = Cli::command();
        cmd.print_help()?;
        println!();
        std::process::exit(0);
    }
    
    if let Err(e) = ensure_chatgpt_tab(&config_path, cli.new, cli.verbose) {
        eprintln!("Error ensuring ChatGPT tab: {}", e);
        std::process::exit(1);
    }
    
    // Verify login
    match check_login_status(&config_path) {
        Ok(false) => {
            eprintln!("\nError: You are not logged in to ChatGPT.");
            eprintln!("Please run `ask login` to log in manually first, and then run your query again.\n");
            std::process::exit(1);
        }
        Err(e) => {
            if cli.verbose {
                eprintln!("Warning: Failed to verify login status: {}. Attempting to proceed...", e);
            }
        }
        _ => {}
    }
    
    // Get initial text of the latest assistant message before submitting the prompt
    let init_res = call_mcp_tool(&config_path, "evaluate_script", serde_json::json!({
        "function": r#"() => {
            const messages = document.querySelectorAll('[data-message-author-role="assistant"]');
            if (messages.length > 0) {
                const latestMessage = messages[messages.length - 1];
                const prose = latestMessage.querySelector('.markdown') || latestMessage;
                return prose.innerText;
            }
            const proseElements = document.querySelectorAll('.markdown.prose');
            if (proseElements.length > 0) {
                return proseElements[proseElements.length - 1].innerText;
            }
            return "";
        }"#
    }))?;
    let initial_text = parse_script_result(&init_res)
        .map(|v| v.as_str().unwrap_or("").to_string())
        .unwrap_or_default();
        
    if cli.verbose {
        println!("Focusing input field...");
    }
    call_mcp_tool(&config_path, "evaluate_script", serde_json::json!({
        "function": "() => { const el = document.getElementById('prompt-textarea'); if (el) { el.focus(); return true; } return false; }"
    }))?;
    
    if cli.verbose {
        println!("Typing your prompt...");
    }
    call_mcp_tool(&config_path, "type_text", serde_json::json!({
        "text": prompt
    }))?;
    
    thread::sleep(Duration::from_millis(500));
    
    if cli.verbose {
        println!("Submitting...");
    }
    call_mcp_tool(&config_path, "evaluate_script", serde_json::json!({
        "function": "() => { const btn = document.querySelector('[data-testid=\"send-button\"]') || document.getElementById('composer-submit-button'); if (btn) { btn.click(); return true; } return false; }"
    }))?;
    
    if cli.verbose {
        println!("Waiting for ChatGPT response...");
    }
    
    let is_terminal = io::stdout().is_terminal();
    let mut last_text = initial_text.clone();
    let mut finished = false;
    let mut wait_cycles = 0;
    let spinner_frames = vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let mut spinner_idx = 0;
    let mut is_thinking = true;
    
    while !finished && wait_cycles < 1200 { // Max 120 seconds (1200 * 100ms)
        if is_thinking && is_terminal {
            let frame = spinner_frames[spinner_idx % spinner_frames.len()];
            print!("\r\x1b[1;36m{}\x1b[0m 正在思考中 🧠...", frame);
            io::stdout().flush()?;
            spinner_idx += 1;
        }
        
        if wait_cycles % 5 == 0 {
            let check_res = call_mcp_tool(&config_path, "evaluate_script", serde_json::json!({
                "function": format!(r#"() => {{
                    const stopButton = document.querySelector('[data-testid="stop-button"]') || 
                                       document.getElementById('composer-stop-button') ||
                                       document.querySelector('button[aria-label="Stop generating"]');
                    
                    const messages = document.querySelectorAll('[data-message-author-role="assistant"]');
                    let text = "";
                    if (messages.length > 0) {{
                        const latestMessage = messages[messages.length - 1];
                        const prose = latestMessage.querySelector('.markdown') || latestMessage;
                        text = prose.innerText;
                    }} else {{
                        const proseElements = document.querySelectorAll('.markdown.prose');
                        if (proseElements.length > 0) {{
                            text = proseElements[proseElements.length - 1].innerText;
                        }}
                    }}
                    
                    const initialText = {:?};
                    const isNew = (text !== initialText && text.trim().length > 0);
                    
                    if (stopButton) {{
                        return {{ status: "generating", text: text, isNew: isNew }};
                    }}
                    
                    if (isNew) {{
                        return {{ status: "done", text: text, isNew: isNew }};
                    }}
                    
                    return {{ status: "waiting", text: text, isNew: isNew }};
                }}"#, initial_text)
            }))?;
            
            if let Ok(parsed) = parse_script_result(&check_res) {
                let status = parsed["status"].as_str().unwrap_or("waiting");
                let text = parsed["text"].as_str().unwrap_or("");
                let is_new = parsed["isNew"].as_bool().unwrap_or(false);
                
                if is_new && !text.is_empty() && text != last_text {
                    if is_thinking {
                        if is_terminal {
                            print!("\r\x1b[K");
                            io::stdout().flush()?;
                        }
                        is_thinking = false;
                    }
                    
                    let delta = get_diff(&last_text, text);
                    print!("{}", delta);
                    io::stdout().flush()?;
                    last_text = text.to_string();
                }
                
                if status == "done" {
                    finished = true;
                }
            }
        }
        
        thread::sleep(Duration::from_millis(100));
        wait_cycles += 1;
    }
    
    if is_thinking && is_terminal {
        print!("\r\x1b[K");
        io::stdout().flush()?;
    }
    
    println!(); // Print final newline
    
    if !finished {
        println!("\nWarning: Output stream did not complete within the timeout period.");
    }
    
    Ok(())
}
