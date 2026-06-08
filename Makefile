# Ask ChatGPT Makefile 🦀

.DEFAULT_GOAL := help

# Colors for terminal output
CYAN   := \033[1;36m
GREEN  := \033[1;32m
YELLOW := \033[1;33m
RESET  := \033[0m

##@ General

.PHONY: help
help: ## Display this help message
	@echo "$(CYAN)Ask ChatGPT (Rust Version) Makefile$(RESET)"
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-12s$(RESET) %s\n", $$1, $$2}'

##@ Development

.PHONY: check
check: ## Run cargo check to verify code compiles
	@echo "$(CYAN)Checking codebase...$(RESET)"
	cargo check

.PHONY: fmt
fmt: ## Format the code using cargo fmt
	@echo "$(CYAN)Formatting codebase...$(RESET)"
	cargo fmt

.PHONY: clippy
clippy: ## Lint the codebase using cargo clippy
	@echo "$(CYAN)Linting codebase...$(RESET)"
	cargo clippy -- -D warnings

.PHONY: clean
clean: ## Clean the cargo build artifacts
	@echo "$(CYAN)Cleaning build artifacts...$(RESET)"
	cargo clean

##@ Build

.PHONY: build
build: ## Build the project in debug mode
	@echo "$(CYAN)Building in debug mode...$(RESET)"
	cargo build

.PHONY: release
release: ## Build the project in release mode (optimized)
	@echo "$(CYAN)Building in release mode...$(RESET)"
	cargo build --release

##@ Setup & Commands

.PHONY: login
login: build ## Run the manual login process
	@echo "$(CYAN)Launching Chrome for manual login...$(RESET)"
	cargo run -- login

.PHONY: open
open: build ## Launch Chrome and open ChatGPT page
	@echo "$(CYAN)Opening ChatGPT in Chrome...$(RESET)"
	cargo run -- open

##@ Installation

.PHONY: install
install: release ## Build release and create an 'ask' symlink in ~/.local/bin/
	@echo "$(CYAN)Installing binary symlink to ~/.local/bin/ask...$(RESET)"
	@mkdir -p ~/.local/bin
	@ln -sf "$$(pwd)/target/release/ask-chatgpt" ~/.local/bin/ask
	@echo "$(GREEN)Successfully installed! You can now use the 'ask' command globally.$(RESET)"

.PHONY: uninstall
uninstall: ## Remove the 'ask' symlink from ~/.local/bin/
	@echo "$(CYAN)Uninstalling ask...$(RESET)"
	@rm -f ~/.local/bin/ask
	@echo "$(GREEN)Successfully uninstalled.$(RESET)"

##@ Verification

.PHONY: test-query
test-query: release ## Run a quick test query to verify functionality
	@echo "$(CYAN)Running verification query...$(RESET)"
	./target/release/ask-chatgpt "請用五個字自我介紹。"
