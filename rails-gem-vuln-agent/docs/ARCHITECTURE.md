# Architecture & Codebase Guide

This document explains the full architecture, data flow, and codebase structure of the Rails Gem Vulnerability Agent. It's written for developers who want to understand, modify, or extend the system.

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          main.py (CLI)                                │
│                                                                      │
│  Parses CLI args → loads config → creates Orchestrator → runs        │
└──────────────────────────────┬───────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                      Orchestrator (orchestrator.py)                   │
│                                                                      │
│  Coordinates all agents sequentially for each vulnerability          │
│  Handles retry logic, rollback, and report generation                │
└──────┬──────┬──────┬──────┬──────┬──────┬──────┬────────────────────┘
       │      │      │      │      │      │      │
       ▼      ▼      ▼      ▼      ▼      ▼      ▼
   Scanner Analyzer Updater Fixer Verifier Retry PRCreator
```

---

## Execution Flow (Step by Step)

```
User runs:
  python main.py --rails-app ../hrms_app --gem concurrent-ruby --create-pr --jira-ticket EP-1234
```

### Phase 1: Initialization

```
main.py
  │
  ├─ load_dotenv()                    # Load .env file
  ├─ load_config("config.yaml")      # Merge YAML + env overrides
  ├─ Validate Rails app path          # Check Gemfile exists
  │
  └─ VulnerabilityOrchestrator(...)   # Create orchestrator with all agents
       │
       ├─ create_llm_client()         # Auto-detect LLM provider:
       │    ├─ --mock-llm?  → MockLLMClient (no API call)
       │    ├─ provider=gen_ai? → GenAIClient (Bedrock gateway)
       │    ├─ OPENAI_API_KEY set? → LLMClient(openai)
       │    ├─ GEN_AI_API_HOST set? → GenAIClient (auto-fallback)
       │    └─ ANTHROPIC_API_KEY? → LLMClient(anthropic)
       │
       ├─ ScannerAgent(rails_path, config)
       ├─ AnalyzerAgent(rails_path, config, llm_client)
       ├─ UpdaterAgent(rails_path, config)
       ├─ FixerAgent(rails_path, config, llm_client)
       ├─ VerifierAgent(rails_path, config)
       └─ PRCreatorAgent(rails_path, config, jira_ticket)
```

### Phase 2: Scanning (scanner.py)

```
ScannerAgent.scan()
  │
  ├─ run_ruby_command("bundle-audit --version")   # Check tool exists (login shell)
  │
  ├─ run_ruby_command("bundle-audit update")       # Update advisory DB
  │
  ├─ run_ruby_command("bundle-audit check --format json")
  │    │
  │    ├─ Exit 0 → No vulnerabilities found
  │    └─ Exit 1 → Parse JSON output → list[Vulnerability]
  │         │
  │         └─ Fallback: parse text output if JSON fails
  │
  ├─ (optional) osv-scanner --lockfile Gemfile.lock --format json
  │
  ├─ Deduplicate by CVE
  │
  └─ Filter by severity_threshold (config: low/medium/high/critical)
       │
       └─ Returns: list[Vulnerability]
```

**Data Model: Vulnerability**
```python
@dataclass
class Vulnerability:
    gem: str                    # "concurrent-ruby"
    current_version: str        # "1.3.6"
    patched_versions: list[str] # [">= 1.3.7"]
    cve: str                    # "CVE-2026-54904"
    title: str                  # "AtomicReference race condition"
    severity: Severity          # MEDIUM
    advisory_url: str
    description: str
```

### Phase 3: Analysis (analyzer.py)

```
AnalyzerAgent.analyze(vulnerability)
  │
  ├─ Gather context:
  │    ├─ Detect Rails version (from Gemfile.lock)
  │    ├─ Detect Ruby version (from .ruby-version)
  │    ├─ Get Gemfile entry for gem
  │    └─ Find dependent gems (from Gemfile.lock dependency tree)
  │
  ├─ Build LLM prompt:
  │    "Gem: concurrent-ruby, Current: 1.3.6, Patched: >= 1.3.7
  │     Rails: 4.2.2, Ruby: 3.4.7
  │     Question: Can this be upgraded safely? Breaking changes?"
  │
  ├─ LLM.chat(system_prompt, user_message, json_mode=True)
  │    │
  │    ├─ Gen AI Gateway → POST /v3/generate (JWT auth, Bedrock)
  │    ├─ OpenAI → POST /chat/completions
  │    ├─ Anthropic → POST /messages
  │    └─ Mock → hardcoded response based on semver analysis
  │
  └─ Parse LLM JSON response → AnalysisResult
```

**Data Model: AnalysisResult**
```python
@dataclass
class AnalysisResult:
    vulnerability: Vulnerability
    recommended_version: str      # "1.3.7"
    breaking_changes: list[str]   # []
    migration_steps: list[str]    # ["Update Gemfile", "bundle update"]
    rails_compatibility: str      # "Compatible with Rails 4.2+"
    risk_level: RiskLevel         # LOW
    risk_score: float             # 0.2
    requires_code_changes: bool   # False
    code_change_description: str  # ""
    safe_to_auto_upgrade: bool    # True
```

**Decision Point:**
```
if risk_level == HIGH and not --gem flag:
    → SKIP (manual review required)
if dry_run:
    → SKIP (report only)
else:
    → PROCEED to update
```

### Phase 4: Update (updater.py)

```
UpdaterAgent.update(analysis)
  │
  ├─ Save git state (git rev-parse HEAD) for potential rollback
  │
  ├─ Update Gemfile (if gem is directly listed):
  │    ├─ Regex match: gem 'concurrent-ruby', '~> 1.3'
  │    └─ Replace with: gem 'concurrent-ruby', '>= 1.3.7'
  │
  ├─ run_ruby_command("bundle update concurrent-ruby")
  │    │                    ↑ login shell ensures correct Ruby version
  │    │
  │    ├─ Success → continue
  │    └─ Failure → retry with --conservative flag
  │         │
  │         ├─ Success → continue
  │         └─ Failure → ROLLBACK, mark as FAILED
  │
  └─ Returns: {success: bool, changes: list, error: str}
```

**Key: shell_runner.py**
```
All Ruby commands run through:
  zsh -l -c "cd /path/to/app && bundle update gem"
       ^
       └─ Login shell loads ~/.zshrc → initializes RVM → correct Ruby version
```

### Phase 5: Code Fix (fixer.py)

```
FixerAgent.fix_breaking_changes(analysis)
  │
  ├─ Skip if analysis.requires_code_changes == False
  │
  ├─ Find affected files:
  │    grep -rl "Sidekiq::Worker" --include=*.rb .
  │    (patterns based on gem name + breaking_changes)
  │
  ├─ Send to LLM:
  │    "Gem sidekiq upgraded 6→8. Sidekiq::Worker is now Sidekiq::Job.
  │     Here are the affected files: [code]
  │     Generate JSON fixes."
  │
  ├─ LLM returns:
  │    {"fixes": [
  │      {"file": "app/workers/foo.rb",
  │       "search": "include Sidekiq::Worker",
  │       "replace": "include Sidekiq::Job"}
  │    ]}
  │
  └─ Apply each fix:
       file.read() → str.replace(search, replace) → file.write()
```

### Phase 6: Verification (verifier.py)

```
VerifierAgent.verify()
  │
  ├─ bundle install              (stream_output=True → real-time logs)
  │    └─ FAIL? → return immediately
  │
  ├─ Detect test framework:
  │    ├─ spec/ exists → bundle exec rspec (stream_output=True)
  │    └─ test/ exists → bundle exec rails test (stream_output=True)
  │
  ├─ bundle exec rubocop --autocorrect-all
  │
  ├─ bundle exec brakeman --no-pager -q
  │
  ├─ bundle-audit check (confirm CVE is fixed)
  │
  └─ Rails checks: bin/rails zeitwerk:check (if configured)
       │
       └─ Returns: VerificationResult
            success = tests_passed AND bundle_install
```

**Data Model: VerificationResult**
```python
@dataclass
class VerificationResult:
    success: bool
    bundle_install: bool
    tests_passed: bool
    rubocop_passed: bool
    brakeman_passed: bool
    audit_clean: bool
    failed_specs: list[str]     # ["spec/models/user_spec.rb:42"]
    warnings: list[str]
    stdout: str                 # Full test output (for retry agent)
    stderr: str
```

### Phase 7: Retry Loop (orchestrator.py)

```
while not verification.success and attempts < max_retries:
  │
  ├─ FixerAgent.fix_from_test_failure(
  │      analysis, test_output, failed_specs)
  │    │
  │    ├─ Extract relevant source files from stack traces
  │    │
  │    ├─ Send to LLM:
  │    │    "Tests failed after upgrading gem. Here's the error:
  │    │     Expected: foo, Got: bar
  │    │     Source code: [relevant files]
  │    │     Generate JSON fixes."
  │    │
  │    └─ Apply fixes
  │
  ├─ Re-run VerifierAgent.verify()
  │
  └─ attempts += 1

If still failing after max_retries:
  → git checkout -- .   (rollback all changes)
  → mark as ROLLED_BACK
```

### Phase 8: PR Creation (pr_creator.py)

```
PRCreatorAgent.create_pr(analysis, fix_result, verification)
  │
  ├─ Detect platform:
  │    ├─ GIT_PLATFORM env var (explicit)
  │    ├─ BITBUCKET_SERVER_URL set → bitbucket
  │    └─ git remote URL contains "bitbucket" → bitbucket
  │
  ├─ Generate branch name:
  │    "EP-1234/fix-concurrent-ruby-202654904"
  │     ^jira    ^gem          ^cve
  │
  ├─ git checkout -b <branch>
  │
  ├─ git add -A
  │
  ├─ git commit -m "EP-1234: fix(security): Upgrade concurrent-ruby to 1.3.7"
  │                  ^jira ticket satisfies YACC hook
  │
  ├─ git push -u origin <branch>
  │
  └─ Create PR via API:
       ├─ Bitbucket Server: POST /rest/api/1.0/projects/{project}/repos/{slug}/pull-requests
       ├─ Bitbucket Cloud:  POST /2.0/repositories/{workspace}/{slug}/pullrequests
       └─ GitHub:           POST /repos/{owner}/{repo}/pulls (or gh CLI)
```

---

## File-by-File Breakdown

### Entry Points

| File | Purpose |
|------|---------|
| `main.py` | CLI entry point. Parses args, loads config, runs orchestrator |
| `scan_only.py` | Standalone scanner with table output (no AI, no fixes) |
| `run_local.sh` | Quick-start script (creates venv, installs deps, runs) |

### Core Agents (agents/)

| File | Agent | Responsibility |
|------|-------|----------------|
| `orchestrator.py` | Orchestrator | Coordinates all agents, retry loop, rollback, report |
| `scanner.py` | Scanner | Runs bundle-audit/osv-scanner, parses vulnerabilities |
| `analyzer.py` | Analyzer | LLM analysis: risk, breaking changes, compatibility |
| `updater.py` | Updater | Edits Gemfile, runs bundle update |
| `fixer.py` | Fixer | LLM-driven code changes for breaking APIs |
| `verifier.py` | Verifier | Runs test suite, rubocop, brakeman, audit |
| `pr_creator.py` | PR Creator | Git branch/commit/push, API call to create PR |

### Infrastructure (agents/)

| File | Purpose |
|------|---------|
| `models.py` | All data models (Vulnerability, AnalysisResult, FixResult, etc.) |
| `llm_client.py` | LLM factory + OpenAI/Anthropic client |
| `gen_ai_client.py` | Internal Gen AI gateway client (JWT + Bedrock) |
| `mock_llm.py` | Mock LLM for testing without API keys |
| `shell_runner.py` | Login shell wrapper for Ruby commands (RVM support) |
| `utils.py` | Helpers: semver parsing, Rails app detection |

### Configuration

| File | Purpose |
|------|---------|
| `config.yaml` | All settings (LLM, scanner, verifier, PR, retry) |
| `config_loader.py` | Loads YAML + merges env var overrides |
| `.env` / `.env.example` | API keys and credentials |

---

## LLM Provider Selection Flow

```
create_llm_client(config, mock=False)
  │
  ├─ mock=True?
  │    └─ YES → MockLLMClient (hardcoded responses, no API)
  │
  ├─ config.provider == "gen_ai"?
  │    └─ YES → GenAIClient (JWT auth → Bedrock gateway)
  │
  ├─ config.provider == "openai" AND OPENAI_API_KEY is empty?
  │    ├─ GEN_AI_API_HOST set? → GenAIClient (auto-fallback)
  │    ├─ ANTHROPIC_API_KEY set? → LLMClient(anthropic)
  │    └─ Neither? → ERROR with helpful message
  │
  ├─ config.provider == "anthropic" AND ANTHROPIC_API_KEY is empty?
  │    ├─ GEN_AI_API_HOST set? → GenAIClient (auto-fallback)
  │    ├─ OPENAI_API_KEY set? → LLMClient(openai)
  │    └─ Neither? → ERROR
  │
  └─ Key is present → LLMClient(configured provider)
```

### Gen AI Gateway Authentication (gen_ai_client.py)

```
GenAIClient._generate_jwt_token()
  │
  ├─ Read GEN_AI_API_PRIVATE_KEY (RSA PEM)
  ├─ Build JWT payload:
  │    iss: "EDX"
  │    aud: GEN_AI_AUD_URL
  │    sub: "Edcast-LXP"
  │    x-app: "EDX"
  │    exp: now + 4 hours
  │
  ├─ Sign with RS256
  │
  └─ Return token string

GenAIClient.chat(system_prompt, user_message)
  │
  ├─ POST {GEN_AI_API_HOST}/v3/generate
  │    Headers:
  │      Authorization: Bearer <jwt_token>
  │      Content-Type: application/json
  │      x-ai-usecase: lxp-security-vuln-agent
  │    Body:
  │      { prompt, system_message, max_tokens, temperature, model }
  │
  └─ Parse response.processed_response → text
```

---

## Shell Execution (shell_runner.py)

**Problem:** Python's subprocess doesn't load `~/.zshrc`, so RVM isn't initialized and the wrong Ruby version is used.

**Solution:** Wrap all Ruby commands in a login shell:

```python
run_ruby_command(["bundle", "update", "gem"], cwd=rails_path)

# Internally executes:
#   /bin/zsh -l -c "cd '/path/to/app' && bundle update gem"
#                ^
#                └─ Login shell loads ~/.zshrc → source rvm → correct Ruby
```

**stream_output=True** (used by verifier for tests):
```
Uses subprocess.Popen with line-buffered stdout.
Each line is printed to console with "    │ " prefix
AND captured in result.stdout for the retry agent.
```

---

## Complete Sequence Diagram

```
User                    main.py          Orchestrator        Scanner
 │                        │                   │                │
 │─── python main.py ────▶│                   │                │
 │                        │── create ────────▶│                │
 │                        │                   │── scan() ─────▶│
 │                        │                   │                │── bundle-audit
 │                        │                   │                │◀─ vulnerabilities
 │                        │                   │◀───────────────│
 │                        │                   │
 │                        │                   │    Analyzer     Updater
 │                        │                   │       │           │
 │                        │                   │──────▶│           │
 │                        │                   │       │── LLM call
 │                        │                   │       │◀─ analysis
 │                        │                   │◀──────│           │
 │                        │                   │                   │
 │                        │                   │──────────────────▶│
 │                        │                   │                   │── edit Gemfile
 │                        │                   │                   │── bundle update
 │                        │                   │◀──────────────────│
 │                        │                   │
 │                        │                   │    Fixer      Verifier
 │                        │                   │      │           │
 │                        │                   │─────▶│           │
 │                        │                   │      │── LLM call
 │                        │                   │      │── apply fixes
 │                        │                   │◀─────│           │
 │                        │                   │                  │
 │                        │                   │─────────────────▶│
 │  (test output streams) │                   │                  │── rspec/minitest
 │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ │── rubocop
 │                        │                   │                  │── brakeman
 │                        │                   │◀─────────────────│
 │                        │                   │
 │                        │                   │   (if tests fail + retries left)
 │                        │                   │──── Fixer → fix from errors
 │                        │                   │──── Verifier → re-run tests
 │                        │                   │
 │                        │                   │    PRCreator
 │                        │                   │       │
 │                        │                   │──────▶│
 │                        │                   │       │── git branch
 │                        │                   │       │── git commit
 │                        │                   │       │── git push
 │                        │                   │       │── Bitbucket API
 │                        │                   │◀──────│
 │                        │                   │
 │                        │◀──────────────────│ (results)
 │◀───── summary ─────────│
 │
```

---

## State Transitions per Vulnerability

```
                    ┌──────────┐
                    │ PENDING  │
                    └────┬─────┘
                         │ orchestrator picks it up
                         ▼
                    ┌──────────────┐
                    │ IN_PROGRESS  │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
              ▼            ▼            ▼
        ┌─────────┐  ┌─────────┐  ┌─────────────┐
        │ SUCCESS │  │ SKIPPED │  │   FAILED    │
        └─────────┘  └─────────┘  └──────┬──────┘
                                         │ rollback_on_failure=true
                                         ▼
                                   ┌─────────────┐
                                   │ ROLLED_BACK │
                                   └─────────────┘

SKIPPED reasons:
  - dry_run mode
  - High risk + not forced with --gem
  - safe_to_auto_upgrade=False + not forced

FAILED reasons:
  - bundle update failed (dependency conflict)
  - Tests failed after max retries
  - Bundle install failed
```

---

## Configuration Reference (config.yaml)

```yaml
llm:
  provider: gen_ai        # Which LLM to use
  model: amazon-nova-lite # Model for the selected provider
  temperature: 0.2        # Lower = more deterministic
  max_tokens: 4096        # Max response length

scanner:
  tools: [bundle-audit]   # Scanning tools to use
  severity_threshold: medium  # Minimum severity to process

updater:
  strategy: minimum       # minimum = smallest safe bump
  pin_in_gemfile: true    # Whether to add version constraint

verifier:
  steps: [...]            # Verification commands to run
  timeout_seconds: 600    # Max time for test suite

retry:
  max_attempts: 3         # How many times to retry on test failure
  rollback_on_failure: true  # Auto-revert if fix fails

pr:
  branch_pattern: "security/fix-{gem}-{cve}"
  labels: [security, automated]
  reviewers: [team-lead]
```

---

## Extending the Agent

### Add a new LLM provider

1. Create `agents/my_provider_client.py` with a `chat(system_prompt, user_message, json_mode)` method
2. Add detection logic in `llm_client.py` → `create_llm_client()`

### Add a new scanner

1. Add method `_run_my_scanner()` in `scanner.py`
2. Add `"my-scanner"` to `config.yaml` → `scanner.tools`
3. Parse output into `list[Vulnerability]`

### Add a new verification step

1. Add to `config.yaml` → `verifier.steps`
2. Or add a new method in `verifier.py` and call it from `verify()`

### Add a new git platform (e.g., GitLab)

1. Add `_create_gitlab_pr()` in `pr_creator.py`
2. Add detection in `_detect_platform()`
3. Route in `create_pr()` based on platform
