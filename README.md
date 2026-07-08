# Rails Gem Vulnerability Agent

An AI-powered agent that continuously detects, analyzes, and fixes Ruby on Rails gem vulnerabilities with minimal manual effort. It scans your Rails app, uses an LLM to understand breaking changes, upgrades gems, fixes code, runs your test suite, and optionally opens a pull request.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Orchestrator                       │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Scanner Agent                                   │
│     bundle-audit / osv-scanner                      │
│              │                                      │
│              ▼                                      │
│  2. Analyzer Agent (LLM)                            │
│     Read changelog, check Rails compat, risk score  │
│              │                                      │
│              ▼                                      │
│  3. Updater Agent                                   │
│     Edit Gemfile, run bundle update                 │
│              │                                      │
│              ▼                                      │
│  4. Fixer Agent (LLM)                               │
│     Fix breaking API changes in app code            │
│              │                                      │
│              ▼                                      │
│  5. Verifier Agent                                  │
│     bundle install / rspec / rubocop / brakeman     │
│              │                                      │
│              ▼                                      │
│  6. Retry Agent                                     │
│     If tests fail → LLM reads errors → fix → retry │
│              │                                      │
│              ▼                                      │
│  7. PR Creator Agent                                │
│     git branch / commit / push / gh pr create       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

- **Python 3.11+** (with pip)
- **Ruby** (matching your Rails app's `.ruby-version`)
- **Bundler** (`gem install bundler`)
- **bundler-audit** (`gem install bundler-audit`)
- **osv-scanner** (optional — `go install github.com/google/osv-scanner/cmd/osv-scanner@latest`)
- **brakeman** (optional — `gem install brakeman`)
- **GitHub CLI** (optional, for PR creation — `brew install gh`)

## Setup

```bash
cd /Users/avinashkumar/Documents/bitbucket/rails-gem-vuln-agent

# 1. Create Python virtual environment
python3 -m venv venv
source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Copy environment file
cp .env.example .env

# 4. Install bundler-audit for your Ruby version
gem install bundler-audit
```

## LLM Provider Configuration

The agent supports 3 AI providers. Set up whichever you have access to.

### Option A: Internal Gen AI Gateway (Bedrock — same as lx-edcast)

Uses the same JWT-authenticated API gateway from `lx-edcast/config/settings.yml` backed by AWS Bedrock (Amazon Nova / Claude models).

Edit `.env`:
```bash
# Copy these values from your deployment environment or settings.yml
GEN_AI_API_PRIVATE_KEY=<your RSA private key>
GEN_AI_API_PUBLIC_KEY_URL=<your JWKS URL>
GEN_AI_API_PUBLIC_KEY_ID=<your key ID>
GEN_AI_API_HOST=<your Gen AI gateway URL>
GEN_AI_AUD_URL=<your audience URL>

# Optional: Bedrock-specific endpoint
GEN_AI_BEDROCK_API_HOST=<bedrock endpoint if separate>
GEN_AI_BEDROCK_AUD_URL=<bedrock audience URL>
```

Then set provider in `config.yaml`:
```yaml
llm:
  provider: gen_ai
  model: amazon-nova-lite   # or anthropic.claude-3-5-sonnet-20241022-v2:0
```

> The agent auto-detects: if no OpenAI/Anthropic key is present but `GEN_AI_API_HOST` is set, it will automatically use Gen AI without changing `config.yaml`.

### Option B: OpenAI

Edit `.env`:
```bash
OPENAI_API_KEY=sk-your-key-here
```

`config.yaml`:
```yaml
llm:
  provider: openai
  model: gpt-4o
```

### Option C: Anthropic

Edit `.env`:
```bash
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

`config.yaml`:
```yaml
llm:
  provider: anthropic
  model: claude-sonnet-4-20250514
```

## Usage

### 1. Quick Scan (no AI, no API key needed)

Just runs `bundle-audit` and shows a vulnerability table:

```bash
source venv/bin/activate
python scan_only.py /path/to/your/rails/app
```

Example:
```bash
python scan_only.py ../hrms_app
```

Output:
```
Rails App: /Users/avinashkumar/Documents/bitbucket/hrms_app
  Rails: 4.2.2 | Ruby: 3.4.7 | Gems: 228
  Tests: minitest | Sidekiq: ✓

                    Vulnerabilities Found (12)
┌──────────────┬─────────┬─────────┬───────────────┬──────────┬───────────────┐
│ Gem          │ Current │ Patched │ CVE           │ Severity │ Title         │
├──────────────┼─────────┼─────────┼───────────────┼──────────┼───────────────┤
│ devise       │ 4.9.4   │ 5.0.3   │ CVE-2026-327  │ MEDIUM   │ Confirmable   │
│ savon        │ 2.15.1  │ 2.17.2  │ CVE-2026-535  │ HIGH     │ Savon::Model  │
│ ...          │         │         │               │          │               │
└──────────────┴─────────┴─────────┴───────────────┴──────────┴───────────────┘
```

### 2. Dry Run with Mock LLM (no API key needed)

Tests the full pipeline end-to-end without making any changes or calling any AI:

```bash
python main.py --rails-app ../hrms_app --dry-run --mock-llm
```

This will:
- Scan for vulnerabilities
- Run mock AI analysis (determines risk level, breaking changes)
- Skip high-risk upgrades (devise 4→5, webrick with no patch)
- Report what it *would* do for safe upgrades
- Generate a JSON report

### 3. Dry Run with Real LLM (requires API key)

Same as above but uses real AI for smarter analysis:

```bash
python main.py --rails-app ../hrms_app --dry-run
```

This calls the LLM to analyze changelogs, check compatibility, and produce a real risk assessment — but does NOT modify any files.

### 4. Fix All Vulnerabilities (real run)

Actually upgrades gems, fixes code, and runs tests:

```bash
python main.py --rails-app ../hrms_app
```

What happens:
1. Scans for vulnerabilities
2. For each vulnerability (sorted by risk):
   - AI analyzes breaking changes and compatibility
   - Skips high-risk upgrades unless forced
   - Updates Gemfile + runs `bundle update <gem>`
   - AI fixes any breaking API changes in your code
   - Runs full test suite (rspec/minitest + rubocop + brakeman + bundle-audit)
   - If tests fail → AI reads errors → generates fix → re-runs tests (up to 3 retries)
   - If still failing → rolls back changes automatically

### 5. Fix a Specific Gem

Target a single gem (useful for high-risk upgrades that need attention):

```bash
python main.py --rails-app ../hrms_app --gem devise
python main.py --rails-app ../hrms_app --gem concurrent-ruby
```

### 6. Fix and Create Pull Request

After successful fixes, create a GitHub PR:

```bash
python main.py --rails-app ../hrms_app --create-pr
```

Requires:
- `gh` CLI installed and authenticated (`gh auth login`)
- Git repo with a remote

### 7. Custom Retry Limit

Override the max number of fix attempts when tests fail:

```bash
python main.py --rails-app ../hrms_app --max-retries 5
```

## CLI Reference

```
Usage: python main.py [OPTIONS]

Options:
  --rails-app PATH    Path to the Rails application root (required)
  --dry-run           Scan and analyze only, do not modify files
  --mock-llm          Use mock AI responses (no API key needed)
  --gem TEXT          Fix a specific gem only
  --max-retries INT  Override max retry attempts (default: 3)
  --config PATH      Path to config file (default: config.yaml)
  --create-pr        Create a GitHub PR after successful fixes
  --help             Show this message and exit
```

## Configuration (config.yaml)

Key settings you may want to customize:

```yaml
llm:
  provider: gen_ai          # openai | anthropic | gen_ai
  model: amazon-nova-lite   # model name for your provider
  temperature: 0.2          # lower = more deterministic

scanner:
  tools:
    - bundle-audit
    - osv-scanner            # comment out if not installed
  severity_threshold: medium # low | medium | high | critical

updater:
  strategy: minimum          # minimum (smallest safe bump) | latest
  pin_in_gemfile: true       # add version constraint to Gemfile

verifier:
  steps:
    - bundle install
    - bundle exec rspec
    - bundle exec rubocop --autocorrect-all
    - bundle exec brakeman --no-pager -q
    - bundle audit check
  rails_checks:
    - bin/rails zeitwerk:check

retry:
  max_attempts: 3
  rollback_on_failure: true  # auto-rollback if fix fails

pr:
  branch_pattern: "security/fix-{gem}-{cve}"
  labels: [security, automated]
```

## How It Works (Detailed Flow)

```
Scheduler / Manual trigger
  │
  ▼
bundle-audit check
  │
  ▼
Found CVE-2026-XXXXX in gem_name
  │
  ▼
LLM reads advisory + changelog + Rails version
  │
  ▼
Risk assessment: LOW → proceed / HIGH → skip (unless forced)
  │
  ▼
Edit Gemfile → bundle update gem_name
  │
  ▼
LLM proactively fixes known breaking changes
  │
  ▼
Run tests (rspec/minitest)
  │
  ├── PASS → ✓ Continue to next vulnerability
  │
  └── FAIL → LLM reads test output → generates fix → retry
              │
              ├── PASS after retry → ✓ Continue
              │
              └── FAIL after max retries → rollback → mark as failed
  │
  ▼
All done → Create PR with full security summary
```

## Project Structure

```
rails-gem-vuln-agent/
├── main.py                    # CLI entry point
├── scan_only.py               # Standalone scanner (no AI)
├── config.yaml                # All configurable settings
├── config_loader.py           # YAML + env config loading
├── requirements.txt           # Python dependencies
├── run_local.sh               # Quick-start shell script
├── .env.example               # Environment variables template
├── .gitignore
├── agents/
│   ├── __init__.py
│   ├── models.py              # Data models (Vulnerability, FixResult, etc.)
│   ├── llm_client.py          # LLM factory (auto-detects provider)
│   ├── gen_ai_client.py       # Internal Gen AI gateway client (Bedrock)
│   ├── mock_llm.py            # Mock LLM for testing without API keys
│   ├── scanner.py             # Agent 1: bundle-audit + osv-scanner
│   ├── analyzer.py            # Agent 2: LLM analysis + risk scoring
│   ├── updater.py             # Agent 3: Gemfile editing + bundle update
│   ├── fixer.py               # Agent 4: LLM code fixer (breaking changes)
│   ├── verifier.py            # Agent 5: rspec/rubocop/brakeman/audit
│   ├── orchestrator.py        # Pipeline coordinator + retry logic
│   ├── pr_creator.py          # Agent 7: git + GitHub PR via `gh` CLI
│   └── utils.py               # Helpers (semver, Rails detection)
├── reports/                   # Generated JSON reports (gitignored)
└── .github/workflows/
    └── security-fix-agent.yml # CI: scheduled + manual trigger
```

## GitHub Actions Integration

Add to your Rails app's CI for automated weekly scans:

```yaml
name: Security Fix Agent
on:
  schedule:
    - cron: "0 2 * * 1"  # Every Monday 2 AM
  workflow_dispatch:
    inputs:
      target_gem:
        description: "Specific gem to fix (leave empty for all)"
        required: false
      dry_run:
        description: "Dry run (scan only)"
        type: boolean
        default: false
```

See `.github/workflows/security-fix-agent.yml` for the full workflow.

## Reports

Every run generates a JSON report in `reports/`:

```json
{
  "timestamp": "2026-07-07T15:44:58",
  "rails_app": "/path/to/app",
  "vulnerabilities_found": 11,
  "vulnerabilities_fixed": 8,
  "vulnerabilities_failed": 0,
  "vulnerabilities_skipped": 3,
  "pr_url": "https://github.com/org/repo/pull/42",
  "details": [
    {
      "gem": "concurrent-ruby",
      "cve": "CVE-2026-54904",
      "status": "success",
      "attempts": 1,
      "gemfile_changes": ["Updated Gemfile.lock: concurrent-ruby → 1.3.7"],
      "code_changes": []
    }
  ]
}
```

## Troubleshooting

### `bundle-audit` not found or times out
```bash
# Install for your current Ruby version
gem install bundler-audit

# If using RVM, ensure it's on the right Ruby
rvm use 3.4.7
gem install bundler-audit
```

### No vulnerabilities found (false negative)
- Ensure `bundle-audit` is installed for the same Ruby version as your app
- Run `bundle-audit update` to refresh the advisory database
- Try running directly: `cd /path/to/app && bundle-audit check`

### LLM not connecting
- Check your `.env` has the correct keys
- For Gen AI gateway: ensure the private key has proper `\n` line breaks
- Test with `--mock-llm` first to confirm the pipeline works

### Tests timing out
- Increase `verifier.timeout_seconds` in `config.yaml` (default: 600s)
- For large test suites, consider targeting specific gems: `--gem <name>`

## License

MIT
