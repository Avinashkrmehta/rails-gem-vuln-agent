"""Mock LLM Client for testing the pipeline without API keys.

Returns realistic but hardcoded responses for each agent stage.
"""

import json
import logging
import re

from .models import Vulnerability

logger = logging.getLogger("vuln-agent.mock-llm")


class MockLLMClient:
    """Simulates LLM responses for end-to-end dry run testing."""

    def __init__(self, config: dict):
        self.provider = "mock"
        self.model = "mock-model"
        logger.info("Using MOCK LLM client (no API key required)")

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        json_mode: bool = False,
    ) -> str:
        """Return a mock response based on the context of the prompt."""
        logger.debug(f"[MOCK LLM] Generating response for: {user_message[:80]}...")

        # Detect which agent is calling based on system prompt content
        if "upgrade plan" in system_prompt.lower() or "breaking changes" in system_prompt.lower():
            return self._mock_analysis_response(user_message)
        elif "fixing code" in system_prompt.lower() or "file modifications" in system_prompt.lower():
            return self._mock_fixer_response(user_message)
        else:
            return self._mock_generic_response(user_message)

    def _mock_analysis_response(self, user_message: str) -> str:
        """Generate a mock analysis response."""
        # Extract gem name and version info from the prompt
        gem_match = re.search(r"Gem:\s*(\S+)", user_message)
        current_match = re.search(r"Current Version:\s*(\S+)", user_message)
        patched_match = re.search(r"Patched Versions?:\s*(.+?)(?:\n|$)", user_message)

        gem_name = gem_match.group(1) if gem_match else "unknown"
        current_version = current_match.group(1) if current_match else "0.0.0"
        patched_raw = patched_match.group(1).strip() if patched_match else ""

        # Extract version number from patched string
        version_match = re.search(r"(\d+\.\d+\.\d+)", patched_raw)
        recommended = version_match.group(1) if version_match else "999.0.0"

        # Determine risk based on major version bump
        current_major = int(current_version.split(".")[0]) if current_version[0].isdigit() else 0
        recommended_major = int(recommended.split(".")[0]) if recommended[0].isdigit() else 0

        is_major_bump = recommended_major > current_major
        risk_level = "high" if is_major_bump else "low"
        risk_score = 0.7 if is_major_bump else 0.2
        safe_to_auto = not is_major_bump

        # Gem-specific mock breaking changes
        breaking_changes = []
        requires_code_changes = False
        code_change_desc = ""

        if gem_name == "devise" and is_major_bump:
            breaking_changes = [
                "Devise 5.x removes `Devise::Models::Authenticatable#update_without_password` deprecated behavior",
                "Token generator now uses `ActiveSupport::KeyGenerator` by default",
                "Confirmable module requires explicit `confirm` call",
            ]
            requires_code_changes = True
            code_change_desc = "Update Devise initializer and any custom authentication logic"
        elif gem_name == "sidekiq" and is_major_bump:
            breaking_changes = [
                "`Sidekiq::Worker` is renamed to `Sidekiq::Job`",
                "Sidekiq.configure_server block API changed",
            ]
            requires_code_changes = True
            code_change_desc = "Replace Sidekiq::Worker with Sidekiq::Job in all workers"
        elif gem_name == "concurrent-ruby":
            breaking_changes = []
            requires_code_changes = False
        elif gem_name == "savon":
            breaking_changes = [
                "WSDL parsing now validates operation names strictly",
            ]
            requires_code_changes = False
            code_change_desc = ""

        response = {
            "recommended_version": recommended,
            "breaking_changes": breaking_changes,
            "migration_steps": [
                f"Update Gemfile constraint for {gem_name}",
                f"Run bundle update {gem_name}",
                "Run test suite to verify compatibility",
            ],
            "rails_compatibility": "Compatible with Rails 4.2+ (verified)",
            "risk_level": risk_level,
            "risk_score": risk_score,
            "changelog_summary": f"Patch release fixing security vulnerability. {'Major version with breaking API changes.' if is_major_bump else 'No breaking changes expected.'}",
            "requires_code_changes": requires_code_changes,
            "code_change_description": code_change_desc,
            "safe_to_auto_upgrade": safe_to_auto,
        }

        return json.dumps(response)

    def _mock_fixer_response(self, user_message: str) -> str:
        """Generate a mock code fix response."""
        # Check if this is a Sidekiq-related fix
        if "Sidekiq::Worker" in user_message or "sidekiq" in user_message.lower():
            return json.dumps({
                "fixes": [
                    {
                        "file": "app/workers/example_worker.rb",
                        "description": "Replace Sidekiq::Worker with Sidekiq::Job",
                        "search": "include Sidekiq::Worker",
                        "replace": "include Sidekiq::Job",
                    }
                ],
                "explanation": "Updated Sidekiq::Worker references to Sidekiq::Job for Sidekiq 7+ compatibility",
            })
        elif "devise" in user_message.lower():
            return json.dumps({
                "fixes": [
                    {
                        "file": "config/initializers/devise.rb",
                        "description": "Update Devise configuration for v5 compatibility",
                        "search": "# config.secret_key",
                        "replace": "# config.secret_key (Devise 5+ uses Rails secret_key_base)",
                    }
                ],
                "explanation": "Updated Devise initializer for v5 compatibility",
            })
        else:
            return json.dumps({
                "fixes": [],
                "explanation": "No code changes needed for this upgrade",
            })

    def _mock_generic_response(self, user_message: str) -> str:
        """Generic mock response."""
        return json.dumps({
            "status": "ok",
            "message": "Mock response - no actual LLM call made",
        })
