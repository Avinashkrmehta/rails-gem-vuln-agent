"""LLM Client - Abstraction over OpenAI, Anthropic, and internal Gen AI APIs."""

import os
import logging
from typing import Optional

logger = logging.getLogger("vuln-agent.llm")


def create_llm_client(config: dict, mock: bool = False):
    """Factory to create the appropriate LLM client.

    Provider selection priority:
    1. If mock=True, use mock client (no API key needed)
    2. If provider is 'gen_ai' in config, use internal Gen AI gateway
    3. If provider is 'openai' but OPENAI_API_KEY is empty/missing,
       fall back to Gen AI if available
    4. If provider is 'anthropic' but ANTHROPIC_API_KEY is empty/missing,
       fall back to Gen AI if available
    5. Otherwise use the configured provider
    """
    if mock:
        from .mock_llm import MockLLMClient
        return MockLLMClient(config)

    provider = config.get("provider", "openai")

    # Check if gen_ai is explicitly configured
    if provider == "gen_ai":
        from .gen_ai_client import GenAIClient
        return GenAIClient(config)

    # Check what keys are actually available (non-empty)
    openai_key = os.environ.get("OPENAI_API_KEY", "").strip()
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    has_gen_ai = bool(
        os.environ.get("GEN_AI_API_HOST", "").strip()
        or os.environ.get("GEN_AI_BEDROCK_API_HOST", "").strip()
    )

    # If configured provider's key is missing, try to fall back
    if provider == "openai" and not openai_key:
        if has_gen_ai:
            logger.info(
                "OPENAI_API_KEY is empty. Falling back to Gen AI gateway "
                "(GEN_AI_API_HOST is set)."
            )
            from .gen_ai_client import GenAIClient
            return GenAIClient(config)
        elif anthropic_key:
            logger.info("OPENAI_API_KEY is empty. Falling back to Anthropic.")
            config["provider"] = "anthropic"
            return LLMClient(config)
        else:
            raise RuntimeError(
                "No LLM provider available.\n"
                "Set one of:\n"
                "  - OPENAI_API_KEY (for OpenAI)\n"
                "  - ANTHROPIC_API_KEY (for Anthropic)\n"
                "  - GEN_AI_API_HOST + GEN_AI_API_PRIVATE_KEY (for internal Gen AI)\n"
                "Or use --mock-llm for testing."
            )

    if provider == "anthropic" and not anthropic_key:
        if has_gen_ai:
            logger.info(
                "ANTHROPIC_API_KEY is empty. Falling back to Gen AI gateway "
                "(GEN_AI_API_HOST is set)."
            )
            from .gen_ai_client import GenAIClient
            return GenAIClient(config)
        elif openai_key:
            logger.info("ANTHROPIC_API_KEY is empty. Falling back to OpenAI.")
            config["provider"] = "openai"
            return LLMClient(config)
        else:
            raise RuntimeError(
                "No LLM provider available.\n"
                "Set one of:\n"
                "  - ANTHROPIC_API_KEY (for Anthropic)\n"
                "  - OPENAI_API_KEY (for OpenAI)\n"
                "  - GEN_AI_API_HOST + GEN_AI_API_PRIVATE_KEY (for internal Gen AI)\n"
                "Or use --mock-llm for testing."
            )

    return LLMClient(config)


class LLMClient:
    """Unified interface for LLM providers."""

    def __init__(self, config: dict):
        self.provider = config.get("provider", "openai")
        self.model = config.get("model", "gpt-4o")
        self.temperature = config.get("temperature", 0.2)
        self.max_tokens = config.get("max_tokens", 4096)
        self._client = None

    @property
    def client(self):
        """Lazy-initialize the LLM client."""
        if self._client is None:
            if self.provider == "openai":
                from openai import OpenAI

                api_key = os.environ.get("OPENAI_API_KEY")
                if not api_key:
                    raise RuntimeError(
                        "OPENAI_API_KEY not set. Use --mock-llm for testing without API keys."
                    )
                self._client = OpenAI(api_key=api_key)
            elif self.provider == "anthropic":
                import anthropic

                api_key = os.environ.get("ANTHROPIC_API_KEY")
                if not api_key:
                    raise RuntimeError(
                        "ANTHROPIC_API_KEY not set. Use --mock-llm for testing without API keys."
                    )
                self._client = anthropic.Anthropic(api_key=api_key)
            else:
                raise ValueError(f"Unsupported LLM provider: {self.provider}")
        return self._client

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        json_mode: bool = False,
    ) -> str:
        """Send a chat message and return the response text."""
        logger.debug(f"LLM request ({self.provider}/{self.model}): {user_message[:100]}...")

        if self.provider == "openai":
            return self._chat_openai(system_prompt, user_message, json_mode)
        elif self.provider == "anthropic":
            return self._chat_anthropic(system_prompt, user_message, json_mode)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _chat_openai(self, system_prompt: str, user_message: str, json_mode: bool) -> str:
        """Chat using OpenAI API."""
        kwargs = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}

        response = self.client.chat.completions.create(**kwargs)
        return response.choices[0].message.content

    def _chat_anthropic(self, system_prompt: str, user_message: str, json_mode: bool) -> str:
        """Chat using Anthropic API."""
        message = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
            temperature=self.temperature,
        )
        return message.content[0].text
