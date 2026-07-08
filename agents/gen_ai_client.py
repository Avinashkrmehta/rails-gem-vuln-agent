"""Gen AI Client - Integration with the internal Gen AI API gateway.

This uses the same JWT-authenticated API that lx-edcast uses for text generation,
backed by AWS Bedrock (Amazon Nova Lite/Pro models).

Required environment variables:
  GEN_AI_API_PRIVATE_KEY  - RSA private key for JWT signing
  GEN_AI_API_PUBLIC_KEY_URL - JWKS URL for public key verification
  GEN_AI_API_PUBLIC_KEY_ID - Key ID (kid) for JWT header
  GEN_AI_API_HOST - API gateway endpoint (e.g., https://gen-ai.yourcompany.com)
  GEN_AI_AUD_URL - Audience URL for JWT claims

Optional:
  GEN_AI_BEDROCK_API_HOST - Bedrock-specific endpoint (if separate)
  GEN_AI_BEDROCK_AUD_URL - Bedrock audience URL
  GEN_AI_MAX_TOKENS - Max tokens (default: 2000)
  GEN_AI_API_TIME_OUT - Request timeout in seconds (default: 20)
"""

import json
import logging
import os
import time
from typing import Optional

import jwt
import requests
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger("vuln-agent.gen-ai")


class GenAIClient:
    """Client for the internal Gen AI API gateway (Bedrock-backed)."""

    DEFAULT_MODEL = "amazon-nova-lite"
    BEDROCK_MODEL = "anthropic.claude-3-5-sonnet-20241022-v2:0"

    def __init__(self, config: dict):
        self.provider = "gen_ai"
        # If model looks like an OpenAI/Anthropic model (fallback scenario), use our default
        configured_model = config.get("model", self.DEFAULT_MODEL)
        if configured_model.startswith(("gpt-", "claude-", "o1", "o3")):
            self.model = self.DEFAULT_MODEL
        else:
            self.model = configured_model
        self.temperature = config.get("temperature", 0.2)
        self.max_tokens = int(os.environ.get("GEN_AI_MAX_TOKENS", config.get("max_tokens", 2000)))
        self.timeout = int(os.environ.get("GEN_AI_API_TIME_OUT", 30))

        # JWT auth config
        self.private_key_str = os.environ.get("GEN_AI_API_PRIVATE_KEY")
        self.public_key_url = os.environ.get("GEN_AI_API_PUBLIC_KEY_URL")
        self.public_key_id = os.environ.get("GEN_AI_API_PUBLIC_KEY_ID")
        self.audience_url = os.environ.get("GEN_AI_AUD_URL")

        # API endpoints
        self.api_endpoint = os.environ.get("GEN_AI_API_HOST")
        self.bedrock_endpoint = os.environ.get("GEN_AI_BEDROCK_API_HOST")
        self.bedrock_aud_url = os.environ.get("GEN_AI_BEDROCK_AUD_URL")

        # Use bedrock endpoint if available and model is a bedrock model
        self.use_bedrock = bool(self.bedrock_endpoint)

        self._validate_config()

    def _validate_config(self):
        """Validate required environment variables are set."""
        missing = []
        if not self.private_key_str:
            missing.append("GEN_AI_API_PRIVATE_KEY")
        if not self.api_endpoint and not self.bedrock_endpoint:
            missing.append("GEN_AI_API_HOST (or GEN_AI_BEDROCK_API_HOST)")
        if not self.public_key_url:
            missing.append("GEN_AI_API_PUBLIC_KEY_URL")
        if not self.public_key_id:
            missing.append("GEN_AI_API_PUBLIC_KEY_ID")
        if not self.audience_url:
            missing.append("GEN_AI_AUD_URL")

        if missing:
            raise RuntimeError(
                f"Gen AI client missing required env vars: {', '.join(missing)}\n"
                "These are the same vars used by lx-edcast's gen_ai config in settings.yml.\n"
                "Alternatively, use --mock-llm for testing or set OPENAI_API_KEY for OpenAI."
            )

        logger.info(f"Using Gen AI gateway: {self._active_endpoint()}")
        logger.info(f"Model: {self.model}")

    def _active_endpoint(self) -> str:
        """Return the active API endpoint."""
        if self.use_bedrock and self.bedrock_endpoint:
            return self.bedrock_endpoint
        return self.api_endpoint

    def _active_aud_url(self) -> str:
        """Return the audience URL for the active endpoint."""
        if self.use_bedrock and self.bedrock_aud_url:
            return self.bedrock_aud_url
        return self.audience_url

    def _generate_jwt_token(self) -> str:
        """Generate RS256 JWT token for API authentication."""
        now = int(time.time())
        max_expiry = 14400  # 4 hours

        headers = {
            "jku": self.public_key_url,
            "kid": self.public_key_id,
            "typ": "JWT",
            "alg": "RS256",
        }

        payload = {
            "iss": "EDX",
            "aud": self._active_aud_url(),
            "iat": now,
            "exp": now + max_expiry,
            "nbf": now,
            "x-tenant-id": "vuln-agent",
            "sub": "Edcast-LXP",
            "x-app": "EDX",
        }

        # Parse private key
        private_key_pem = self.private_key_str.replace("\\n", "\n")
        if not private_key_pem.startswith("-----"):
            private_key_pem = f"-----BEGIN RSA PRIVATE KEY-----\n{private_key_pem}\n-----END RSA PRIVATE KEY-----"

        private_key = load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend(),
        )

        token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
        return token

    def chat(
        self,
        system_prompt: str,
        user_message: str,
        json_mode: bool = False,
    ) -> str:
        """Send a chat request to the Gen AI gateway.

        Maps the system_prompt + user_message to the gateway's expected format.
        """
        logger.debug(f"Gen AI request ({self.model}): {user_message[:80]}...")

        # Generate JWT token
        jwt_token = self._generate_jwt_token()

        # Build request body matching the csod_client format
        # The gateway expects: prompt, context, examples, max_tokens, etc.
        prompt = user_message
        if json_mode:
            prompt += "\n\nRespond with valid JSON only."

        request_body = {
            "prompt": prompt,
            "system_message": system_prompt,
            "context": {},
            "examples": [],
            "max_tokens": self.max_tokens,
            "chat_history": [],
            "temperature": self.temperature,
            "model": self.model,
        }

        # Make the API request
        endpoint = self._active_endpoint()
        url = f"{endpoint.rstrip('/')}/v3/generate"

        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Content-Type": "application/json",
            "x-ai-usecase": "lxp-security-vuln-agent",
        }

        try:
            response = requests.post(
                url,
                headers=headers,
                json=request_body,
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                # Extract the generated text from the response
                # The API typically returns: {"output": "...", "model": "..."}
                # or nested: {"data": {"output": "..."}}
                return self._extract_response_text(data)
            else:
                logger.error(f"Gen AI API returned {response.status_code}: {response.text[:200]}")
                raise RuntimeError(f"Gen AI API error ({response.status_code}): {response.text[:200]}")

        except requests.Timeout:
            raise RuntimeError(f"Gen AI API timed out after {self.timeout}s")
        except requests.ConnectionError as e:
            raise RuntimeError(f"Gen AI API connection failed: {e}")

    def _extract_response_text(self, data: dict) -> str:
        """Extract generated text from the API response.

        Handles multiple possible response formats:
        - {"processed_response": "text"}  (actual Gen AI gateway format)
        - {"output": "text"}
        - {"data": {"output": "text"}}
        - {"data": {"choices": [{"message": {"content": "text"}}]}}
        - {"text": "text"}
        - {"response": "text"}
        """
        # Try common response formats
        if isinstance(data, str):
            return data

        # Gen AI gateway format: processed_response
        if "processed_response" in data:
            return data["processed_response"]

        # Direct output field
        if "output" in data:
            return data["output"]

        # Nested under data
        if "data" in data:
            inner = data["data"]
            if isinstance(inner, str):
                return inner
            if "processed_response" in inner:
                return inner["processed_response"]
            if "output" in inner:
                return inner["output"]
            if "text" in inner:
                return inner["text"]
            # OpenAI-compatible format
            if "choices" in inner:
                return inner["choices"][0]["message"]["content"]

        # Other common patterns
        if "text" in data:
            return data["text"]
        if "response" in data:
            return data["response"]
        if "message" in data:
            return data["message"]

        # Last resort: return the full JSON as string
        logger.warning(f"Unknown Gen AI response format, returning raw: {str(data)[:100]}")
        return json.dumps(data)
