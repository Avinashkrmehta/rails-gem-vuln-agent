"""Load and validate configuration."""

import os
import yaml
from pathlib import Path


def load_config(config_path: str = "config.yaml") -> dict:
    """Load configuration from YAML file with environment variable overrides."""

    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        config = yaml.safe_load(f)

    # Environment variable overrides
    env_overrides = {
        "llm.provider": "LLM_PROVIDER",
        "llm.model": "OPENAI_MODEL" if config["llm"]["provider"] == "openai" else "ANTHROPIC_MODEL",
    }

    for config_key, env_var in env_overrides.items():
        value = os.environ.get(env_var)
        if value:
            keys = config_key.split(".")
            obj = config
            for k in keys[:-1]:
                obj = obj[k]
            obj[keys[-1]] = value

    # Inject log level from env
    config["log_level"] = os.environ.get("LOG_LEVEL", "INFO")

    return config
