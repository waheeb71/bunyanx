#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enterprise bunyanx - Configuration Management Helpers

NOTE: This module is DEPRECATED for new code.
======================================================
All configuration loading should now use:
    from system.core.config_loader import ConfigLoader

ConfigLoader is the unified, thread-safe, single-source-of-truth config API.
It reads from system/config/settings.yaml and modules/*/config/*.yaml.

Functions kept for backward compatibility (still used by legacy loading paths):
  - load_config()    — raw YAML loader used by engine.py startup
  - apply_defaults() — fallback defaults when key is missing in base.yaml
  - deep_merge()     — dict merge utility
  - validate_config() — basic schema check on startup

DO NOT add new hardcoded defaults here. Add them to system/config/settings.yaml.
"""

import sys
from pathlib import Path
import yaml
import logging
from typing import Dict, Any
logger = logging.getLogger(__name__)


def load_config(config_path: Path) -> Dict[str, Any]:
    """
    Load configuration from YAML file.

    DEPRECATED: Use ConfigLoader.instance() for runtime config access.
    This function is kept for the initial startup bootstrap in engine.py
    where ConfigLoader itself has not been initialised yet.

    Args:
        config_path: Path to config file

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config is invalid YAML
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)

        if config is None:
            config = {}

        # Apply minimal safety defaults (not business logic — those live in settings.yaml)
        config = apply_defaults(config)

        logger.info("Configuration loaded from %s", config_path)
        return config

    except yaml.YAMLError as e:
        logger.error("Invalid YAML in config file: %s", e)
        raise


def apply_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply minimal fallback defaults to configuration.

    IMPORTANT: Only structural/safety defaults belong here.
    Business-logic defaults (thresholds, network ranges, fail_open, etc.)
    must be in system/config/settings.yaml — not hardcoded here.
    """
    # Minimal structural defaults — prevents KeyError on missing top-level sections.
    # Values here are intentionally conservative (disabled / empty).
    defaults = {
        'event_sink': {
            'buffer_size': 1000,
            'flush_interval': 1.0,
            'batch_size': 100,
            'backends': [
                {
                    'type': 'file',
                    'output_dir': 'data/logs/events',
                    'format': 'json',
                    'rotation': 'daily',
                }
            ],
        },
        # NOTE: ebpf, proxy, ml, logging defaults are intentionally removed.
        # They are defined in system/config/settings.yaml → ConfigLoader.
        'logging': {
            'level': 'INFO',
            'format': 'json',
        },
    }

    return deep_merge(defaults, config)


def deep_merge(default: Dict, override: Dict) -> Dict:
    """
    Deep merge two dictionaries (override wins on conflicts).

    Args:
        default: Default values
        override: Override values (takes priority)

    Returns:
        Merged dictionary
    """
    result = default.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value

    return result


def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate top-level configuration structure.

    Args:
        config: Configuration dictionary

    Returns:
        True if valid

    Raises:
        ValueError: If configuration is invalid
    """
    # Basic structural validation only.
    # Deep value validation is handled by ConfigLoader (Pydantic/schema).
    required_sections = ['proxy']

    for section in required_sections:
        if section not in config:
            raise ValueError(f"Missing required configuration section: {section}")

    if 'event_sink' in config:
        backends = config['event_sink'].get('backends', [])
        for backend in backends:
            if 'type' not in backend:
                raise ValueError("Event sink backend missing 'type' field")

    logger.info("Configuration validation passed")
    return True
