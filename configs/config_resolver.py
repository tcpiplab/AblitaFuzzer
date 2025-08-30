#!/usr/bin/env python3

"""
Lazy loading configuration resolution functions for AblitaFuzzer.

Provides graceful error handling and fallback configuration values
to ensure the tool remains functional even with configuration issues.
"""

from typing import Optional, Dict, Any
import os
import sys
from functools import lru_cache

from .exceptions import ConfigurationError, EnvironmentVariableError
from .fallback_config import get_fallback_value, has_fallback

# Import existing configuration functions
try:
    from .config_loader import load_configuration, get_target_configuration, get_attack_model_configuration
    from .env_resolver import resolve_environment_variables
except ImportError as e:
    print(f"Warning: Could not import configuration modules: {e}", file=sys.stderr)
    print("Some configuration functionality may be limited", file=sys.stderr)


@lru_cache(maxsize=1)
def get_current_config() -> Optional[Dict[str, Any]]:
    """
    Load configuration with caching and error handling.
    
    Returns:
        Configuration dictionary or None if loading fails
        
    Raises:
        ConfigurationError: If configuration is invalid
    """
    try:
        return load_configuration()
    except Exception as e:
        # Log error but don't crash the entire tool
        print(f"Warning: Configuration loading failed: {e}", file=sys.stderr)
        return None


def _get_fallback_target_url() -> str:
    """Get fallback target URL."""
    if has_fallback('target_model_api_url'):
        return get_fallback_value('target_model_api_url')
    return 'http://localhost:11434/api/chat'


def _get_fallback_attack_url() -> str:
    """Get fallback attack URL."""
    if has_fallback('attack_model_api_url'):
        return get_fallback_value('attack_model_api_url')
    return 'http://localhost:8181/v1'


def get_target_model_api_url() -> str:
    """
    Get target model API URL with fallback handling.
    
    Returns:
        API URL string
        
    Raises:
        ConfigurationError: If configuration cannot be resolved
    """
    config = get_current_config()
    if not config:
        return _get_fallback_target_url()
    
    try:
        target_config = get_target_configuration(config, 'legacy_target')
        return target_config['base_url']
    except Exception as e:
        print(f"Warning: Failed to resolve target API URL: {e}", file=sys.stderr)
        print("Run 'ablitafuzzer config validate' to check configuration", file=sys.stderr)
        return _get_fallback_target_url()


def get_target_model_name() -> str:
    """
    Get target model name with fallback handling.
    
    Returns:
        Model name string
    """
    config = get_current_config()
    if not config:
        return get_fallback_value('target_model_name')
    
    try:
        target_config = get_target_configuration(config, 'legacy_target')
        return target_config['model']
    except Exception:
        return get_fallback_value('target_model_name')


def get_attack_model_api_url() -> str:
    """
    Get attack model API URL with fallback handling.
    
    Returns:
        API URL string
    """
    config = get_current_config()
    if not config:
        return _get_fallback_attack_url()
    
    try:
        attack_config = get_attack_model_configuration(config, 'attacker_model')
        return attack_config['base_url']
    except Exception:
        return _get_fallback_attack_url()


def get_attack_model_api_key() -> Optional[str]:
    """
    Get attack model API key with graceful handling.
    
    Returns:
        API key string or None if not configured
        
    Note:
        Returns None for local models that don't require authentication
    """
    config = get_current_config()
    if not config:
        return get_fallback_value('attack_model_api_key')
    
    try:
        attack_config = get_attack_model_configuration(config, 'attacker_model')
        auth_format = attack_config['auth']['format']
        
        # Handle environment variable resolution
        if '${' in auth_format:
            resolved = resolve_environment_variables(auth_format)
            if 'Bearer ' in resolved:
                return resolved.replace('Bearer ', '')
            return resolved
        
        return auth_format if auth_format != 'dummy' else None
        
    except EnvironmentVariableError as e:
        # Provide helpful guidance for missing environment variables
        print(f"Warning: {e}", file=sys.stderr)
        print("Run 'ablitafuzzer config validate' for setup guidance", file=sys.stderr)
        return get_fallback_value('attack_model_api_key')
    except Exception:
        return get_fallback_value('attack_model_api_key')


def get_attack_model_name() -> str:
    """
    Get attack model name with fallback handling.
    
    Returns:
        Model name string
    """
    config = get_current_config()
    if not config:
        return get_fallback_value('attack_model_name')
    
    try:
        attack_config = get_attack_model_configuration(config, 'attacker_model')
        return attack_config['model']
    except Exception:
        return get_fallback_value('attack_model_name')


def get_attack_model_temperature() -> float:
    """
    Get attack model temperature with fallback handling.
    
    Returns:
        Temperature value as float
    """
    config = get_current_config()
    if not config:
        return get_fallback_value('attack_model_temperature')
    
    try:
        attack_config = get_attack_model_configuration(config, 'attacker_model')
        return attack_config.get('temperature', 0.7)
    except Exception:
        return get_fallback_value('attack_model_temperature')


def get_analyzer_model_api_url() -> str:
    """
    Get analyzer model API URL with fallback handling.
    
    Returns:
        API URL string
    """
    config = get_current_config()
    if not config:
        return get_fallback_value('analyzer_model_api_url')
    
    try:
        analyzer_config = get_attack_model_configuration(config, 'analyzer_model')
        return analyzer_config['base_url']
    except Exception:
        return get_fallback_value('analyzer_model_api_url')


def get_analyzer_model_api_key() -> Optional[str]:
    """
    Get analyzer model API key with graceful handling.
    
    Returns:
        API key string or None if not configured
    """
    config = get_current_config()
    if not config:
        return get_fallback_value('analyzer_model_api_key')
    
    try:
        analyzer_config = get_attack_model_configuration(config, 'analyzer_model')
        auth_format = analyzer_config['auth']['format']
        
        # Handle environment variable resolution
        if '${' in auth_format:
            resolved = resolve_environment_variables(auth_format)
            if 'Bearer ' in resolved:
                return resolved.replace('Bearer ', '')
            return resolved
        
        return auth_format if auth_format != 'dummy' else None
        
    except EnvironmentVariableError as e:
        print(f"Warning: {e}", file=sys.stderr)
        print("Run 'ablitafuzzer config validate' for setup guidance", file=sys.stderr)
        return get_fallback_value('analyzer_model_api_key')
    except Exception:
        return get_fallback_value('analyzer_model_api_key')


def get_analyzer_model_name() -> str:
    """
    Get analyzer model name with fallback handling.
    
    Returns:
        Model name string
    """
    config = get_current_config()
    if not config:
        return get_fallback_value('analyzer_model_name')
    
    try:
        analyzer_config = get_attack_model_configuration(config, 'analyzer_model')
        return analyzer_config['model']
    except Exception:
        return get_fallback_value('analyzer_model_name')