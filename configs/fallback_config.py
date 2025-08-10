#!/usr/bin/env python3

"""
Fallback configuration values to ensure basic tool functionality.
Used when primary configuration cannot be loaded.
"""

# Fallback values that allow basic tool operation
FALLBACK_CONFIG = {
    'target_model_api_url': 'http://localhost:11434/api/chat',
    'target_model_name': 'llama2:7b',
    'attack_model_api_url': 'http://localhost:8181/v1',
    'attack_model_api_key': 'dummy',
    'attack_model_name': 'vicuna-7b',
    'attack_model_temperature': 0.7,
    'analyzer_model_api_url': 'http://localhost:8181/v1',
    'analyzer_model_api_key': 'dummy', 
    'analyzer_model_name': 'vicuna-7b'
}


def get_fallback_value(key: str) -> str:
    """
    Get fallback configuration value.
    
    Args:
        key: Configuration key to retrieve
        
    Returns:
        Fallback value for the key
        
    Raises:
        KeyError: If no fallback exists for the key
    """
    return FALLBACK_CONFIG[key]


def has_fallback(key: str) -> bool:
    """Check if a fallback value exists for the given key."""
    return key in FALLBACK_CONFIG