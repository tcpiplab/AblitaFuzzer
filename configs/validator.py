#!/usr/bin/env python3

import os
import yaml
import jsonschema
from pathlib import Path
from .auth_manager import validate_auth_config_schema
from .api_providers import validate_provider_config


CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "version": {"type": "string"},
        "global": {
            "type": "object",
            "properties": {
                "proxy": {
                    "type": "object",
                    "properties": {
                        "http": {"type": "string"},
                        "https": {"type": "string"}
                    }
                },
                "timeout": {
                    "type": "object",
                    "properties": {
                        "connection": {"type": "number"},
                        "read": {"type": "number"},
                        "total": {"type": "number"}
                    }
                },
                "retry": {
                    "type": "object",
                    "properties": {
                        "attempts": {"type": "number"},
                        "backoff": {"type": "string", "enum": ["linear", "exponential"]},
                        "max_delay": {"type": "number"}
                    }
                }
            }
        },
        "environments": {
            "type": "object",
            "patternProperties": {
                "^[a-zA-Z0-9_]+$": {
                    "type": "object",
                    "properties": {
                        "log_level": {"type": "string", "enum": ["DEBUG", "INFO", "WARNING", "ERROR"]},
                        "rate_limit": {"type": "number"},
                        "require_confirmation": {"type": "boolean"}
                    }
                }
            }
        },
        "providers": {
            "type": "object",
            "patternProperties": {
                "^[a-zA-Z0-9_]+$": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string"},
                        "base_url": {"type": "string"},
                        "auth": {"type": "object"},
                        "models": {"type": "array", "items": {"type": "string"}},
                        "api_version": {"type": "string"},
                        "deployment": {"type": "string"}
                    },
                    "required": ["type", "base_url", "auth"]
                }
            }
        },
        "targets": {
            "type": "object",
            "patternProperties": {
                "^[a-zA-Z0-9_]+$": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string"},
                        "model": {"type": "string"},
                        "description": {"type": "string"},
                        "base_url": {"type": "string"},
                        "auth": {"type": "object"}
                    },
                    "required": ["provider", "model"]
                }
            }
        },
        "attack": {
            "type": "object",
            "properties": {
                "attacker_model": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string"},
                        "model": {"type": "string"},
                        "temperature": {"type": "number"}
                    },
                    "required": ["provider", "model"]
                },
                "analyzer_model": {
                    "type": "object",
                    "properties": {
                        "provider": {"type": "string"},
                        "model": {"type": "string"},
                        "temperature": {"type": "number"}
                    },
                    "required": ["provider", "model"]
                }
            }
        },
        "campaigns": {
            "type": "object",
            "patternProperties": {
                "^[a-zA-Z0-9_]+$": {
                    "type": "object",
                    "properties": {
                        "targets": {"type": "array", "items": {"type": "string"}},
                        "datasets": {"type": "array", "items": {"type": "string"}},
                        "concurrent_targets": {"type": "number"},
                        "prompt_limit": {"type": "number"}
                    },
                    "required": ["targets", "datasets"]
                }
            }
        }
    },
    "required": ["version", "providers", "targets"]
}


def validate_configuration_schema(config):
    """
    Validate configuration against JSON schema.
    
    Args:
        config (dict): Configuration dictionary to validate
        
    Returns:
        dict: Validated configuration
        
    Raises:
        ValueError: If configuration is invalid
    """
    try:
        jsonschema.validate(config, CONFIG_SCHEMA)
        return config
    except jsonschema.ValidationError as e:
        raise ValueError(f"Configuration validation failed: {e.message}")


def validate_configuration_logic(config):
    """
    Validate configuration business logic and cross-references.
    
    Args:
        config (dict): Configuration dictionary to validate
        
    Returns:
        list: List of validation errors, empty if valid
    """
    errors = []
    
    # Validate provider configurations
    for provider_name, provider_config in config.get('providers', {}).items():
        provider_errors = validate_provider_config(provider_config)
        for error in provider_errors:
            errors.append(f"Provider '{provider_name}': {error}")
        
        # Validate authentication configuration
        if 'auth' in provider_config:
            auth_errors = validate_auth_config_schema(provider_config['auth'])
            for error in auth_errors:
                errors.append(f"Provider '{provider_name}' auth: {error}")
    
    # Validate target references to providers
    for target_name, target_config in config.get('targets', {}).items():
        provider_name = target_config.get('provider')
        if provider_name and provider_name not in config.get('providers', {}):
            errors.append(f"Target '{target_name}' references unknown provider '{provider_name}'")
        
        # Validate model is in provider's model list (if specified)
        if provider_name and provider_name in config.get('providers', {}):
            provider_models = config['providers'][provider_name].get('models', [])
            target_model = target_config.get('model')
            if provider_models and target_model and target_model not in provider_models:
                errors.append(f"Target '{target_name}' model '{target_model}' not in provider '{provider_name}' model list")
    
    # Validate attack model references
    attack_config = config.get('attack', {})
    for model_type in ['attacker_model', 'analyzer_model']:
        if model_type in attack_config:
            model_config = attack_config[model_type]
            provider_name = model_config.get('provider')
            if provider_name and provider_name not in config.get('providers', {}):
                errors.append(f"Attack {model_type} references unknown provider '{provider_name}'")
    
    # Validate campaign references
    for campaign_name, campaign_config in config.get('campaigns', {}).items():
        # Check target references
        for target_name in campaign_config.get('targets', []):
            if target_name not in config.get('targets', {}):
                errors.append(f"Campaign '{campaign_name}' references unknown target '{target_name}'")
    
    return errors


def validate_configuration_file(config_path):
    """
    Validate configuration file exists and is readable.
    
    Args:
        config_path (str): Path to configuration file
        
    Returns:
        list: List of validation errors, empty if valid
    """
    errors = []
    
    config_file = Path(config_path)
    
    if not config_file.exists():
        errors.append(f"Configuration file does not exist: {config_path}")
        return errors
    
    if not config_file.is_file():
        errors.append(f"Configuration path is not a file: {config_path}")
        return errors
    
    if not os.access(config_path, os.R_OK):
        errors.append(f"Configuration file is not readable: {config_path}")
        return errors
    
    # Try to parse YAML
    try:
        with open(config_path, 'r') as f:
            yaml.safe_load(f)
    except yaml.YAMLError as e:
        errors.append(f"Configuration file is not valid YAML: {e}")
    except Exception as e:
        errors.append(f"Error reading configuration file: {e}")
    
    return errors


def validate_environment_setup(config):
    """
    Validate that required environment variables are properly set.
    
    Args:
        config (dict): Configuration dictionary to validate
        
    Returns:
        dict: Validation results with missing variables and warnings
    """
    from .env_resolver import validate_required_environment_variables, check_environment_variable_safety
    
    missing_vars = validate_required_environment_variables(config)
    
    # Check safety of existing environment variables
    warnings = []
    for var_name in os.environ:
        if var_name.startswith(('OPENAI_', 'ANTHROPIC_', 'AZURE_', 'API_')):
            safety_check = check_environment_variable_safety(var_name, os.environ[var_name])
            warnings.extend(safety_check['warnings'])
    
    return {
        'missing_variables': missing_vars,
        'warnings': warnings,
        'valid': len(missing_vars) == 0
    }


def get_configuration_recommendations(config):
    """
    Generate recommendations for improving configuration.
    
    Args:
        config (dict): Configuration dictionary to analyze
        
    Returns:
        list: List of recommendation strings
    """
    recommendations = []
    
    # Check for security best practices
    if not config.get('global', {}).get('timeout'):
        recommendations.append("Consider setting global timeout values for better reliability")
    
    if not config.get('global', {}).get('retry'):
        recommendations.append("Consider configuring retry logic for improved resilience")
    
    # Check environment configuration
    environments = config.get('environments', {})
    if 'production' not in environments:
        recommendations.append("Consider adding a production environment configuration")
    
    if 'development' not in environments:
        recommendations.append("Consider adding a development environment configuration")
    
    # Check for proxy configuration in enterprise scenarios
    providers = config.get('providers', {})
    has_cloud_providers = any(
        'api.openai.com' in provider.get('base_url', '') or
        'api.anthropic.com' in provider.get('base_url', '')
        for provider in providers.values()
    )
    
    if has_cloud_providers and not config.get('global', {}).get('proxy'):
        recommendations.append("Consider configuring proxy settings for enterprise network access")
    
    # Check for multiple providers
    if len(providers) == 1:
        recommendations.append("Consider adding multiple API providers for redundancy")
    
    return recommendations


def validate_network_connectivity(config, target_name=None):
    """
    Validate network connectivity to configured endpoints.
    
    Args:
        config (dict): Configuration dictionary
        target_name (str): Specific target to test, or None for all
        
    Returns:
        dict: Connectivity test results
    """
    import requests
    from .auth_manager import generate_auth_headers
    
    results = {}
    
    targets_to_test = {}
    if target_name:
        if target_name in config.get('targets', {}):
            targets_to_test[target_name] = config['targets'][target_name]
    else:
        targets_to_test = config.get('targets', {})
    
    for name, target_config in targets_to_test.items():
        try:
            provider_name = target_config['provider']
            provider_config = config['providers'][provider_name]
            
            # Generate auth headers
            auth_headers = generate_auth_headers(provider_config['auth'])
            
            # Test connectivity with HEAD request
            base_url = provider_config['base_url']
            test_url = base_url.split('/chat')[0] if '/chat' in base_url else base_url
            
            response = requests.head(test_url, headers=auth_headers, timeout=10)
            
            results[name] = {
                'status': 'success' if response.status_code < 500 else 'warning',
                'status_code': response.status_code,
                'response_time': response.elapsed.total_seconds(),
                'error': None
            }
            
        except Exception as e:
            results[name] = {
                'status': 'failed',
                'status_code': None,
                'response_time': None,
                'error': str(e)
            }
    
    return results