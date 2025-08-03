#!/usr/bin/env python3

import os
import yaml
from pathlib import Path
from .env_resolver import resolve_environment_variables_recursive
from .validator import validate_configuration_schema, validate_configuration_logic


def get_default_config_path():
    """
    Get the default configuration file path.
    
    Returns:
        str: Default configuration file path
    """
    # Try multiple locations in order of preference
    config_locations = [
        os.path.expanduser("~/.ablitafuzzer/config.yaml"),
        os.path.expanduser("~/.config/ablitafuzzer/config.yaml"),
        "./config.yaml",
        "./configs/config.yaml"
    ]
    
    for path in config_locations:
        if os.path.exists(path):
            return path
    
    # Return the preferred location even if it doesn't exist
    return config_locations[0]


def load_yaml_file(config_path):
    """
    Load YAML configuration file.
    
    Args:
        config_path (str): Path to YAML configuration file
        
    Returns:
        dict: Parsed YAML configuration
        
    Raises:
        FileNotFoundError: If configuration file doesn't exist
        yaml.YAMLError: If YAML parsing fails
    """
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_file, 'r') as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise yaml.YAMLError(f"Failed to parse YAML configuration: {e}")


def merge_environment_overrides(config, environment):
    """
    Merge environment-specific configuration overrides.
    
    Args:
        config (dict): Base configuration
        environment (str): Environment name (development, staging, production)
        
    Returns:
        dict: Configuration with environment overrides applied
    """
    if 'environments' not in config or environment not in config['environments']:
        return config
    
    env_config = config['environments'][environment]
    merged_config = config.copy()
    
    # Apply environment-specific settings to global config
    if 'global' not in merged_config:
        merged_config['global'] = {}
    
    # Apply log level
    if 'log_level' in env_config:
        merged_config['global']['log_level'] = env_config['log_level']
    
    # Apply rate limiting
    if 'rate_limit' in env_config:
        merged_config['global']['rate_limit'] = env_config['rate_limit']
    
    # Apply confirmation requirements
    if 'require_confirmation' in env_config:
        merged_config['global']['require_confirmation'] = env_config['require_confirmation']
    
    return merged_config


def merge_target_and_provider_config(target_config, provider_config):
    """
    Merge target configuration with provider configuration.
    
    Args:
        target_config (dict): Target-specific configuration
        provider_config (dict): Provider configuration
        
    Returns:
        dict: Merged configuration
    """
    merged = provider_config.copy()
    
    # Target-specific overrides take precedence
    for key in ['base_url', 'auth', 'model']:
        if key in target_config:
            merged[key] = target_config[key]
    
    # Add target-specific metadata
    merged['target_name'] = target_config.get('name', 'unknown')
    merged['description'] = target_config.get('description', '')
    
    return merged


def load_configuration(config_path=None, environment=None, profile=None):
    """
    Load and validate configuration from YAML file with environment resolution.
    
    Args:
        config_path (str): Path to configuration file
        environment (str): Environment name (development, staging, production)
        profile (str): Configuration profile name (currently unused, reserved for future)
        
    Returns:
        dict: Loaded and validated configuration
        
    Raises:
        FileNotFoundError: If configuration file doesn't exist
        ValueError: If configuration is invalid
    """
    config_path = config_path or get_default_config_path()
    environment = environment or os.getenv('ABLITAFUZZER_ENV', 'development')
    
    # Load raw configuration
    raw_config = load_yaml_file(config_path)
    
    # Resolve environment variables
    resolved_config = resolve_environment_variables_recursive(raw_config)
    
    # Validate schema
    validated_config = validate_configuration_schema(resolved_config)
    
    # Validate business logic
    logic_errors = validate_configuration_logic(validated_config)
    if logic_errors:
        raise ValueError("Configuration validation errors:\n" + "\n".join(logic_errors))
    
    # Apply environment overrides
    final_config = merge_environment_overrides(validated_config, environment)
    
    # Add metadata
    final_config['_metadata'] = {
        'config_path': str(config_path),
        'environment': environment,
        'profile': profile,
        'loaded_at': None  # Could add timestamp if needed
    }
    
    return final_config


def get_target_configuration(config, target_name):
    """
    Get complete configuration for a specific target including provider details.
    
    Args:
        config (dict): Loaded configuration
        target_name (str): Name of target to retrieve
        
    Returns:
        dict: Complete target configuration with provider details merged
        
    Raises:
        ValueError: If target or provider not found
    """
    target_config = config['targets'].get(target_name)
    if not target_config:
        available_targets = list(config['targets'].keys())
        raise ValueError(f"Target '{target_name}' not found. Available targets: {available_targets}")
    
    provider_name = target_config['provider']
    provider_config = config['providers'].get(provider_name)
    if not provider_config:
        available_providers = list(config['providers'].keys())
        raise ValueError(f"Provider '{provider_name}' not found. Available providers: {available_providers}")
    
    return merge_target_and_provider_config(target_config, provider_config)


def get_attack_model_configuration(config, model_type='attacker_model'):
    """
    Get configuration for attack or analyzer models.
    
    Args:
        config (dict): Loaded configuration
        model_type (str): Type of model ('attacker_model' or 'analyzer_model')
        
    Returns:
        dict: Model configuration with provider details
        
    Raises:
        ValueError: If model configuration not found
    """
    attack_config = config.get('attack', {})
    model_config = attack_config.get(model_type)
    
    if not model_config:
        raise ValueError(f"Attack {model_type} configuration not found")
    
    provider_name = model_config['provider']
    provider_config = config['providers'].get(provider_name)
    if not provider_config:
        raise ValueError(f"Provider '{provider_name}' for {model_type} not found")
    
    # Merge model config with provider config
    merged = provider_config.copy()
    merged.update(model_config)
    
    return merged


def list_available_targets(config):
    """
    List all configured targets with their basic information.
    
    Args:
        config (dict): Loaded configuration
        
    Returns:
        list: Target information dictionaries
    """
    targets = []
    for target_name, target_config in config['targets'].items():
        targets.append({
            'name': target_name,
            'description': target_config.get('description', ''),
            'provider': target_config['provider'],
            'model': target_config['model']
        })
    return targets


def list_available_providers(config):
    """
    List all configured providers with their basic information.
    
    Args:
        config (dict): Loaded configuration
        
    Returns:
        list: Provider information dictionaries
    """
    providers = []
    for provider_name, provider_config in config['providers'].items():
        providers.append({
            'name': provider_name,
            'type': provider_config['type'],
            'base_url': provider_config['base_url'],
            'models': provider_config.get('models', [])
        })
    return providers


def get_campaign_configuration(config, campaign_name):
    """
    Get configuration for a specific campaign.
    
    Args:
        config (dict): Loaded configuration
        campaign_name (str): Name of campaign to retrieve
        
    Returns:
        dict: Campaign configuration
        
    Raises:
        ValueError: If campaign not found
    """
    campaign_config = config.get('campaigns', {}).get(campaign_name)
    if not campaign_config:
        available_campaigns = list(config.get('campaigns', {}).keys())
        raise ValueError(f"Campaign '{campaign_name}' not found. Available campaigns: {available_campaigns}")
    
    # Validate that all referenced targets exist
    for target_name in campaign_config['targets']:
        if target_name not in config['targets']:
            raise ValueError(f"Campaign '{campaign_name}' references unknown target '{target_name}'")
    
    return campaign_config


def save_configuration(config, config_path=None):
    """
    Save configuration to YAML file.
    
    Args:
        config (dict): Configuration to save
        config_path (str): Path to save configuration file
        
    Raises:
        PermissionError: If unable to write to file
    """
    config_path = config_path or get_default_config_path()
    
    # Remove metadata before saving
    config_to_save = config.copy()
    config_to_save.pop('_metadata', None)
    
    # Ensure directory exists
    config_file = Path(config_path)
    config_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(config_path, 'w') as f:
        yaml.dump(config_to_save, f, default_flow_style=False, indent=2)
    
    # Set appropriate file permissions (readable by user only)
    os.chmod(config_path, 0o600)