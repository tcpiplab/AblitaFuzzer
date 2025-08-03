#!/usr/bin/env python3

import re
import os


def resolve_environment_variables(config_value):
    """
    Resolve ${VAR_NAME} references in configuration values.
    
    Args:
        config_value (str): Configuration value that may contain env var references
        
    Returns:
        str: Resolved configuration value
    """
    if not isinstance(config_value, str):
        return config_value
    
    def replace_env_var(match):
        var_name = match.group(1)
        env_value = os.getenv(var_name)
        if env_value is None:
            raise ValueError(f"Required environment variable '{var_name}' is not set")
        return env_value
    
    return re.sub(r'\$\{([^}]+)\}', replace_env_var, config_value)


def resolve_environment_variables_recursive(config):
    """
    Recursively resolve environment variables in configuration dictionary.
    
    Args:
        config (dict): Configuration dictionary that may contain env var references
        
    Returns:
        dict: Configuration with all environment variables resolved
    """
    if isinstance(config, dict):
        return {key: resolve_environment_variables_recursive(value) for key, value in config.items()}
    elif isinstance(config, list):
        return [resolve_environment_variables_recursive(item) for item in config]
    elif isinstance(config, str):
        return resolve_environment_variables(config)
    else:
        return config


def validate_required_environment_variables(config):
    """
    Ensure all required environment variables are set.
    
    Args:
        config (dict): Configuration dictionary to validate
        
    Returns:
        list: List of missing environment variables
    """
    required_vars = set()
    missing_vars = []
    
    def extract_env_vars(obj):
        if isinstance(obj, dict):
            for value in obj.values():
                extract_env_vars(value)
        elif isinstance(obj, list):
            for item in obj:
                extract_env_vars(item)
        elif isinstance(obj, str):
            vars_in_string = re.findall(r'\$\{([^}]+)\}', obj)
            required_vars.update(vars_in_string)
    
    extract_env_vars(config)
    
    for var_name in required_vars:
        if os.getenv(var_name) is None:
            missing_vars.append(var_name)
    
    return missing_vars


def generate_env_template(config):
    """
    Generate template .env file for user reference.
    
    Args:
        config (dict): Configuration dictionary to analyze
        
    Returns:
        str: Template .env file content
    """
    env_vars = set()
    
    def extract_env_vars(obj):
        if isinstance(obj, dict):
            for value in obj.values():
                extract_env_vars(value)
        elif isinstance(obj, list):
            for item in obj:
                extract_env_vars(item)
        elif isinstance(obj, str):
            vars_in_string = re.findall(r'\$\{([^}]+)\}', obj)
            env_vars.update(vars_in_string)
    
    extract_env_vars(config)
    
    template_lines = ["# AblitaFuzzer Environment Variables Template", ""]
    for var_name in sorted(env_vars):
        template_lines.append(f"{var_name}=your_value_here")
    
    return "\n".join(template_lines)


def check_environment_variable_safety(var_name, var_value):
    """
    Check if environment variable contains potentially unsafe values.
    
    Args:
        var_name (str): Name of environment variable
        var_value (str): Value of environment variable
        
    Returns:
        dict: Safety check results with warnings
    """
    warnings = []
    
    # Check for common secrets that should be masked
    secret_patterns = [
        r'sk-[a-zA-Z0-9]{20,}',  # OpenAI API keys
        r'[a-zA-Z0-9]{32}',      # Generic 32-char keys
        r'Bearer\s+[a-zA-Z0-9]+', # Bearer tokens
    ]
    
    for pattern in secret_patterns:
        if re.search(pattern, var_value):
            warnings.append(f"Variable '{var_name}' appears to contain a secret key")
            break
    
    # Check for localhost in production variables
    if 'PROD' in var_name.upper() and 'localhost' in var_value.lower():
        warnings.append(f"Production variable '{var_name}' contains localhost reference")
    
    return {
        'safe': len(warnings) == 0,
        'warnings': warnings
    }