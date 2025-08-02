#!/usr/bin/env python3

from .env_resolver import resolve_environment_variables


def generate_auth_headers(auth_config):
    """
    Generate authentication headers based on configuration.
    
    Args:
        auth_config (dict): Authentication configuration
        
    Returns:
        dict: HTTP headers for authentication
    """
    auth_type = auth_config.get('type')
    
    if auth_type == 'api_key':
        return generate_api_key_headers(auth_config)
    elif auth_type == 'bearer':
        return generate_bearer_token_headers(auth_config)
    elif auth_type == 'custom':
        return generate_custom_headers(auth_config)
    else:
        raise ValueError(f"Unsupported authentication type: {auth_type}")


def generate_api_key_headers(auth_config):
    """
    Generate headers for API key authentication.
    
    Args:
        auth_config (dict): API key authentication configuration
        
    Returns:
        dict: HTTP headers with API key
    """
    header_name = auth_config['header']
    auth_format = auth_config['format']
    resolved_value = resolve_environment_variables(auth_format)
    
    return {header_name: resolved_value}


def generate_bearer_token_headers(auth_config):
    """
    Generate headers for bearer token authentication.
    
    Args:
        auth_config (dict): Bearer token authentication configuration
        
    Returns:
        dict: HTTP headers with bearer token
    """
    token = resolve_environment_variables(auth_config['token'])
    return {'Authorization': f'Bearer {token}'}


def generate_custom_headers(auth_config):
    """
    Generate custom authentication headers.
    
    Args:
        auth_config (dict): Custom authentication configuration
        
    Returns:
        dict: HTTP headers with custom authentication
    """
    headers = {}
    for header_name, header_value in auth_config['headers'].items():
        resolved_value = resolve_environment_variables(header_value)
        headers[header_name] = resolved_value
    
    return headers


def validate_credentials(auth_config):
    """
    Validate that authentication credentials are properly configured.
    
    Args:
        auth_config (dict): Authentication configuration to validate
        
    Returns:
        dict: Validation results with status and any error messages
    """
    try:
        headers = generate_auth_headers(auth_config)
        missing_values = [k for k, v in headers.items() if not v]
        
        if missing_values:
            return {
                'valid': False,
                'error': f"Missing values for headers: {missing_values}"
            }
        
        return {'valid': True}
    except Exception as e:
        return {
            'valid': False,
            'error': str(e)
        }


def mask_sensitive_headers(headers):
    """
    Mask sensitive header values for logging purposes.
    
    Args:
        headers (dict): HTTP headers that may contain sensitive data
        
    Returns:
        dict: Headers with sensitive values masked
    """
    sensitive_headers = {
        'authorization', 'x-api-key', 'api-key', 'bearer',
        'x-auth-token', 'x-access-token'
    }
    
    masked_headers = {}
    for key, value in headers.items():
        if key.lower() in sensitive_headers:
            if len(value) > 8:
                masked_headers[key] = value[:4] + '...' + value[-4:]
            else:
                masked_headers[key] = '***'
        else:
            masked_headers[key] = value
    
    return masked_headers


def get_supported_auth_types():
    """
    Get list of supported authentication types.
    
    Returns:
        list: List of supported authentication type strings
    """
    return ['api_key', 'bearer', 'custom']


def validate_auth_config_schema(auth_config):
    """
    Validate authentication configuration schema.
    
    Args:
        auth_config (dict): Authentication configuration to validate
        
    Returns:
        list: List of validation errors, empty if valid
    """
    errors = []
    
    if not isinstance(auth_config, dict):
        errors.append("Authentication config must be a dictionary")
        return errors
    
    auth_type = auth_config.get('type')
    if not auth_type:
        errors.append("Authentication type is required")
        return errors
    
    if auth_type not in get_supported_auth_types():
        errors.append(f"Unsupported authentication type: {auth_type}")
    
    # Validate type-specific fields
    if auth_type == 'api_key':
        if 'header' not in auth_config:
            errors.append("API key authentication requires 'header' field")
        if 'format' not in auth_config:
            errors.append("API key authentication requires 'format' field")
    
    elif auth_type == 'bearer':
        if 'token' not in auth_config:
            errors.append("Bearer token authentication requires 'token' field")
    
    elif auth_type == 'custom':
        if 'headers' not in auth_config:
            errors.append("Custom authentication requires 'headers' field")
        elif not isinstance(auth_config['headers'], dict):
            errors.append("Custom authentication 'headers' must be a dictionary")
    
    return errors