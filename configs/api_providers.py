#!/usr/bin/env python3


def format_openai_request(prompt, model_params):
    """
    Format request payload for OpenAI-compatible APIs.
    
    Args:
        prompt (str): User prompt to send
        model_params (dict): Model configuration parameters
        
    Returns:
        dict: Formatted request payload
    """
    return {
        "model": model_params["model"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": model_params.get("temperature", 0.7),
        "max_tokens": model_params.get("max_tokens", 1000)
    }


def format_anthropic_request(prompt, model_params):
    """
    Format request payload for Anthropic Claude API.
    
    Args:
        prompt (str): User prompt to send
        model_params (dict): Model configuration parameters
        
    Returns:
        dict: Formatted request payload
    """
    return {
        "model": model_params["model"],
        "max_tokens": model_params.get("max_tokens", 1000),
        "messages": [{"role": "user", "content": prompt}],
        "temperature": model_params.get("temperature", 0.7)
    }


def format_azure_openai_request(prompt, model_params):
    """
    Format request payload for Azure OpenAI deployments.
    
    Args:
        prompt (str): User prompt to send
        model_params (dict): Model configuration parameters
        
    Returns:
        dict: Formatted request payload
    """
    base_payload = format_openai_request(prompt, model_params)
    # Azure uses deployment name instead of model in URL path
    base_payload.pop("model", None)
    return base_payload


def format_ollama_request(prompt, model_params):
    """
    Format request payload for Ollama API.
    
    Args:
        prompt (str): User prompt to send
        model_params (dict): Model configuration parameters
        
    Returns:
        dict: Formatted request payload
    """
    return {
        "model": model_params["model"],
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": model_params.get("temperature", 0.7),
            "num_predict": model_params.get("max_tokens", 1000)
        }
    }


def format_custom_request(prompt, model_params, format_template=None):
    """
    Format request payload for custom API endpoints.
    
    Args:
        prompt (str): User prompt to send
        model_params (dict): Model configuration parameters
        format_template (dict): Custom format template
        
    Returns:
        dict: Formatted request payload
    """
    if format_template:
        # Use custom template with variable substitution
        payload = format_template.copy()
        for key, value in payload.items():
            if isinstance(value, str):
                payload[key] = value.replace("{prompt}", prompt)
                payload[key] = payload[key].replace("{model}", model_params.get("model", ""))
                payload[key] = payload[key].replace("{temperature}", str(model_params.get("temperature", 0.7)))
                payload[key] = payload[key].replace("{max_tokens}", str(model_params.get("max_tokens", 1000)))
        return payload
    else:
        # Default to OpenAI format for custom APIs
        return format_openai_request(prompt, model_params)


def get_request_formatter(provider_type):
    """
    Get the appropriate request formatter function for a provider type.
    
    Args:
        provider_type (str): Type of API provider
        
    Returns:
        function: Request formatter function
    """
    formatters = {
        'openai': format_openai_request,
        'anthropic': format_anthropic_request,
        'azure_openai': format_azure_openai_request,
        'ollama': format_ollama_request,
        'custom': format_custom_request
    }
    
    formatter = formatters.get(provider_type)
    if not formatter:
        raise ValueError(f"Unsupported provider type: {provider_type}")
    
    return formatter


def parse_openai_response(response_data):
    """
    Parse response from OpenAI-compatible APIs.
    
    Args:
        response_data (dict): Raw API response
        
    Returns:
        str: Extracted response content
    """
    try:
        return response_data['choices'][0]['message']['content']
    except (KeyError, IndexError) as e:
        raise ValueError(f"Invalid OpenAI response format: {e}")


def parse_anthropic_response(response_data):
    """
    Parse response from Anthropic Claude API.
    
    Args:
        response_data (dict): Raw API response
        
    Returns:
        str: Extracted response content
    """
    try:
        return response_data['content'][0]['text']
    except (KeyError, IndexError) as e:
        raise ValueError(f"Invalid Anthropic response format: {e}")


def parse_ollama_response(response_data):
    """
    Parse response from Ollama API.
    
    Args:
        response_data (dict): Raw API response
        
    Returns:
        str: Extracted response content
    """
    try:
        return response_data['response']
    except KeyError as e:
        raise ValueError(f"Invalid Ollama response format: {e}")


def parse_custom_response(response_data, parser_template=None):
    """
    Parse response from custom API endpoints.
    
    Args:
        response_data (dict): Raw API response
        parser_template (dict): Custom parser configuration
        
    Returns:
        str: Extracted response content
    """
    if parser_template and 'path' in parser_template:
        # Use JSONPath-like syntax to extract content
        current = response_data
        for key in parser_template['path']:
            if isinstance(current, dict):
                current = current.get(key)
            elif isinstance(current, list) and isinstance(key, int):
                current = current[key] if len(current) > key else None
            else:
                raise ValueError(f"Cannot navigate to key '{key}' in response")
        return str(current) if current is not None else ""
    else:
        # Default to OpenAI format for custom APIs
        return parse_openai_response(response_data)


def get_response_parser(provider_type):
    """
    Get the appropriate response parser function for a provider type.
    
    Args:
        provider_type (str): Type of API provider
        
    Returns:
        function: Response parser function
    """
    parsers = {
        'openai': parse_openai_response,
        'anthropic': parse_anthropic_response,
        'azure_openai': parse_openai_response,  # Azure uses OpenAI format
        'ollama': parse_ollama_response,
        'custom': parse_custom_response
    }
    
    parser = parsers.get(provider_type)
    if not parser:
        raise ValueError(f"Unsupported provider type: {provider_type}")
    
    return parser


def get_supported_providers():
    """
    Get list of supported API providers.
    
    Returns:
        list: List of supported provider type strings
    """
    return ['openai', 'anthropic', 'azure_openai', 'ollama', 'custom']


def get_provider_endpoints():
    """
    Get default API endpoints for supported providers.
    
    Returns:
        dict: Mapping of provider types to default endpoints
    """
    return {
        'openai': 'https://api.openai.com/v1/chat/completions',
        'anthropic': 'https://api.anthropic.com/v1/messages',
        'azure_openai': 'https://{resource}.openai.azure.com/openai/deployments/{deployment}/chat/completions',
        'ollama': 'http://localhost:11434/api/generate',
        'custom': None  # Must be specified in configuration
    }


def validate_provider_config(provider_config):
    """
    Validate provider configuration schema.
    
    Args:
        provider_config (dict): Provider configuration to validate
        
    Returns:
        list: List of validation errors, empty if valid
    """
    errors = []
    
    if not isinstance(provider_config, dict):
        errors.append("Provider config must be a dictionary")
        return errors
    
    provider_type = provider_config.get('type')
    if not provider_type:
        errors.append("Provider type is required")
        return errors
    
    if provider_type not in get_supported_providers():
        errors.append(f"Unsupported provider type: {provider_type}")
    
    # Validate required fields
    if 'base_url' not in provider_config:
        errors.append("Provider base_url is required")
    
    if 'auth' not in provider_config:
        errors.append("Provider authentication configuration is required")
    
    # Validate provider-specific requirements
    if provider_type == 'azure_openai':
        if 'api_version' not in provider_config:
            errors.append("Azure OpenAI provider requires api_version")
        if 'deployment' not in provider_config:
            errors.append("Azure OpenAI provider requires deployment name")
    
    return errors