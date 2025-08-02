#!/usr/bin/env python3

import requests
from .config_loader import get_target_configuration
from .auth_manager import generate_auth_headers
from .validator import validate_network_connectivity


def test_target_connectivity(config, target_name, timeout=10):
    """
    Test network connectivity and authentication to target API.
    
    Args:
        config (dict): Loaded configuration
        target_name (str): Name of target to test
        timeout (int): Request timeout in seconds
        
    Returns:
        dict: Connectivity test results with status and error details
    """
    try:
        target_config = get_target_configuration(config, target_name)
        auth_headers = generate_auth_headers(target_config['auth'])
        
        # Perform connectivity test
        test_url = target_config['base_url']
        response = requests.head(test_url, headers=auth_headers, timeout=timeout)
        
        return {
            'target': target_name,
            'status': 'success' if response.status_code < 500 else 'warning',
            'status_code': response.status_code,
            'response_time': response.elapsed.total_seconds(),
            'url': test_url,
            'error': None,
            'troubleshooting': None
        }
        
    except requests.exceptions.Timeout:
        return {
            'target': target_name,
            'status': 'failed',
            'status_code': None,
            'response_time': None,
            'url': test_url if 'test_url' in locals() else 'unknown',
            'error': 'Request timeout',
            'troubleshooting': 'Check network connectivity and increase timeout value'
        }
    except requests.exceptions.ConnectionError:
        return {
            'target': target_name,
            'status': 'failed',
            'status_code': None,
            'response_time': None,
            'url': test_url if 'test_url' in locals() else 'unknown',
            'error': 'Connection error',
            'troubleshooting': 'Verify URL is correct and service is running'
        }
    except requests.exceptions.HTTPError as e:
        return {
            'target': target_name,
            'status': 'failed',
            'status_code': e.response.status_code if e.response else None,
            'response_time': None,
            'url': test_url if 'test_url' in locals() else 'unknown',
            'error': f'HTTP error: {e}',
            'troubleshooting': 'Check authentication credentials and API endpoint'
        }
    except Exception as e:
        return {
            'target': target_name,
            'status': 'failed',
            'status_code': None,
            'response_time': None,
            'url': 'unknown',
            'error': str(e),
            'troubleshooting': 'Check configuration syntax and environment variables'
        }


def list_targets_with_status(config, test_connectivity=True):
    """
    List all configured targets with their status information.
    
    Args:
        config (dict): Loaded configuration
        test_connectivity (bool): Whether to test connectivity for each target
        
    Returns:
        list: Target information with connectivity status
    """
    targets = []
    
    for target_name, target_config in config['targets'].items():
        target_info = {
            'name': target_name,
            'description': target_config.get('description', ''),
            'provider': target_config['provider'],
            'model': target_config['model']
        }
        
        if test_connectivity:
            connectivity_result = test_target_connectivity(config, target_name)
            target_info.update({
                'status': connectivity_result['status'],
                'response_time': connectivity_result['response_time'],
                'error': connectivity_result['error']
            })
        else:
            target_info['status'] = 'unknown'
            target_info['response_time'] = None
            target_info['error'] = None
        
        targets.append(target_info)
    
    return targets


def get_healthy_targets(config, max_response_time=5.0):
    """
    Get list of targets that are currently healthy and responsive.
    
    Args:
        config (dict): Loaded configuration
        max_response_time (float): Maximum acceptable response time in seconds
        
    Returns:
        list: Names of healthy targets
    """
    healthy_targets = []
    
    for target_name in config['targets'].keys():
        result = test_target_connectivity(config, target_name)
        
        if (result['status'] == 'success' and 
            result['response_time'] is not None and 
            result['response_time'] <= max_response_time):
            healthy_targets.append(target_name)
    
    return healthy_targets


def validate_target_model_compatibility(config, target_name, required_capabilities=None):
    """
    Validate that target model supports required capabilities.
    
    Args:
        config (dict): Loaded configuration
        target_name (str): Name of target to validate
        required_capabilities (list): List of required capabilities (e.g., ['chat', 'streaming'])
        
    Returns:
        dict: Validation results
    """
    required_capabilities = required_capabilities or []
    
    try:
        target_config = get_target_configuration(config, target_name)
        model_name = target_config['model']
        provider_type = target_config['type']
        
        # Basic capability checks based on provider type
        supported_capabilities = []
        
        if provider_type in ['openai', 'azure_openai']:
            supported_capabilities = ['chat', 'completion', 'streaming']
        elif provider_type == 'anthropic':
            supported_capabilities = ['chat', 'completion']
        elif provider_type == 'ollama':
            supported_capabilities = ['chat', 'completion', 'streaming']
        
        # Check if all required capabilities are supported
        missing_capabilities = [cap for cap in required_capabilities if cap not in supported_capabilities]
        
        return {
            'target': target_name,
            'model': model_name,
            'provider': provider_type,
            'supported_capabilities': supported_capabilities,
            'missing_capabilities': missing_capabilities,
            'compatible': len(missing_capabilities) == 0
        }
        
    except Exception as e:
        return {
            'target': target_name,
            'model': 'unknown',
            'provider': 'unknown',
            'supported_capabilities': [],
            'missing_capabilities': required_capabilities,
            'compatible': False,
            'error': str(e)
        }


def select_best_target(config, campaign_targets=None, criteria=None):
    """
    Select the best target based on specified criteria.
    
    Args:
        config (dict): Loaded configuration
        campaign_targets (list): List of target names to choose from, or None for all
        criteria (dict): Selection criteria (e.g., {'prefer_fast': True, 'max_response_time': 2.0})
        
    Returns:
        str: Name of selected target, or None if no suitable target found
    """
    criteria = criteria or {}
    target_names = campaign_targets or list(config['targets'].keys())
    
    if not target_names:
        return None
    
    # Test connectivity for all candidate targets
    target_results = []
    for target_name in target_names:
        result = test_target_connectivity(config, target_name)
        if result['status'] == 'success':
            target_results.append((target_name, result))
    
    if not target_results:
        return None
    
    # Apply selection criteria
    if criteria.get('prefer_fast', False):
        # Sort by response time
        target_results.sort(key=lambda x: x[1]['response_time'] or float('inf'))
    
    # Filter by maximum response time
    max_response_time = criteria.get('max_response_time')
    if max_response_time:
        target_results = [
            (name, result) for name, result in target_results
            if result['response_time'] and result['response_time'] <= max_response_time
        ]
    
    return target_results[0][0] if target_results else None


def generate_target_health_report(config):
    """
    Generate comprehensive health report for all targets.
    
    Args:
        config (dict): Loaded configuration
        
    Returns:
        dict: Health report with statistics and details
    """
    targets_status = list_targets_with_status(config, test_connectivity=True)
    
    total_targets = len(targets_status)
    healthy_targets = [t for t in targets_status if t['status'] == 'success']
    warning_targets = [t for t in targets_status if t['status'] == 'warning']
    failed_targets = [t for t in targets_status if t['status'] == 'failed']
    
    # Calculate average response time for healthy targets
    response_times = [t['response_time'] for t in healthy_targets if t['response_time']]
    avg_response_time = sum(response_times) / len(response_times) if response_times else 0
    
    return {
        'summary': {
            'total_targets': total_targets,
            'healthy_count': len(healthy_targets),
            'warning_count': len(warning_targets),
            'failed_count': len(failed_targets),
            'health_percentage': (len(healthy_targets) / total_targets * 100) if total_targets > 0 else 0
        },
        'performance': {
            'average_response_time': avg_response_time,
            'fastest_target': min(healthy_targets, key=lambda x: x['response_time'] or float('inf'))['name'] if healthy_targets else None,
            'slowest_target': max(healthy_targets, key=lambda x: x['response_time'] or 0)['name'] if healthy_targets else None
        },
        'details': {
            'healthy_targets': [t['name'] for t in healthy_targets],
            'warning_targets': [t['name'] for t in warning_targets],
            'failed_targets': [{'name': t['name'], 'error': t['error']} for t in failed_targets]
        }
    }


def add_target_to_config(config, target_name, target_config):
    """
    Add a new target to the configuration.
    
    Args:
        config (dict): Configuration to modify
        target_name (str): Name of the new target
        target_config (dict): Target configuration
        
    Returns:
        dict: Updated configuration
        
    Raises:
        ValueError: If target already exists or configuration is invalid
    """
    if target_name in config.get('targets', {}):
        raise ValueError(f"Target '{target_name}' already exists")
    
    # Validate required fields
    required_fields = ['provider', 'model']
    for field in required_fields:
        if field not in target_config:
            raise ValueError(f"Target configuration missing required field: {field}")
    
    # Validate provider exists
    provider_name = target_config['provider']
    if provider_name not in config.get('providers', {}):
        raise ValueError(f"Unknown provider: {provider_name}")
    
    # Add target to configuration
    if 'targets' not in config:
        config['targets'] = {}
    
    config['targets'][target_name] = target_config
    
    return config


def remove_target_from_config(config, target_name):
    """
    Remove a target from the configuration.
    
    Args:
        config (dict): Configuration to modify
        target_name (str): Name of target to remove
        
    Returns:
        dict: Updated configuration
        
    Raises:
        ValueError: If target doesn't exist or is referenced by campaigns
    """
    if target_name not in config.get('targets', {}):
        raise ValueError(f"Target '{target_name}' does not exist")
    
    # Check if target is referenced by any campaigns
    campaigns_using_target = []
    for campaign_name, campaign_config in config.get('campaigns', {}).items():
        if target_name in campaign_config.get('targets', []):
            campaigns_using_target.append(campaign_name)
    
    if campaigns_using_target:
        raise ValueError(f"Cannot remove target '{target_name}' - it is used by campaigns: {campaigns_using_target}")
    
    # Remove target
    del config['targets'][target_name]
    
    return config