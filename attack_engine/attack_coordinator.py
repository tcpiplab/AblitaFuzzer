#!/usr/bin/env python3

"""
Unified attack interface functions for AblitaFuzzer.

Provides provider-agnostic attack coordination, response normalization,
and error handling for different API providers.
"""

import time
import json
from typing import Dict, List, Callable, Optional, Any, Union
from concurrent.futures import ThreadPoolExecutor

from .concurrent_executor import execute_concurrent_attacks, calculate_optimal_workers
from .rate_limiter import create_token_bucket_limiter, get_rate_limiter_for_endpoint
from .retry_handler import with_retry, create_circuit_breaker, execute_with_circuit_breaker
from .session_manager import create_attack_session, update_session_progress, get_resumable_prompts
from .progress_monitor import create_progress_monitor, update_progress, finalize_progress

from configs.config import get_config
from configs.config_loader import get_target_configuration, get_attack_model_configuration
from configs.api_providers import get_request_formatter, get_response_parser
from configs.auth_manager import generate_auth_headers


def coordinate_attack_campaign(
    prompts: List[str],
    target_name: str,
    session_name: Optional[str] = None,
    max_workers: Optional[int] = None,
    rate_limit: Optional[float] = None,
    resume_session_id: Optional[str] = None
) -> Dict:
    """
    Coordinate a complete attack campaign with concurrent execution.
    
    Args:
        prompts: List of attack prompts to execute
        target_name: Name of target configuration to attack
        session_name: Optional name for attack session
        max_workers: Optional override for concurrent workers
        rate_limit: Optional override for rate limiting
        resume_session_id: Optional session ID to resume
        
    Returns:
        Dictionary containing campaign results and statistics
    """
    try:
        # Load configuration
        config = get_config()
        target_config = get_target_configuration(config, target_name)
        
        # Handle session resumption
        if resume_session_id:
            remaining_prompts = get_resumable_prompts(resume_session_id)
            if not remaining_prompts:
                return {
                    'success': True,
                    'message': 'Session already completed',
                    'session_id': resume_session_id,
                    'results': []
                }
            prompts = remaining_prompts
            session_id = resume_session_id
        else:
            # Create new session
            if session_name is None:
                session_name = f"attack_{target_name}_{int(time.time())}"
            
            session_id = create_attack_session(
                session_name=session_name,
                target_config=target_config,
                prompts=prompts
            )
        
        # Configure execution parameters
        if max_workers is None:
            max_workers = calculate_optimal_workers(
                total_prompts=len(prompts),
                average_response_time=2.0,  # Estimate
                rate_limit=rate_limit or 10.0
            )
        
        if rate_limit is None:
            rate_limit = 10.0  # Default rate limit
        
        # Create attack function for this target
        attack_func = create_attack_function(target_config)
        
        # Create progress monitor
        progress_monitor = create_progress_monitor(len(prompts))
        
        def progress_callback(success: bool) -> None:
            update_progress(progress_monitor, success)
        
        # Execute concurrent attacks
        print(f"Starting attack campaign '{session_name}' against {target_name}")
        print(f"Prompts: {len(prompts)}, Workers: {max_workers}, Rate limit: {rate_limit}/s")
        
        results = execute_concurrent_attacks(
            prompts=prompts,
            attack_func=attack_func,
            max_workers=max_workers,
            rate_limit=rate_limit,
            progress_callback=progress_callback
        )
        
        # Update session with results
        for result in results:
            update_session_progress(session_id, result['prompt'], result)
        
        # Finalize progress and get statistics
        final_stats = finalize_progress(progress_monitor, "Attack campaign completed")
        
        return {
            'success': True,
            'session_id': session_id,
            'session_name': session_name,
            'target_name': target_name,
            'results': results,
            'statistics': final_stats,
            'execution_config': {
                'max_workers': max_workers,
                'rate_limit': rate_limit,
                'total_prompts': len(prompts)
            }
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'session_id': session_id if 'session_id' in locals() else None
        }


def create_attack_function(target_config: Dict) -> Callable[[str], Dict]:
    """
    Create an attack function tailored for specific target configuration.
    
    Args:
        target_config: Target configuration dictionary
        
    Returns:
        Function that executes attacks against the configured target
    """
    # Extract configuration details
    provider_type = target_config.get('type', 'openai')
    base_url = target_config['base_url']
    auth_config = target_config.get('auth', {})
    model_params = target_config.get('model_params', {})
    
    # Get provider-specific formatters
    request_formatter = get_request_formatter(provider_type)
    response_parser = get_response_parser(provider_type)
    
    # Generate authentication headers
    auth_headers = generate_auth_headers(auth_config)
    
    # Create circuit breaker for this target
    circuit_breaker = create_circuit_breaker()
    
    @with_retry(max_attempts=3, base_delay=1.0, max_delay=30.0)
    def attack_function(prompt: str) -> Dict:
        """
        Execute single attack against configured target.
        
        Args:
            prompt: Attack prompt to send
            
        Returns:
            Normalized attack response dictionary
        """
        def execute_request():
            # Format request for provider
            request_payload = request_formatter(prompt, model_params)
            
            # Prepare headers
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'AblitaFuzzer/1.0'
            }
            headers.update(auth_headers)
            
            # Make request
            import requests
            response = requests.post(
                base_url,
                headers=headers,
                json=request_payload,
                timeout=30
            )
            
            # Check for HTTP errors
            response.raise_for_status()
            
            # Parse response using provider-specific parser
            parsed_response = response_parser(response.json())
            
            return normalize_attack_response(parsed_response, response.status_code)
        
        # Execute with circuit breaker
        return execute_with_circuit_breaker(execute_request, circuit_breaker)
    
    return attack_function


def normalize_attack_response(
    raw_response: Any,
    status_code: int,
    provider_type: str = 'openai'
) -> Dict:
    """
    Normalize API response to standard format across providers.
    
    Args:
        raw_response: Raw response from API provider
        status_code: HTTP status code
        provider_type: Type of API provider
        
    Returns:
        Normalized response dictionary
    """
    normalized = {
        'success': status_code == 200,
        'status_code': status_code,
        'timestamp': time.time(),
        'provider_type': provider_type,
        'raw_response': raw_response
    }
    
    if isinstance(raw_response, dict):
        # Extract common fields across providers
        if 'choices' in raw_response and raw_response['choices']:
            # OpenAI-style response
            choice = raw_response['choices'][0]
            if 'message' in choice:
                normalized['response_text'] = choice['message'].get('content', '')
            elif 'text' in choice:
                normalized['response_text'] = choice['text']
        
        elif 'message' in raw_response and isinstance(raw_response['message'], dict):
            # Ollama-style response
            normalized['response_text'] = raw_response['message'].get('content', '')
        
        elif 'content' in raw_response:
            # Anthropic-style response
            if isinstance(raw_response['content'], list) and raw_response['content']:
                normalized['response_text'] = raw_response['content'][0].get('text', '')
            else:
                normalized['response_text'] = raw_response['content']
        
        elif 'response' in raw_response:
            # Generic response field
            normalized['response_text'] = raw_response['response']
        
        # Extract usage information if available
        if 'usage' in raw_response:
            normalized['usage'] = raw_response['usage']
        
        # Extract model information
        if 'model' in raw_response:
            normalized['model'] = raw_response['model']
    
    else:
        # Handle non-dict responses
        normalized['response_text'] = str(raw_response)
    
    # Ensure response_text exists
    if 'response_text' not in normalized:
        normalized['response_text'] = ''
    
    return normalized


def handle_attack_error(
    error: Exception,
    prompt: str,
    target_config: Dict
) -> Dict:
    """
    Handle and normalize attack errors.
    
    Args:
        error: Exception that occurred during attack
        prompt: Original attack prompt
        target_config: Target configuration
        
    Returns:
        Normalized error response dictionary
    """
    error_response = {
        'success': False,
        'error': str(error),
        'error_type': type(error).__name__,
        'prompt': prompt,
        'target_config': target_config.get('name', 'unknown'),
        'timestamp': time.time()
    }
    
    # Extract additional information from HTTP errors
    if hasattr(error, 'response'):
        response = error.response
        error_response['status_code'] = response.status_code
        
        try:
            error_response['error_details'] = response.json()
        except (ValueError, AttributeError):
            error_response['error_details'] = response.text if hasattr(response, 'text') else None
        
        # Categorize error type
        if response.status_code == 429:
            error_response['error_category'] = 'rate_limited'
        elif response.status_code in [500, 502, 503, 504]:
            error_response['error_category'] = 'server_error'
        elif response.status_code in [401, 403]:
            error_response['error_category'] = 'authentication_error'
        else:
            error_response['error_category'] = 'client_error'
    
    else:
        # Non-HTTP errors
        error_name = type(error).__name__.lower()
        if 'timeout' in error_name:
            error_response['error_category'] = 'timeout'
        elif 'connection' in error_name:
            error_response['error_category'] = 'connection_error'
        else:
            error_response['error_category'] = 'unknown_error'
    
    return error_response


def execute_multi_target_campaign(
    prompts: List[str],
    target_names: List[str],
    session_name: Optional[str] = None,
    concurrent_targets: int = 2
) -> Dict:
    """
    Execute attack campaign against multiple targets concurrently.
    
    Args:
        prompts: List of attack prompts to execute
        target_names: List of target configuration names
        session_name: Optional name for attack session
        concurrent_targets: Number of targets to attack concurrently
        
    Returns:
        Dictionary containing multi-target campaign results
    """
    if session_name is None:
        session_name = f"multi_target_{int(time.time())}"
    
    campaign_results = {
        'success': True,
        'session_name': session_name,
        'target_results': {},
        'combined_statistics': {},
        'errors': []
    }
    
    def execute_target_campaign(target_name: str) -> Dict:
        """Execute campaign against single target."""
        try:
            target_session_name = f"{session_name}_{target_name}"
            return coordinate_attack_campaign(
                prompts=prompts,
                target_name=target_name,
                session_name=target_session_name
            )
        except Exception as e:
            return {
                'success': False,
                'target_name': target_name,
                'error': str(e),
                'error_type': type(e).__name__
            }
    
    # Execute target campaigns concurrently
    print(f"Starting multi-target campaign against {len(target_names)} targets")
    
    with ThreadPoolExecutor(max_workers=concurrent_targets) as executor:
        future_to_target = {
            executor.submit(execute_target_campaign, target): target 
            for target in target_names
        }
        
        for future in future_to_target:
            target_name = future_to_target[future]
            try:
                result = future.result()
                campaign_results['target_results'][target_name] = result
                
                if not result.get('success', False):
                    campaign_results['errors'].append(result)
                    
            except Exception as e:
                error_result = {
                    'target_name': target_name,
                    'error': str(e),
                    'error_type': type(e).__name__
                }
                campaign_results['target_results'][target_name] = error_result
                campaign_results['errors'].append(error_result)
    
    # Calculate combined statistics
    all_results = []
    total_successful = 0
    total_failed = 0
    
    for target_name, target_result in campaign_results['target_results'].items():
        if target_result.get('success') and 'results' in target_result:
            target_results = target_result['results']
            all_results.extend(target_results)
            
            for result in target_results:
                if result.get('success', False):
                    total_successful += 1
                else:
                    total_failed += 1
    
    campaign_results['combined_statistics'] = {
        'total_targets': len(target_names),
        'successful_targets': len([r for r in campaign_results['target_results'].values() 
                                 if r.get('success', False)]),
        'total_attacks': len(all_results),
        'successful_attacks': total_successful,
        'failed_attacks': total_failed,
        'overall_success_rate': total_successful / max(1, len(all_results))
    }
    
    # Mark overall campaign as failed if any targets failed
    if campaign_results['errors']:
        campaign_results['success'] = False
    
    print(f"Multi-target campaign completed: {campaign_results['combined_statistics']}")
    
    return campaign_results


def validate_attack_configuration(target_config: Dict) -> Dict:
    """
    Validate attack target configuration for completeness and correctness.
    
    Args:
        target_config: Target configuration to validate
        
    Returns:
        Validation result dictionary
    """
    validation_result = {
        'valid': True,
        'errors': [],
        'warnings': [],
        'recommendations': []
    }
    
    # Check required fields
    required_fields = ['base_url', 'type', 'auth']
    for field in required_fields:
        if field not in target_config:
            validation_result['errors'].append(f"Missing required field: {field}")
            validation_result['valid'] = False
    
    # Validate provider type
    if 'type' in target_config:
        supported_types = ['openai', 'anthropic', 'azure_openai', 'ollama']
        if target_config['type'] not in supported_types:
            validation_result['warnings'].append(
                f"Provider type '{target_config['type']}' may not be fully supported"
            )
    
    # Validate authentication
    if 'auth' in target_config:
        auth_config = target_config['auth']
        if 'type' not in auth_config:
            validation_result['errors'].append("Authentication configuration missing 'type' field")
            validation_result['valid'] = False
        
        auth_type = auth_config.get('type')
        if auth_type == 'api_key' and 'format' not in auth_config:
            validation_result['errors'].append("API key authentication missing 'format' field")
            validation_result['valid'] = False
    
    # Check URL format
    if 'base_url' in target_config:
        base_url = target_config['base_url']
        if not (base_url.startswith('http://') or base_url.startswith('https://')):
            validation_result['warnings'].append("Base URL should start with http:// or https://")
    
    # Add recommendations
    if validation_result['valid']:
        validation_result['recommendations'].extend([
            "Test connectivity before running large campaigns",
            "Configure appropriate rate limits for the target API",
            "Consider using circuit breakers for production APIs"
        ])
    
    return validation_result