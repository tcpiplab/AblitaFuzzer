#!/usr/bin/env python3

"""
Retry logic and circuit breaker functions for AblitaFuzzer.

Provides intelligent retry strategies with exponential backoff, jitter,
and circuit breaker pattern for handling transient failures.
"""

import time
import random
from typing import Dict, Callable, Optional, Any, List
from functools import wraps
import threading


def with_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True,
    retryable_exceptions: Optional[List[str]] = None
) -> Callable:
    """
    Decorator to add retry logic with exponential backoff to functions.
    
    Args:
        max_attempts: Maximum number of retry attempts
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        exponential_base: Base for exponential backoff calculation
        jitter: Whether to add random jitter to delays
        retryable_exceptions: List of exception names that should trigger retries
        
    Returns:
        Decorated function with retry logic
    """
    if retryable_exceptions is None:
        retryable_exceptions = ['ConnectionError', 'TimeoutError', 'HTTPError']
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
                    # Check if this exception should trigger a retry
                    if not should_retry_error(e, retryable_exceptions):
                        break
                    
                    # Don't retry on final attempt
                    if attempt == max_attempts - 1:
                        break
                    
                    # Calculate delay with exponential backoff
                    delay = min(
                        max_delay,
                        base_delay * (exponential_base ** attempt)
                    )
                    
                    # Add jitter if enabled
                    if jitter:
                        delay *= (0.5 + random.random() * 0.5)
                    
                    time.sleep(delay)
            
            # Re-raise the last exception if all retries failed
            raise last_exception
        
        return wrapper
    return decorator


def should_retry_error(
    error: Exception,
    retryable_exceptions: Optional[List[str]] = None
) -> bool:
    """
    Determine if an error should trigger a retry attempt.
    
    Args:
        error: Exception that occurred during request
        retryable_exceptions: List of exception names that are retryable
        
    Returns:
        True if error is retryable, False otherwise
    """
    if retryable_exceptions is None:
        retryable_exceptions = ['ConnectionError', 'TimeoutError', 'HTTPError']
    
    error_name = type(error).__name__
    
    # Check if error type is in retryable list
    if error_name in retryable_exceptions:
        return True
    
    # Check HTTP status codes for retryable conditions
    if hasattr(error, 'response') and hasattr(error.response, 'status_code'):
        retryable_status_codes = [429, 500, 502, 503, 504]
        return error.response.status_code in retryable_status_codes
    
    # Check for common network-related error messages
    error_message = str(error).lower()
    retryable_keywords = [
        'connection', 'timeout', 'temporary', 'service unavailable',
        'bad gateway', 'gateway timeout', 'too many requests'
    ]
    
    for keyword in retryable_keywords:
        if keyword in error_message:
            return True
    
    return False


def execute_with_retry(
    func: Callable,
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True
) -> Any:
    """
    Execute function with retry logic without using decorator.
    
    Args:
        func: Function to execute with retry logic
        max_attempts: Maximum number of retry attempts
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        exponential_base: Base for exponential backoff calculation
        jitter: Whether to add random jitter to delays
        
    Returns:
        Function result or raises last exception if all retries failed
    """
    last_exception = None
    
    for attempt in range(max_attempts):
        try:
            return func()
        except Exception as e:
            last_exception = e
            
            # Check if this exception should trigger a retry
            if not should_retry_error(e):
                break
            
            # Don't retry on final attempt
            if attempt == max_attempts - 1:
                break
            
            # Calculate delay with exponential backoff
            delay = min(
                max_delay,
                base_delay * (exponential_base ** attempt)
            )
            
            # Add jitter if enabled
            if jitter:
                delay *= (0.5 + random.random() * 0.5)
            
            time.sleep(delay)
    
    # Re-raise the last exception if all retries failed
    raise last_exception


def create_circuit_breaker(
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    success_threshold: int = 2
) -> Dict:
    """
    Create a circuit breaker for handling persistent failures.
    
    Args:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Time to wait before attempting recovery
        success_threshold: Number of successes needed to close circuit
        
    Returns:
        Circuit breaker state dictionary
    """
    return {
        'state': 'closed',  # closed, open, half-open
        'failure_count': 0,
        'success_count': 0,
        'last_failure_time': 0,
        'failure_threshold': failure_threshold,
        'recovery_timeout': recovery_timeout,
        'success_threshold': success_threshold,
        'lock': threading.Lock(),
        'total_calls': 0,
        'total_failures': 0,
        'total_successes': 0
    }


def execute_with_circuit_breaker(
    func: Callable,
    circuit_breaker: Dict
) -> Any:
    """
    Execute function with circuit breaker pattern for persistent failures.
    
    Args:
        func: Function to execute
        circuit_breaker: Circuit breaker state dictionary
        
    Returns:
        Function result or raises exception if circuit is open
    """
    with circuit_breaker['lock']:
        circuit_breaker['total_calls'] += 1
        current_time = time.time()
        
        # Check if circuit should transition from open to half-open
        if (circuit_breaker['state'] == 'open' and 
            current_time - circuit_breaker['last_failure_time'] > circuit_breaker['recovery_timeout']):
            circuit_breaker['state'] = 'half-open'
            circuit_breaker['success_count'] = 0
        
        # Fail fast if circuit is open
        if circuit_breaker['state'] == 'open':
            raise Exception("Circuit breaker is open - too many recent failures")
    
    try:
        result = func()
        
        # Handle success
        with circuit_breaker['lock']:
            circuit_breaker['total_successes'] += 1
            
            if circuit_breaker['state'] == 'half-open':
                circuit_breaker['success_count'] += 1
                if circuit_breaker['success_count'] >= circuit_breaker['success_threshold']:
                    circuit_breaker['state'] = 'closed'
                    circuit_breaker['failure_count'] = 0
            elif circuit_breaker['state'] == 'closed':
                # Reset failure count on success in closed state
                circuit_breaker['failure_count'] = 0
        
        return result
    
    except Exception as e:
        # Handle failure
        with circuit_breaker['lock']:
            circuit_breaker['total_failures'] += 1
            circuit_breaker['failure_count'] += 1
            circuit_breaker['last_failure_time'] = current_time
            
            # Open circuit if failure threshold exceeded
            if (circuit_breaker['state'] in ['closed', 'half-open'] and 
                circuit_breaker['failure_count'] >= circuit_breaker['failure_threshold']):
                circuit_breaker['state'] = 'open'
        
        raise e


def get_circuit_breaker_statistics(circuit_breaker: Dict) -> Dict:
    """
    Get statistics from circuit breaker for monitoring.
    
    Args:
        circuit_breaker: Circuit breaker state dictionary
        
    Returns:
        Dictionary containing circuit breaker statistics
    """
    with circuit_breaker['lock']:
        total_calls = circuit_breaker['total_calls']
        
        stats = {
            'state': circuit_breaker['state'],
            'failure_count': circuit_breaker['failure_count'],
            'success_count': circuit_breaker['success_count'],
            'total_calls': total_calls,
            'total_failures': circuit_breaker['total_failures'],
            'total_successes': circuit_breaker['total_successes'],
            'failure_rate': circuit_breaker['total_failures'] / max(1, total_calls),
            'success_rate': circuit_breaker['total_successes'] / max(1, total_calls),
            'failure_threshold': circuit_breaker['failure_threshold'],
            'recovery_timeout': circuit_breaker['recovery_timeout']
        }
        
        if circuit_breaker['state'] == 'open':
            time_until_half_open = max(0, 
                circuit_breaker['recovery_timeout'] - 
                (time.time() - circuit_breaker['last_failure_time'])
            )
            stats['time_until_half_open'] = time_until_half_open
        
        return stats


def reset_circuit_breaker(circuit_breaker: Dict) -> None:
    """
    Reset circuit breaker to initial closed state.
    
    Args:
        circuit_breaker: Circuit breaker state dictionary
    """
    with circuit_breaker['lock']:
        circuit_breaker['state'] = 'closed'
        circuit_breaker['failure_count'] = 0
        circuit_breaker['success_count'] = 0
        circuit_breaker['last_failure_time'] = 0


def create_dead_letter_queue(max_size: int = 1000) -> Dict:
    """
    Create a dead letter queue for permanently failed requests.
    
    Args:
        max_size: Maximum number of failed requests to store
        
    Returns:
        Dead letter queue configuration dictionary
    """
    return {
        'failed_requests': [],
        'max_size': max_size,
        'total_failed': 0,
        'lock': threading.Lock()
    }


def add_to_dead_letter_queue(
    dead_letter_queue: Dict,
    request_data: Any,
    error: Exception,
    attempts: int
) -> None:
    """
    Add permanently failed request to dead letter queue.
    
    Args:
        dead_letter_queue: Dead letter queue configuration
        request_data: Original request data that failed
        error: Final exception that caused permanent failure
        attempts: Number of retry attempts made
    """
    with dead_letter_queue['lock']:
        dead_letter_queue['total_failed'] += 1
        
        failed_request = {
            'request_data': request_data,
            'error': str(error),
            'error_type': type(error).__name__,
            'attempts': attempts,
            'timestamp': time.time()
        }
        
        # Add to queue, removing oldest if at capacity
        if len(dead_letter_queue['failed_requests']) >= dead_letter_queue['max_size']:
            dead_letter_queue['failed_requests'].pop(0)
        
        dead_letter_queue['failed_requests'].append(failed_request)


def get_dead_letter_statistics(dead_letter_queue: Dict) -> Dict:
    """
    Get statistics from dead letter queue.
    
    Args:
        dead_letter_queue: Dead letter queue configuration
        
    Returns:
        Dictionary containing dead letter queue statistics
    """
    with dead_letter_queue['lock']:
        return {
            'current_failed_count': len(dead_letter_queue['failed_requests']),
            'total_failed_count': dead_letter_queue['total_failed'],
            'max_size': dead_letter_queue['max_size'],
            'is_full': len(dead_letter_queue['failed_requests']) >= dead_letter_queue['max_size']
        }