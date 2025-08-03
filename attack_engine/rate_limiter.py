#!/usr/bin/env python3

"""
Rate limiting implementation functions for AblitaFuzzer.

Provides intelligent rate limiting with token bucket algorithm, dynamic adjustment,
and HTTP 429 detection to prevent API blocking.
"""

import time
import threading
from typing import Dict, Optional, Any
from collections import defaultdict


def create_token_bucket_limiter(
    requests_per_second: float,
    burst_capacity: Optional[float] = None
) -> Dict:
    """
    Create a token bucket rate limiter with configurable burst capacity.
    
    Args:
        requests_per_second: Maximum sustained requests per second
        burst_capacity: Maximum burst requests (defaults to requests_per_second)
        
    Returns:
        Token bucket rate limiter configuration dictionary
    """
    if burst_capacity is None:
        burst_capacity = requests_per_second
    
    return {
        'rate': requests_per_second,
        'burst_capacity': burst_capacity,
        'tokens': burst_capacity,
        'last_refill': time.time(),
        'lock': threading.Lock(),
        'total_requests': 0,
        'denied_requests': 0,
        'created_at': time.time()
    }


def enforce_rate_limit(rate_limiter: Dict) -> bool:
    """
    Check if request should be allowed based on current rate limit.
    
    Args:
        rate_limiter: Token bucket rate limiter configuration
        
    Returns:
        True if request is allowed, False if rate limited
    """
    with rate_limiter['lock']:
        current_time = time.time()
        rate_limiter['total_requests'] += 1
        
        # Refill tokens based on time passed
        time_passed = current_time - rate_limiter['last_refill']
        tokens_to_add = time_passed * rate_limiter['rate']
        
        rate_limiter['tokens'] = min(
            rate_limiter['burst_capacity'],
            rate_limiter['tokens'] + tokens_to_add
        )
        rate_limiter['last_refill'] = current_time
        
        # Check if tokens available
        if rate_limiter['tokens'] >= 1.0:
            rate_limiter['tokens'] -= 1.0
            return True
        else:
            rate_limiter['denied_requests'] += 1
            return False


def wait_for_rate_limit_availability(
    rate_limiter: Dict,
    max_wait_time: float = 60.0
) -> bool:
    """
    Wait until rate limiter allows next request or timeout.
    
    Args:
        rate_limiter: Token bucket rate limiter configuration
        max_wait_time: Maximum time to wait in seconds
        
    Returns:
        True if request can proceed, False if timeout exceeded
    """
    start_time = time.time()
    
    while time.time() - start_time < max_wait_time:
        if enforce_rate_limit(rate_limiter):
            return True
        
        # Calculate sleep time until next token available
        with rate_limiter['lock']:
            sleep_time = min(1.0 / rate_limiter['rate'], 1.0)
        
        time.sleep(sleep_time)
    
    return False


def adjust_rate_limit_dynamically(
    rate_limiter: Dict,
    response_status: int,
    response_headers: Optional[Dict[str, str]] = None
) -> None:
    """
    Dynamically adjust rate limit based on API response.
    
    Args:
        rate_limiter: Token bucket rate limiter configuration
        response_status: HTTP response status code
        response_headers: Optional HTTP response headers
    """
    with rate_limiter['lock']:
        current_rate = rate_limiter['rate']
        
        # Detect rate limiting from response
        if response_status == 429:  # Too Many Requests
            # Reduce rate by 50%
            new_rate = current_rate * 0.5
            rate_limiter['rate'] = max(0.1, new_rate)  # Minimum 0.1 req/sec
            
            # Check for Retry-After header
            if response_headers and 'retry-after' in response_headers:
                try:
                    retry_after = float(response_headers['retry-after'])
                    # Set tokens to 0 and adjust last_refill to honor retry-after
                    rate_limiter['tokens'] = 0
                    rate_limiter['last_refill'] = time.time() + retry_after
                except ValueError:
                    pass
        
        elif response_status in [500, 502, 503, 504]:  # Server errors
            # Slight rate reduction for server errors
            new_rate = current_rate * 0.8
            rate_limiter['rate'] = max(0.1, new_rate)
        
        elif response_status == 200:  # Success
            # Gradually increase rate if consistently successful
            if not hasattr(rate_limiter, 'success_count'):
                rate_limiter['success_count'] = 0
            
            rate_limiter['success_count'] += 1
            
            # After 10 successful requests, try increasing rate slightly
            if rate_limiter['success_count'] >= 10:
                new_rate = current_rate * 1.1
                # Don't exceed original rate by more than 50%
                original_rate = getattr(rate_limiter, 'original_rate', current_rate)
                rate_limiter['rate'] = min(new_rate, original_rate * 1.5)
                rate_limiter['success_count'] = 0


def detect_rate_limit_from_response(
    response_status: int,
    response_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None
) -> Dict:
    """
    Detect rate limiting information from API response.
    
    Args:
        response_status: HTTP response status code
        response_headers: Optional HTTP response headers
        response_body: Optional HTTP response body
        
    Returns:
        Dictionary with rate limiting detection results
    """
    result = {
        'is_rate_limited': False,
        'retry_after': None,
        'rate_limit_info': {},
        'recommended_action': 'continue'
    }
    
    # Check status code
    if response_status == 429:
        result['is_rate_limited'] = True
        result['recommended_action'] = 'backoff'
        
        if response_headers:
            # Extract Retry-After header
            retry_after = response_headers.get('retry-after') or response_headers.get('Retry-After')
            if retry_after:
                try:
                    result['retry_after'] = float(retry_after)
                except ValueError:
                    pass
            
            # Extract rate limit headers (various formats)
            rate_limit_headers = [
                'x-ratelimit-limit', 'x-rate-limit-limit', 'ratelimit-limit',
                'x-ratelimit-remaining', 'x-rate-limit-remaining', 'ratelimit-remaining',
                'x-ratelimit-reset', 'x-rate-limit-reset', 'ratelimit-reset'
            ]
            
            for header in rate_limit_headers:
                value = response_headers.get(header) or response_headers.get(header.title())
                if value:
                    result['rate_limit_info'][header] = value
    
    elif response_status in [500, 502, 503, 504]:
        result['recommended_action'] = 'retry_with_backoff'
    
    # Check response body for rate limiting messages
    if response_body:
        rate_limit_keywords = [
            'rate limit', 'too many requests', 'quota exceeded',
            'throttled', 'rate exceeded', 'limit exceeded'
        ]
        
        body_lower = response_body.lower()
        for keyword in rate_limit_keywords:
            if keyword in body_lower:
                result['is_rate_limited'] = True
                result['recommended_action'] = 'backoff'
                break
    
    return result


def create_multi_endpoint_limiter(
    default_rate: float = 10.0,
    endpoint_configs: Optional[Dict[str, float]] = None
) -> Dict:
    """
    Create rate limiter that handles multiple API endpoints with different limits.
    
    Args:
        default_rate: Default rate limit for unlisted endpoints
        endpoint_configs: Dictionary mapping endpoint patterns to rate limits
        
    Returns:
        Multi-endpoint rate limiter configuration
    """
    if endpoint_configs is None:
        endpoint_configs = {}
    
    return {
        'default_rate': default_rate,
        'endpoint_configs': endpoint_configs,
        'limiters': defaultdict(lambda: create_token_bucket_limiter(default_rate)),
        'lock': threading.Lock()
    }


def get_rate_limiter_for_endpoint(
    multi_limiter: Dict,
    endpoint: str
) -> Dict:
    """
    Get appropriate rate limiter for specific endpoint.
    
    Args:
        multi_limiter: Multi-endpoint rate limiter configuration
        endpoint: API endpoint URL or pattern
        
    Returns:
        Token bucket rate limiter for the endpoint
    """
    with multi_limiter['lock']:
        # Check if endpoint has specific configuration
        rate = multi_limiter['default_rate']
        for pattern, pattern_rate in multi_limiter['endpoint_configs'].items():
            if pattern in endpoint:
                rate = pattern_rate
                break
        
        # Get or create limiter for this endpoint
        if endpoint not in multi_limiter['limiters']:
            multi_limiter['limiters'][endpoint] = create_token_bucket_limiter(rate)
        
        return multi_limiter['limiters'][endpoint]


def get_rate_limiter_statistics(rate_limiter: Dict) -> Dict:
    """
    Get statistics from rate limiter for monitoring and debugging.
    
    Args:
        rate_limiter: Token bucket rate limiter configuration
        
    Returns:
        Dictionary containing rate limiter statistics
    """
    with rate_limiter['lock']:
        current_time = time.time()
        uptime = current_time - rate_limiter['created_at']
        
        stats = {
            'current_rate': rate_limiter['rate'],
            'burst_capacity': rate_limiter['burst_capacity'],
            'current_tokens': rate_limiter['tokens'],
            'total_requests': rate_limiter['total_requests'],
            'denied_requests': rate_limiter['denied_requests'],
            'approval_rate': 1.0 - (rate_limiter['denied_requests'] / max(1, rate_limiter['total_requests'])),
            'uptime_seconds': uptime,
            'average_request_rate': rate_limiter['total_requests'] / max(1, uptime)
        }
        
        # Add original rate if available
        if hasattr(rate_limiter, 'original_rate'):
            stats['original_rate'] = rate_limiter['original_rate']
            stats['rate_adjustment_factor'] = rate_limiter['rate'] / rate_limiter['original_rate']
        
        return stats


def reset_rate_limiter(rate_limiter: Dict) -> None:
    """
    Reset rate limiter to initial state.
    
    Args:
        rate_limiter: Token bucket rate limiter configuration
    """
    with rate_limiter['lock']:
        rate_limiter['tokens'] = rate_limiter['burst_capacity']
        rate_limiter['last_refill'] = time.time()
        rate_limiter['total_requests'] = 0
        rate_limiter['denied_requests'] = 0
        
        # Reset to original rate if available
        if hasattr(rate_limiter, 'original_rate'):
            rate_limiter['rate'] = rate_limiter['original_rate']
        
        # Reset success counter
        if hasattr(rate_limiter, 'success_count'):
            rate_limiter['success_count'] = 0