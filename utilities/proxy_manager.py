#!/usr/bin/env python3

"""
Proxy management utility for AblitaFuzzer.

Handles selective proxy routing - localhost traffic bypasses proxy while 
target traffic uses proxy when specified.
"""

import requests
from urllib.parse import urlparse
from typing import Optional, Dict, Any


def is_localhost_url(url: str) -> bool:
    """
    Check if URL points to localhost/127.0.0.1.
    
    Args:
        url: URL to check
        
    Returns:
        True if URL is localhost, False otherwise
    """
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return False
            
        # Check for localhost variants
        localhost_hosts = {
            'localhost',
            '127.0.0.1',
            '::1',
            '0.0.0.0'
        }
        
        return hostname.lower() in localhost_hosts
    except Exception:
        return False


def get_proxy_config(url: str, proxy_setting: Optional[str] = None) -> Dict[str, Optional[str]]:
    """
    Get proxy configuration for a given URL.
    
    Args:
        url: Target URL for the request
        proxy_setting: Proxy setting (e.g., "127.0.0.1:8080")
        
    Returns:
        Dictionary with proxy configuration for requests library
    """
    # If no proxy specified or URL is localhost, don't use proxy
    if not proxy_setting or is_localhost_url(url):
        return {}
    
    # Format proxy URL for requests library
    proxy_url = f"http://{proxy_setting}"
    return {
        'http': proxy_url,
        'https': proxy_url
    }


def make_request(method: str, url: str, proxy_setting: Optional[str] = None, **kwargs) -> requests.Response:
    """
    Make HTTP request with selective proxy routing.
    
    Args:
        method: HTTP method ('GET', 'POST', etc.)
        url: Target URL
        proxy_setting: Proxy setting (e.g., "127.0.0.1:8080")
        **kwargs: Additional arguments for requests
        
    Returns:
        Response object from requests library
    """
    # Get proxy configuration based on URL
    proxies = get_proxy_config(url, proxy_setting)
    
    # Add proxy configuration to kwargs
    if proxies:
        kwargs['proxies'] = proxies
        # Disable SSL verification for proxy testing (Burp Suite, etc.)
        kwargs.setdefault('verify', False)
    
    # Make the request using appropriate method
    if method.upper() == 'POST':
        return requests.post(url, **kwargs)
    elif method.upper() == 'GET':
        return requests.get(url, **kwargs)
    elif method.upper() == 'PUT':
        return requests.put(url, **kwargs)
    elif method.upper() == 'DELETE':
        return requests.delete(url, **kwargs)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")


def post(url: str, proxy_setting: Optional[str] = None, **kwargs) -> requests.Response:
    """
    Make POST request with selective proxy routing.
    
    Args:
        url: Target URL
        proxy_setting: Proxy setting (e.g., "127.0.0.1:8080")
        **kwargs: Additional arguments for requests.post
        
    Returns:
        Response object
    """
    return make_request('POST', url, proxy_setting, **kwargs)


def get(url: str, proxy_setting: Optional[str] = None, **kwargs) -> requests.Response:
    """
    Make GET request with selective proxy routing.
    
    Args:
        url: Target URL
        proxy_setting: Proxy setting (e.g., "127.0.0.1:8080")
        **kwargs: Additional arguments for requests.get
        
    Returns:
        Response object
    """
    return make_request('GET', url, proxy_setting, **kwargs)