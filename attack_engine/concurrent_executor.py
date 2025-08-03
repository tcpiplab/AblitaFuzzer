#!/usr/bin/env python3

"""
Concurrent attack execution functions for AblitaFuzzer.

Provides thread-pool based concurrent execution with configurable worker threads,
rate limiting, and thread-safe result collection.
"""

import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Callable, Optional, Any
from queue import Queue


def execute_concurrent_attacks(
    prompts: List[str],
    attack_func: Callable[[str], Dict],
    max_workers: int = 5,
    rate_limit: float = 10.0,
    progress_callback: Optional[Callable[[bool], None]] = None
) -> List[Dict]:
    """
    Execute attack prompts concurrently with rate limiting.
    
    Args:
        prompts: List of attack prompts to execute
        attack_func: Function to execute individual attacks
        max_workers: Maximum number of concurrent threads
        rate_limit: Maximum requests per second
        progress_callback: Optional callback function for progress updates
        
    Returns:
        List of attack results with responses and metadata
    """
    results = []
    rate_limiter = create_rate_limiter(rate_limit)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all attacks to thread pool
        future_to_prompt = {}
        for prompt in prompts:
            # Wait for rate limiter before submitting
            wait_for_rate_limit(rate_limiter)
            future = executor.submit(execute_single_attack, prompt, attack_func)
            future_to_prompt[future] = prompt
        
        # Collect results as they complete
        for future in as_completed(future_to_prompt):
            prompt = future_to_prompt[future]
            try:
                result = future.result()
                result['prompt'] = prompt
                results.append(result)
                
                # Update progress if callback provided
                if progress_callback:
                    progress_callback(result.get('success', False))
                    
            except Exception as e:
                error_result = create_error_result(prompt, e)
                results.append(error_result)
                
                # Update progress for failed attempt
                if progress_callback:
                    progress_callback(False)
    
    return results


def execute_single_attack(prompt: str, attack_func: Callable[[str], Dict]) -> Dict:
    """
    Execute a single attack with error handling and timing.
    
    Args:
        prompt: Attack prompt to execute
        attack_func: Function to execute the attack
        
    Returns:
        Attack result with response data and metadata
    """
    start_time = time.time()
    
    try:
        response = attack_func(prompt)
        execution_time = time.time() - start_time
        
        return {
            'success': True,
            'response': response,
            'execution_time': execution_time,
            'timestamp': start_time,
            'thread_id': threading.get_ident()
        }
    except Exception as e:
        execution_time = time.time() - start_time
        return {
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'execution_time': execution_time,
            'timestamp': start_time,
            'thread_id': threading.get_ident()
        }


def create_rate_limiter(requests_per_second: float) -> Dict:
    """
    Create a token bucket rate limiter.
    
    Args:
        requests_per_second: Maximum requests per second allowed
        
    Returns:
        Rate limiter configuration dictionary
    """
    return {
        'rate': requests_per_second,
        'tokens': requests_per_second,
        'max_tokens': requests_per_second,
        'last_update': time.time(),
        'lock': threading.Lock()
    }


def wait_for_rate_limit(rate_limiter: Dict) -> None:
    """
    Block until rate limiter allows next request.
    
    Args:
        rate_limiter: Rate limiter configuration dictionary
    """
    with rate_limiter['lock']:
        current_time = time.time()
        time_passed = current_time - rate_limiter['last_update']
        
        # Add tokens based on time passed
        rate_limiter['tokens'] = min(
            rate_limiter['max_tokens'],
            rate_limiter['tokens'] + time_passed * rate_limiter['rate']
        )
        rate_limiter['last_update'] = current_time
        
        # Wait if no tokens available
        if rate_limiter['tokens'] < 1:
            sleep_time = (1 - rate_limiter['tokens']) / rate_limiter['rate']
            time.sleep(sleep_time)
            rate_limiter['tokens'] = 0
        else:
            rate_limiter['tokens'] -= 1


def create_error_result(prompt: str, error: Exception) -> Dict:
    """
    Create standardized error result dictionary.
    
    Args:
        prompt: The prompt that caused the error
        error: The exception that occurred
        
    Returns:
        Standardized error result dictionary
    """
    return {
        'prompt': prompt,
        'success': False,
        'error': str(error),
        'error_type': type(error).__name__,
        'execution_time': 0.0,
        'timestamp': time.time(),
        'thread_id': threading.get_ident()
    }


def execute_attacks_with_queue(
    prompts: List[str],
    attack_func: Callable[[str], Dict],
    max_workers: int = 5,
    rate_limit: float = 10.0,
    result_queue: Optional[Queue] = None
) -> Queue:
    """
    Execute attacks with results streamed to a queue for memory efficiency.
    
    Args:
        prompts: List of attack prompts to execute
        attack_func: Function to execute individual attacks
        max_workers: Maximum number of concurrent threads
        rate_limit: Maximum requests per second
        result_queue: Optional queue to use for results
        
    Returns:
        Queue containing attack results as they complete
    """
    if result_queue is None:
        result_queue = Queue()
    
    rate_limiter = create_rate_limiter(rate_limit)
    
    def worker():
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_prompt = {}
            
            # Submit all attacks
            for prompt in prompts:
                wait_for_rate_limit(rate_limiter)
                future = executor.submit(execute_single_attack, prompt, attack_func)
                future_to_prompt[future] = prompt
            
            # Process results as they complete
            for future in as_completed(future_to_prompt):
                prompt = future_to_prompt[future]
                try:
                    result = future.result()
                    result['prompt'] = prompt
                    result_queue.put(result)
                except Exception as e:
                    error_result = create_error_result(prompt, e)
                    result_queue.put(error_result)
            
            # Signal completion
            result_queue.put(None)
    
    # Start worker thread
    worker_thread = threading.Thread(target=worker)
    worker_thread.daemon = True
    worker_thread.start()
    
    return result_queue


def calculate_optimal_workers(
    total_prompts: int,
    average_response_time: float,
    rate_limit: float,
    max_system_workers: int = 20
) -> int:
    """
    Calculate optimal number of worker threads based on constraints.
    
    Args:
        total_prompts: Total number of prompts to process
        average_response_time: Expected response time per request in seconds
        rate_limit: Maximum requests per second allowed
        max_system_workers: Maximum workers the system can handle
        
    Returns:
        Optimal number of worker threads
    """
    # Base calculation: workers needed to maintain rate limit
    rate_optimal_workers = int(rate_limit * average_response_time) + 1
    
    # Don't exceed system limits
    system_optimal = min(rate_optimal_workers, max_system_workers)
    
    # For small batches, don't use more workers than prompts
    batch_optimal = min(system_optimal, total_prompts)
    
    # Ensure at least 1 worker
    return max(1, batch_optimal)


def get_executor_statistics(results: List[Dict]) -> Dict:
    """
    Calculate execution statistics from attack results.
    
    Args:
        results: List of attack result dictionaries
        
    Returns:
        Dictionary containing execution statistics
    """
    if not results:
        return {}
    
    successful_results = [r for r in results if r.get('success', False)]
    failed_results = [r for r in results if not r.get('success', False)]
    
    execution_times = [r.get('execution_time', 0) for r in results if 'execution_time' in r]
    
    # Calculate timing statistics
    total_time = 0
    if results:
        start_time = min(r.get('timestamp', 0) for r in results)
        end_time = max(r.get('timestamp', 0) + r.get('execution_time', 0) for r in results)
        total_time = end_time - start_time
    
    stats = {
        'total_attacks': len(results),
        'successful_attacks': len(successful_results),
        'failed_attacks': len(failed_results),
        'success_rate': len(successful_results) / len(results) if results else 0.0,
        'total_execution_time': total_time,
        'average_response_time': sum(execution_times) / len(execution_times) if execution_times else 0.0,
        'min_response_time': min(execution_times) if execution_times else 0.0,
        'max_response_time': max(execution_times) if execution_times else 0.0,
        'throughput': len(results) / total_time if total_time > 0 else 0.0
    }
    
    # Error analysis
    if failed_results:
        error_types = {}
        for result in failed_results:
            error_type = result.get('error_type', 'Unknown')
            error_types[error_type] = error_types.get(error_type, 0) + 1
        stats['error_breakdown'] = error_types
    
    return stats