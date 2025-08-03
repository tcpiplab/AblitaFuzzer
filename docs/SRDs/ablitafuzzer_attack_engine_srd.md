# Software Requirements Document: AblitaFuzzer Attack Engine Overhaul

## Document Information
- **Project**: AblitaFuzzer
- **Component**: Attack Engine with Concurrent Execution and API Abstraction
- **Version**: 1.0
- **Date**: 2025-01-02

## Executive Summary

This SRD defines the requirements for overhauling AblitaFuzzer's attack execution engine to support concurrent execution, multiple API providers, and professional-grade reliability features. The new engine will transform the tool from single-threaded localhost testing to concurrent production API testing with proper rate limiting, retry logic, and session management.

## Current State Analysis

### Current Attack Engine Limitations
- **Single-threaded execution**: Attacks sent sequentially, extremely slow for production use
- **Hardcoded API format**: Only supports Ollama-style JSON payloads
- **No retry logic**: Network failures cause immediate test termination
- **No rate limiting**: Will get blocked by production APIs with rate limits
- **No session persistence**: Cannot pause/resume long-running attacks
- **Poor error handling**: Minimal feedback on API failures
- **No progress monitoring**: No visibility into attack progress or completion time

### Current Attack Architecture
```python
# during_attack/run_fuzz_attack.py - Current problematic approach
for prompt in prompts:
    response = session.post(TARGET_MODEL_API_URL, headers=headers, data=json.dumps(payload))
    if response.status_code == 200:
        results.append({"prompt": prompt, "response": response.json()})
    time.sleep(0.5)  # Fixed delay, no rate limiting awareness
```

### Performance Impact
- **50 prompts**: ~25 minutes (0.5s delay + 30s average API response time)
- **200 prompts**: ~100 minutes for basic pentest scenarios
- **Production APIs**: Often have 1-10 requests/second limits, requiring intelligent rate management

## Requirements

### Functional Requirements

#### FR-1: Concurrent Attack Execution
- **Requirement**: Execute multiple attack requests simultaneously with configurable concurrency
- **Implementation**: New module `attack_engine/concurrent_executor.py`
- **Details**:
  - Thread-pool based execution with configurable worker threads
  - Configurable concurrency limits per API provider
  - Queue-based attack distribution to worker threads
  - Thread-safe result collection and error handling
  - Graceful shutdown on user interruption or critical errors
  - Memory-efficient handling of large attack campaigns

#### FR-2: Intelligent Rate Limiting
- **Requirement**: Respect API provider rate limits and avoid service blocking
- **Implementation**: New module `attack_engine/rate_limiter.py`
- **Details**:
  - Per-provider rate limiting configuration
  - Token bucket algorithm for smooth rate distribution
  - Dynamic rate adjustment based on API responses
  - Rate limit detection from HTTP 429 responses
  - Backoff strategies for rate-limited requests
  - Multiple rate limit windows (per-second, per-minute, per-hour)

#### FR-3: Robust Retry Logic
- **Requirement**: Handle transient failures with intelligent retry strategies
- **Implementation**: New module `attack_engine/retry_handler.py`
- **Details**:
  - Exponential backoff with jitter for retries
  - Configurable retry limits per error type
  - Different retry strategies for different failure modes
  - Circuit breaker pattern for persistent failures
  - Dead letter queue for permanently failed requests
  - Retry attempt logging and metrics

#### FR-4: Unified Attack Interface
- **Requirement**: Abstract API differences so attack logic works with any provider
- **Implementation**: New module `attack_engine/attack_coordinator.py`
- **Details**:
  - Provider-agnostic attack request formatting
  - Unified response parsing and normalization
  - Error code standardization across providers
  - Attack result format standardization
  - Provider capability detection and adaptation
  - Fallback handling for unsupported features

#### FR-5: Session Management and Persistence
- **Requirement**: Enable pause/resume functionality for long-running attacks
- **Implementation**: New module `attack_engine/session_manager.py`
- **Details**:
  - Attack session state persistence to disk
  - Resume interrupted attacks from last successful point
  - Session metadata tracking (start time, progress, errors)
  - Attack campaign checkpointing
  - Session cleanup and archival
  - Multiple concurrent session support

#### FR-6: Real-Time Progress Monitoring
- **Requirement**: Provide detailed feedback during attack execution
- **Implementation**: New module `attack_engine/progress_monitor.py`
- **Details**:
  - Real-time progress indicators with ETA calculations
  - Attack success/failure rate monitoring
  - Rate limiting status display
  - Current throughput and latency metrics
  - Error rate tracking and alerting
  - Configurable progress update intervals

### Non-Functional Requirements

#### NFR-1: Performance Requirements
- Concurrent execution must provide 5-10x speed improvement over current implementation
- Memory usage must remain under 500MB for attacks with 1000+ prompts
- CPU usage must not exceed 80% during concurrent execution
- Attack throughput must adapt to API provider capabilities

#### NFR-2: Reliability Requirements
- No attack data loss due to network failures or interruptions
- Graceful degradation when API providers become unavailable
- Automatic recovery from transient network issues
- Session persistence must survive application crashes

#### NFR-3: Scalability Requirements
- Support for attack campaigns with 10,000+ prompts
- Handle multiple concurrent target APIs simultaneously
- Scale worker threads based on system resources and API capabilities
- Efficient memory usage for large result sets

#### NFR-4: Usability Requirements
- Clear progress indicators for long-running attacks
- Informative error messages for API failures
- Ability to pause/resume attacks interactively
- Attack statistics and performance summaries

## Implementation Specifications

### Concurrent Execution Architecture

```python
# attack_engine/concurrent_executor.py
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue
from typing import List, Dict, Callable, Optional
import threading
import time


def execute_concurrent_attacks(
    prompts: List[str],
    attack_func: Callable[[str], Dict],
    max_workers: int = 5,
    rate_limit: float = 10.0
) -> List[Dict]:
    """
    Execute attack prompts concurrently with rate limiting.
    
    Args:
        prompts: List of attack prompts to execute
        attack_func: Function to execute individual attacks
        max_workers: Maximum number of concurrent threads
        rate_limit: Maximum requests per second
        
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
            except Exception as e:
                error_result = create_error_result(prompt, e)
                results.append(error_result)
    
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
            'timestamp': start_time
        }
    except Exception as e:
        execution_time = time.time() - start_time
        return {
            'success': False,
            'error': str(e),
            'execution_time': execution_time,
            'timestamp': start_time
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
            rate_limiter['rate'],
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
```

### Retry Logic Implementation

```python
# attack_engine/retry_handler.py
import time
import random
from typing import Dict, Callable, Optional, Any
from functools import wraps


def with_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: bool = True
) -> Callable:
    """
    Decorator to add retry logic with exponential backoff to functions.
    
    Args:
        max_attempts: Maximum number of retry attempts
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        exponential_base: Base for exponential backoff calculation
        jitter: Whether to add random jitter to delays
        
    Returns:
        Decorated function with retry logic
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    
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


def should_retry_error(error: Exception) -> bool:
    """
    Determine if an error should trigger a retry attempt.
    
    Args:
        error: Exception that occurred during request
        
    Returns:
        True if error is retryable, False otherwise
    """
    # Network-related errors are generally retryable
    retryable_errors = [
        'ConnectionError',
        'TimeoutError',
        'HTTPError'  # Will check status code separately
    ]
    
    error_name = type(error).__name__
    if error_name in retryable_errors:
        return True
    
    # Check HTTP status codes for retryable conditions
    if hasattr(error, 'response') and hasattr(error.response, 'status_code'):
        retryable_status_codes = [429, 500, 502, 503, 504]
        return error.response.status_code in retryable_status_codes
    
    return False


def execute_with_circuit_breaker(
    func: Callable,
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    circuit_state: Optional[Dict] = None
) -> Any:
    """
    Execute function with circuit breaker pattern for persistent failures.
    
    Args:
        func: Function to execute
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Time to wait before attempting recovery
        circuit_state: Shared circuit breaker state dictionary
        
    Returns:
        Function result or raises exception if circuit is open
    """
    if circuit_state is None:
        circuit_state = {
            'failures': 0,
            'last_failure_time': 0,
            'state': 'closed'  # closed, open, half-open
        }
    
    current_time = time.time()
    
    # Check if circuit should transition from open to half-open
    if (circuit_state['state'] == 'open' and 
        current_time - circuit_state['last_failure_time'] > recovery_timeout):
        circuit_state['state'] = 'half-open'
    
    # Fail fast if circuit is open
    if circuit_state['state'] == 'open':
        raise Exception("Circuit breaker is open - too many recent failures")
    
    try:
        result = func()
        
        # Reset failure count on success
        if circuit_state['state'] == 'half-open':
            circuit_state['state'] = 'closed'
            circuit_state['failures'] = 0
        
        return result
    
    except Exception as e:
        circuit_state['failures'] += 1
        circuit_state['last_failure_time'] = current_time
        
        # Open circuit if failure threshold exceeded
        if circuit_state['failures'] >= failure_threshold:
            circuit_state['state'] = 'open'
        
        raise e
```

### Session Management System

```python
# attack_engine/session_manager.py
import json
import os
import time
import uuid
from typing import Dict, List, Optional, Any
from pathlib import Path


def create_attack_session(
    session_name: str,
    target_config: Dict,
    prompts: List[str],
    session_dir: str = "~/.ablitafuzzer/sessions"
) -> str:
    """
    Create a new attack session with persistent state.
    
    Args:
        session_name: Human-readable name for the session
        target_config: Target API configuration
        prompts: List of attack prompts to execute
        session_dir: Directory to store session files
        
    Returns:
        Session ID for tracking and resuming the session
    """
    session_id = str(uuid.uuid4())
    session_path = Path(session_dir).expanduser() / f"{session_id}.json"
    session_path.parent.mkdir(parents=True, exist_ok=True)
    
    session_data = {
        'session_id': session_id,
        'session_name': session_name,
        'created_at': time.time(),
        'target_config': target_config,
        'prompts': prompts,
        'completed_prompts': [],
        'failed_prompts': [],
        'results': [],
        'status': 'created',
        'progress': {
            'total': len(prompts),
            'completed': 0,
            'failed': 0,
            'remaining': len(prompts)
        }
    }
    
    save_session_state(session_data, str(session_path))
    return session_id


def load_attack_session(session_id: str, session_dir: str = "~/.ablitafuzzer/sessions") -> Dict:
    """
    Load an existing attack session from persistent storage.
    
    Args:
        session_id: Session ID to load
        session_dir: Directory where session files are stored
        
    Returns:
        Session data dictionary
    """
    session_path = Path(session_dir).expanduser() / f"{session_id}.json"
    
    if not session_path.exists():
        raise FileNotFoundError(f"Session {session_id} not found")
    
    with open(session_path, 'r') as f:
        return json.load(f)


def save_session_state(session_data: Dict, session_path: str) -> None:
    """
    Save session state to persistent storage.
    
    Args:
        session_data: Complete session data dictionary
        session_path: Full path to session file
    """
    session_data['updated_at'] = time.time()
    
    with open(session_path, 'w') as f:
        json.dump(session_data, f, indent=2)


def update_session_progress(
    session_id: str,
    completed_prompt: str,
    result: Dict,
    session_dir: str = "~/.ablitafuzzer/sessions"
) -> None:
    """
    Update session progress with completed attack result.
    
    Args:
        session_id: Session ID to update
        completed_prompt: Prompt that was completed
        result: Attack result data
        session_dir: Directory where session files are stored
    """
    session_data = load_attack_session(session_id, session_dir)
    session_path = Path(session_dir).expanduser() / f"{session_id}.json"
    
    # Update completed/failed tracking
    if result.get('success', False):
        session_data['completed_prompts'].append(completed_prompt)
        session_data['progress']['completed'] += 1
    else:
        session_data['failed_prompts'].append(completed_prompt)
        session_data['progress']['failed'] += 1
    
    session_data['progress']['remaining'] = (
        session_data['progress']['total'] - 
        session_data['progress']['completed'] - 
        session_data['progress']['failed']
    )
    
    # Store result
    result['prompt'] = completed_prompt
    session_data['results'].append(result)
    
    # Update status
    if session_data['progress']['remaining'] == 0:
        session_data['status'] = 'completed'
    else:
        session_data['status'] = 'in_progress'
    
    save_session_state(session_data, str(session_path))


def get_resumable_prompts(session_id: str, session_dir: str = "~/.ablitafuzzer/sessions") -> List[str]:
    """
    Get list of prompts that still need to be executed in a session.
    
    Args:
        session_id: Session ID to check
        session_dir: Directory where session files are stored
        
    Returns:
        List of prompts that haven't been completed or failed
    """
    session_data = load_attack_session(session_id, session_dir)
    
    completed_set = set(session_data['completed_prompts'])
    failed_set = set(session_data['failed_prompts'])
    all_prompts = session_data['prompts']
    
    return [p for p in all_prompts if p not in completed_set and p not in failed_set]


def list_sessions(session_dir: str = "~/.ablitafuzzer/sessions") -> List[Dict]:
    """
    List all available attack sessions with summary information.
    
    Args:
        session_dir: Directory where session files are stored
        
    Returns:
        List of session summary dictionaries
    """
    session_path = Path(session_dir).expanduser()
    if not session_path.exists():
        return []
    
    sessions = []
    for session_file in session_path.glob("*.json"):
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
            
            sessions.append({
                'session_id': session_data['session_id'],
                'session_name': session_data['session_name'],
                'status': session_data['status'],
                'created_at': session_data['created_at'],
                'progress': session_data['progress']
            })
        except Exception:
            # Skip corrupted session files
            continue
    
    return sorted(sessions, key=lambda x: x['created_at'], reverse=True)
```

### Progress Monitoring System

```python
# attack_engine/progress_monitor.py
import time
import sys
from typing import Dict, Optional
from threading import Lock


def create_progress_monitor(total_items: int, update_interval: float = 1.0) -> Dict:
    """
    Create a progress monitor for tracking attack execution.
    
    Args:
        total_items: Total number of items to process
        update_interval: Seconds between progress updates
        
    Returns:
        Progress monitor state dictionary
    """
    return {
        'total': total_items,
        'completed': 0,
        'failed': 0,
        'start_time': time.time(),
        'last_update': time.time(),
        'update_interval': update_interval,
        'lock': Lock()
    }


def update_progress(monitor: Dict, success: bool = True) -> None:
    """
    Update progress monitor with completed item.
    
    Args:
        monitor: Progress monitor state dictionary
        success: Whether the item completed successfully
    """
    with monitor['lock']:
        if success:
            monitor['completed'] += 1
        else:
            monitor['failed'] += 1
        
        current_time = time.time()
        if current_time - monitor['last_update'] >= monitor['update_interval']:
            display_progress(monitor)
            monitor['last_update'] = current_time


def display_progress(monitor: Dict) -> None:
    """
    Display current progress information to the user.
    
    Args:
        monitor: Progress monitor state dictionary
    """
    total = monitor['total']
    completed = monitor['completed']
    failed = monitor['failed']
    processed = completed + failed
    
    if processed == 0:
        return
    
    # Calculate progress percentage
    progress_pct = (processed / total) * 100
    
    # Calculate timing information
    elapsed = time.time() - monitor['start_time']
    rate = processed / elapsed if elapsed > 0 else 0
    
    # Estimate time remaining
    remaining = total - processed
    eta_seconds = remaining / rate if rate > 0 else 0
    eta_str = format_duration(eta_seconds)
    
    # Create progress bar
    bar_width = 40
    filled_width = int(bar_width * progress_pct / 100)
    bar = '█' * filled_width + '░' * (bar_width - filled_width)
    
    # Format output
    status_line = (
        f"\r[{bar}] {progress_pct:5.1f}% "
        f"({processed}/{total}) "
        f"✓{completed} ✗{failed} "
        f"{rate:.1f}/s "
        f"ETA: {eta_str}"
    )
    
    # Print without newline and flush
    sys.stdout.write(status_line)
    sys.stdout.flush()


def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human-readable string.
    
    Args:
        seconds: Duration in seconds
        
    Returns:
        Formatted duration string (e.g., "2m 30s")
    """
    if seconds < 60:
        return f"{int(seconds)}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"


def finalize_progress(monitor: Dict) -> Dict:
    """
    Complete progress monitoring and return final statistics.
    
    Args:
        monitor: Progress monitor state dictionary
        
    Returns:
        Final execution statistics
    """
    total_time = time.time() - monitor['start_time']
    total_processed = monitor['completed'] + monitor['failed']
    
    # Clear progress line and show final results
    sys.stdout.write('\n')
    
    stats = {
        'total_items': monitor['total'],
        'completed': monitor['completed'],
        'failed': monitor['failed'],
        'success_rate': monitor['completed'] / total_processed if total_processed > 0 else 0,
        'total_time': total_time,
        'average_rate': total_processed / total_time if total_time > 0 else 0
    }
    
    return stats
```

## File Modifications Required

### New Files to Create
1. `attack_engine/concurrent_executor.py` - Concurrent attack execution functions
2. `attack_engine/rate_limiter.py` - Rate limiting implementation functions
3. `attack_engine/retry_handler.py` - Retry logic and circuit breaker functions
4. `attack_engine/attack_coordinator.py` - Unified attack interface functions
5. `attack_engine/session_manager.py` - Session persistence functions
6. `attack_engine/progress_monitor.py` - Progress tracking functions
7. `attack_engine/__init__.py` - Module initialization
8. `tests/test_attack_engine.py` - Comprehensive attack engine tests

### Existing Files to Modify
1. `during_attack/run_fuzz_attack.py` - Replace with new concurrent attack engine
2. `configs/config.py` - Add concurrency and rate limiting configuration
3. `ablitafuzzer.py` - Add session management CLI commands
4. `utilities/http_utilities.py` - Integrate with new retry and rate limiting
5. `README.md` - Update documentation for new attack capabilities

### Configuration Updates Required
```python
# configs/config.py additions
ATTACK_ENGINE_CONFIG = {
    'max_workers': 5,
    'default_rate_limit': 10.0,  # requests per second
    'retry_attempts': 3,
    'retry_base_delay': 1.0,
    'circuit_breaker_threshold': 5,
    'progress_update_interval': 1.0
}
```

## CLI Integration

### New CLI Commands
```bash
# Session management
ablitafuzzer session list                    # List all attack sessions
ablitafuzzer session resume <session_id>    # Resume interrupted session
ablitafuzzer session status <session_id>    # Show session progress
ablitafuzzer session clean                   # Clean up old sessions

# Attack execution with new options
ablitafuzzer fuzz --workers 10              # Set concurrent worker threads
ablitafuzzer fuzz --rate-limit 5            # Set requests per second limit
ablitafuzzer fuzz --session-name "client_test"  # Named session for resuming
ablitafuzzer fuzz --resume <session_id>     # Resume specific session
```

## Testing Requirements

### Unit Tests
- Concurrent executor with various worker counts and rate limits
- Rate limiter token bucket algorithm accuracy
- Retry handler exponential backoff calculations
- Session persistence and recovery functionality
- Progress monitor accuracy and timing

### Integration Tests
- End-to-end concurrent attack execution against real APIs
- Rate limiting compliance with different API providers
- Session resume functionality after interruption
- Error handling and circuit breaker behavior
- Performance benchmarks vs. current single-threaded approach

### Performance Tests
- Concurrent execution speed improvement measurement
- Memory usage under various attack sizes
- Rate limiter accuracy under high load
- Progress monitor overhead assessment

## Migration Strategy

### Phase 1: Core Engine Development
1. Implement concurrent executor with basic thread pool
2. Add rate limiting with token bucket algorithm
3. Create retry handler with exponential backoff
4. Build session persistence functionality

### Phase 2: Integration and Testing
1. Integrate new engine with existing attack flow
2. Add progress monitoring and user feedback
3. Implement CLI session management commands
4. Comprehensive testing and performance validation

### Phase 3: Advanced Features
1. Add circuit breaker pattern for persistent failures
2. Implement dynamic rate adjustment based on API responses
3. Add attack result streaming for large campaigns
4. Create attack execution metrics and reporting

## Success Criteria

- 5-10x speed improvement over current single-threaded execution
- Support for professional-scale attack campaigns (1000+ prompts)
- Reliable session persistence and resume functionality
- Intelligent rate limiting prevents API blocking
- Comprehensive error handling and retry logic
- Real-time progress monitoring for long-running attacks

## Dependencies

### External Dependencies
- `concurrent.futures` - Thread pool execution (built-in)
- `threading` - Thread synchronization (built-in)
- `queue` - Thread-safe queues (built-in)
- `time` - Timing and delays (built-in)

### Internal Dependencies
- New configuration system from previous SRD
- Existing HTTP utilities and error handling
- Download manager for attack payloads
- Current CLI framework

## Risk Mitigation

### Risk: Concurrent execution overwhelms target APIs
- **Mitigation**: Intelligent rate limiting and configurable concurrency limits

### Risk: Network failures corrupt attack sessions
- **Mitigation**: Atomic session updates and integrity checking

### Risk: Memory usage grows uncontrollably with large attacks
- **Mitigation**: Result streaming and configurable memory limits

### Risk: Complex concurrency introduces bugs
- **Mitigation**: Comprehensive unit testing and gradual rollout