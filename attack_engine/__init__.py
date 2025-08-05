#!/usr/bin/env python3

"""
AblitaFuzzer Attack Engine - Concurrent execution system for LLM fuzzing attacks.

This module provides concurrent attack execution, rate limiting, retry logic,
session persistence, and progress monitoring for professional-scale LLM penetration testing.
"""

from .concurrent_executor import (
    execute_concurrent_attacks,
    execute_single_attack,
    create_rate_limiter,
    wait_for_rate_limit
)

from .rate_limiter import (
    create_token_bucket_limiter,
    enforce_rate_limit,
    adjust_rate_limit_dynamically,
    detect_rate_limit_from_response
)

from .retry_handler import (
    with_retry,
    should_retry_error,
    execute_with_circuit_breaker
)

from .session_manager import (
    create_attack_session,
    load_attack_session,
    save_session_state,
    update_session_progress,
    get_resumable_prompts,
    list_sessions
)

from .progress_monitor import (
    create_progress_monitor,
    update_progress,
    display_progress,
    finalize_progress
)

from .attack_coordinator import (
    coordinate_attack_campaign,
    create_attack_function,
    normalize_attack_response,
    handle_attack_error,
    execute_multi_target_campaign
)

__version__ = "1.0.0"
__all__ = [
    # Concurrent execution
    "execute_concurrent_attacks",
    "execute_single_attack",
    "create_rate_limiter",
    "wait_for_rate_limit",
    
    # Rate limiting
    "create_token_bucket_limiter",
    "enforce_rate_limit",
    "adjust_rate_limit_dynamically",
    "detect_rate_limit_from_response",
    
    # Retry handling
    "with_retry",
    "should_retry_error",
    "execute_with_circuit_breaker",
    
    # Session management
    "create_attack_session",
    "load_attack_session",
    "save_session_state",
    "update_session_progress",
    "get_resumable_prompts",
    "list_sessions",
    
    # Progress monitoring
    "create_progress_monitor",
    "update_progress",
    "display_progress",
    "finalize_progress",
    
    # Attack coordination
    "coordinate_attack_campaign",
    "create_attack_function",
    "normalize_attack_response",
    "handle_attack_error",
    "execute_multi_target_campaign"
]