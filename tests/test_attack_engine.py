#!/usr/bin/env python3

"""
Comprehensive tests for AblitaFuzzer Attack Engine.

Tests concurrent execution, rate limiting, retry logic, session management,
progress monitoring, and attack coordination functionality.
"""

import unittest
import tempfile
import shutil
import time
import json
import threading
from unittest.mock import patch, Mock, MagicMock
from pathlib import Path

from attack_engine.concurrent_executor import (
    execute_concurrent_attacks, execute_single_attack, create_rate_limiter,
    wait_for_rate_limit, calculate_optimal_workers, get_executor_statistics
)
from attack_engine.rate_limiter import (
    create_token_bucket_limiter, enforce_rate_limit, adjust_rate_limit_dynamically,
    detect_rate_limit_from_response, get_rate_limiter_statistics
)
from attack_engine.retry_handler import (
    with_retry, should_retry_error, execute_with_retry, create_circuit_breaker,
    execute_with_circuit_breaker, get_circuit_breaker_statistics
)
from attack_engine.session_manager import (
    create_attack_session, load_attack_session, save_session_state,
    update_session_progress, get_resumable_prompts, list_sessions,
    get_session_statistics, delete_session
)
from attack_engine.progress_monitor import (
    create_progress_monitor, update_progress, format_duration,
    finalize_progress, get_progress_statistics
)
from attack_engine.attack_coordinator import (
    coordinate_attack_campaign, create_attack_function, normalize_attack_response,
    handle_attack_error, validate_attack_configuration
)


class TestConcurrentExecutor(unittest.TestCase):
    """Test concurrent attack execution functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_prompts = ["prompt1", "prompt2", "prompt3", "prompt4", "prompt5"]
    
    def test_create_rate_limiter(self):
        """Test rate limiter creation."""
        rate_limiter = create_rate_limiter(10.0)
        
        self.assertEqual(rate_limiter['rate'], 10.0)
        self.assertEqual(rate_limiter['tokens'], 10.0)
        self.assertEqual(rate_limiter['max_tokens'], 10.0)
        self.assertIsInstance(rate_limiter['lock'], threading.Lock)
    
    def test_wait_for_rate_limit(self):
        """Test rate limiting wait functionality."""
        rate_limiter = create_rate_limiter(2.0)  # 2 requests per second
        
        start_time = time.time()
        
        # First request should be immediate
        wait_for_rate_limit(rate_limiter)
        first_wait = time.time() - start_time
        self.assertLess(first_wait, 0.1)
        
        # Second request should be immediate
        wait_for_rate_limit(rate_limiter)
        second_wait = time.time() - start_time
        self.assertLess(second_wait, 0.1)
        
        # Third request should wait ~0.5 seconds
        wait_for_rate_limit(rate_limiter)
        third_wait = time.time() - start_time
        self.assertGreater(third_wait, 0.4)
    
    def test_execute_single_attack_success(self):
        """Test successful single attack execution."""
        def mock_attack_func(prompt):
            return {"response": f"Response to {prompt}"}
        
        result = execute_single_attack("test prompt", mock_attack_func)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['response']['response'], "Response to test prompt")
        self.assertIn('execution_time', result)
        self.assertIn('timestamp', result)
        self.assertIn('thread_id', result)
    
    def test_execute_single_attack_failure(self):
        """Test failed single attack execution."""
        def mock_attack_func(prompt):
            raise ValueError("Test error")
        
        result = execute_single_attack("test prompt", mock_attack_func)
        
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], "Test error")
        self.assertEqual(result['error_type'], "ValueError")
        self.assertIn('execution_time', result)
    
    def test_calculate_optimal_workers(self):
        """Test optimal worker calculation."""
        # Small batch, low response time
        workers = calculate_optimal_workers(5, 1.0, 10.0, 20)
        self.assertEqual(workers, 5)  # Limited by batch size
        
        # Large batch, high rate limit
        workers = calculate_optimal_workers(100, 2.0, 50.0, 20)
        self.assertEqual(workers, 20)  # Limited by system max
        
        # Rate-limited scenario
        workers = calculate_optimal_workers(100, 5.0, 2.0, 20)
        self.assertEqual(workers, 11)  # 2.0 * 5.0 + 1 = 11
    
    def test_get_executor_statistics(self):
        """Test execution statistics calculation."""
        results = [
            {'success': True, 'execution_time': 1.0, 'timestamp': 100},
            {'success': False, 'execution_time': 0.5, 'timestamp': 101, 'error_type': 'TimeoutError'},
            {'success': True, 'execution_time': 2.0, 'timestamp': 102}
        ]
        
        stats = get_executor_statistics(results)
        
        self.assertEqual(stats['total_attacks'], 3)
        self.assertEqual(stats['successful_attacks'], 2)
        self.assertEqual(stats['failed_attacks'], 1)
        self.assertAlmostEqual(stats['success_rate'], 2/3)
        self.assertAlmostEqual(stats['average_response_time'], 1.17, places=1)
        self.assertEqual(stats['min_response_time'], 0.5)
        self.assertEqual(stats['max_response_time'], 2.0)
        self.assertIn('error_breakdown', stats)
        self.assertEqual(stats['error_breakdown']['TimeoutError'], 1)


class TestRateLimiter(unittest.TestCase):
    """Test rate limiting functionality."""
    
    def test_create_token_bucket_limiter(self):
        """Test token bucket limiter creation."""
        limiter = create_token_bucket_limiter(5.0, 10.0)
        
        self.assertEqual(limiter['rate'], 5.0)
        self.assertEqual(limiter['burst_capacity'], 10.0)
        self.assertEqual(limiter['tokens'], 10.0)
        self.assertIsInstance(limiter['lock'], threading.Lock)
    
    def test_enforce_rate_limit_allow(self):
        """Test rate limit enforcement - allowing requests."""
        limiter = create_token_bucket_limiter(10.0)
        
        # Should allow first request
        self.assertTrue(enforce_rate_limit(limiter))
        self.assertEqual(limiter['total_requests'], 1)
        self.assertEqual(limiter['denied_requests'], 0)
    
    def test_enforce_rate_limit_deny(self):
        """Test rate limit enforcement - denying requests."""
        limiter = create_token_bucket_limiter(1.0, 1.0)  # Very restrictive
        
        # First request should be allowed
        self.assertTrue(enforce_rate_limit(limiter))
        
        # Second immediate request should be denied
        self.assertFalse(enforce_rate_limit(limiter))
        self.assertEqual(limiter['total_requests'], 2)
        self.assertEqual(limiter['denied_requests'], 1)
    
    def test_adjust_rate_limit_dynamically_429(self):
        """Test dynamic rate limit adjustment for 429 responses."""
        limiter = create_token_bucket_limiter(10.0)
        original_rate = limiter['rate']
        
        # Simulate 429 response
        adjust_rate_limit_dynamically(limiter, 429)
        
        # Rate should be reduced
        self.assertLess(limiter['rate'], original_rate)
        self.assertEqual(limiter['rate'], original_rate * 0.5)
    
    def test_adjust_rate_limit_dynamically_success(self):
        """Test dynamic rate limit adjustment for successful responses."""
        limiter = create_token_bucket_limiter(5.0)
        limiter['original_rate'] = 10.0
        
        # Simulate successful responses to trigger rate increase
        for i in range(10):
            adjust_rate_limit_dynamically(limiter, 200)
        
        # Rate should increase after 10 successes
        self.assertGreater(limiter['rate'], 5.0)
    
    def test_detect_rate_limit_from_response(self):
        """Test rate limit detection from API responses."""
        # Test 429 response
        result = detect_rate_limit_from_response(429)
        self.assertTrue(result['is_rate_limited'])
        self.assertEqual(result['recommended_action'], 'backoff')
        
        # Test 429 with Retry-After header
        headers = {'retry-after': '60'}
        result = detect_rate_limit_from_response(429, headers)
        self.assertTrue(result['is_rate_limited'])
        self.assertEqual(result['retry_after'], 60.0)
        
        # Test successful response
        result = detect_rate_limit_from_response(200)
        self.assertFalse(result['is_rate_limited'])
        self.assertEqual(result['recommended_action'], 'continue')
    
    def test_get_rate_limiter_statistics(self):
        """Test rate limiter statistics."""
        limiter = create_token_bucket_limiter(10.0, 15.0)
        
        # Make some requests
        enforce_rate_limit(limiter)
        enforce_rate_limit(limiter)
        
        stats = get_rate_limiter_statistics(limiter)
        
        self.assertEqual(stats['current_rate'], 10.0)
        self.assertEqual(stats['burst_capacity'], 15.0)
        self.assertEqual(stats['total_requests'], 2)
        self.assertEqual(stats['denied_requests'], 0)
        self.assertEqual(stats['approval_rate'], 1.0)


class TestRetryHandler(unittest.TestCase):
    """Test retry logic and circuit breaker functionality."""
    
    def test_should_retry_error_retryable(self):
        """Test retry decision for retryable errors."""
        # Network errors should be retryable
        timeout_error = TimeoutError("Request timeout")
        self.assertTrue(should_retry_error(timeout_error))
        
        connection_error = ConnectionError("Connection failed")
        self.assertTrue(should_retry_error(connection_error))
    
    def test_should_retry_error_non_retryable(self):
        """Test retry decision for non-retryable errors."""
        # Value errors should not be retryable
        value_error = ValueError("Invalid input")
        self.assertFalse(should_retry_error(value_error))
    
    def test_should_retry_error_http_status(self):
        """Test retry decision based on HTTP status codes."""
        # Mock HTTP error with retryable status code
        http_error = Exception("HTTP Error")
        response_mock = Mock()
        response_mock.status_code = 429
        http_error.response = response_mock
        
        self.assertTrue(should_retry_error(http_error))
        
        # Mock HTTP error with non-retryable status code
        response_mock.status_code = 400
        self.assertFalse(should_retry_error(http_error))
    
    def test_with_retry_decorator_success(self):
        """Test retry decorator with successful function."""
        call_count = 0
        
        @with_retry(max_attempts=3)
        def test_function():
            nonlocal call_count
            call_count += 1
            return "success"
        
        result = test_function()
        self.assertEqual(result, "success")
        self.assertEqual(call_count, 1)
    
    def test_with_retry_decorator_eventual_success(self):
        """Test retry decorator with eventual success."""
        call_count = 0
        
        @with_retry(max_attempts=3, base_delay=0.01)
        def test_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Temporary failure")
            return "success"
        
        result = test_function()
        self.assertEqual(result, "success")
        self.assertEqual(call_count, 3)
    
    def test_with_retry_decorator_permanent_failure(self):
        """Test retry decorator with permanent failure."""
        call_count = 0
        
        @with_retry(max_attempts=3, base_delay=0.01)
        def test_function():
            nonlocal call_count
            call_count += 1
            raise ConnectionError("Permanent failure")
        
        with self.assertRaises(ConnectionError):
            test_function()
        
        self.assertEqual(call_count, 3)
    
    def test_create_circuit_breaker(self):
        """Test circuit breaker creation."""
        cb = create_circuit_breaker(failure_threshold=5, recovery_timeout=60.0)
        
        self.assertEqual(cb['state'], 'closed')
        self.assertEqual(cb['failure_threshold'], 5)
        self.assertEqual(cb['recovery_timeout'], 60.0)
        self.assertEqual(cb['failure_count'], 0)
    
    def test_circuit_breaker_open_close_cycle(self):
        """Test circuit breaker open/close cycle."""
        cb = create_circuit_breaker(failure_threshold=2, recovery_timeout=0.1)
        
        def failing_function():
            raise ConnectionError("Test failure")
        
        def success_function():
            return "success"
        
        # Trigger failures to open circuit
        with self.assertRaises(ConnectionError):
            execute_with_circuit_breaker(failing_function, cb)
        
        with self.assertRaises(ConnectionError):
            execute_with_circuit_breaker(failing_function, cb)
        
        # Circuit should be open now
        self.assertEqual(cb['state'], 'open')
        
        # Should fail fast
        with self.assertRaises(Exception) as context:
            execute_with_circuit_breaker(failing_function, cb)
        
        self.assertIn("Circuit breaker is open", str(context.exception))
        
        # Wait for recovery timeout
        time.sleep(0.15)
        
        # Should transition to half-open and allow success
        result = execute_with_circuit_breaker(success_function, cb)
        self.assertEqual(result, "success")
        
        # Another success should close the circuit
        result = execute_with_circuit_breaker(success_function, cb)
        self.assertEqual(result, "success")
        self.assertEqual(cb['state'], 'closed')
    
    def test_get_circuit_breaker_statistics(self):
        """Test circuit breaker statistics."""
        cb = create_circuit_breaker()
        
        # Execute some operations
        def success_func():
            return "ok"
        
        execute_with_circuit_breaker(success_func, cb)
        execute_with_circuit_breaker(success_func, cb)
        
        stats = get_circuit_breaker_statistics(cb)
        
        self.assertEqual(stats['state'], 'closed')
        self.assertEqual(stats['total_calls'], 2)
        self.assertEqual(stats['total_successes'], 2)
        self.assertEqual(stats['total_failures'], 0)
        self.assertEqual(stats['success_rate'], 1.0)


class TestSessionManager(unittest.TestCase):
    """Test session management functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.target_config = {
            'name': 'test_target',
            'type': 'openai',
            'base_url': 'http://test.example.com/v1/chat/completions',
            'auth': {'type': 'api_key', 'format': 'Bearer test-key'},
            'model': 'test-model'
        }
        self.test_prompts = ["prompt1", "prompt2", "prompt3"]
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_create_attack_session(self):
        """Test attack session creation."""
        session_id = create_attack_session(
            session_name="test_session",
            target_config=self.target_config,
            prompts=self.test_prompts,
            session_dir=self.test_dir
        )
        
        self.assertIsInstance(session_id, str)
        self.assertEqual(len(session_id), 36)  # UUID length
        
        # Verify session file was created
        session_file = Path(self.test_dir) / f"{session_id}.json"
        self.assertTrue(session_file.exists())
    
    def test_load_attack_session(self):
        """Test attack session loading."""
        session_id = create_attack_session(
            session_name="test_session",
            target_config=self.target_config,
            prompts=self.test_prompts,
            session_dir=self.test_dir
        )
        
        loaded_session = load_attack_session(session_id, self.test_dir)
        
        self.assertEqual(loaded_session['session_id'], session_id)
        self.assertEqual(loaded_session['session_name'], "test_session")
        self.assertEqual(loaded_session['prompts'], self.test_prompts)
        self.assertEqual(loaded_session['status'], 'created')
    
    def test_load_nonexistent_session(self):
        """Test loading nonexistent session."""
        with self.assertRaises(FileNotFoundError):
            load_attack_session("nonexistent-id", self.test_dir)
    
    def test_update_session_progress(self):
        """Test session progress updates."""
        session_id = create_attack_session(
            session_name="test_session",
            target_config=self.target_config,
            prompts=self.test_prompts,
            session_dir=self.test_dir
        )
        
        # Update with successful result
        success_result = {
            'success': True,
            'response': {'text': 'Test response'},
            'execution_time': 1.5
        }
        
        update_session_progress(session_id, "prompt1", success_result, self.test_dir)
        
        # Verify session was updated
        updated_session = load_attack_session(session_id, self.test_dir)
        
        self.assertEqual(updated_session['progress']['completed'], 1)
        self.assertEqual(updated_session['progress']['failed'], 0)
        self.assertEqual(updated_session['progress']['remaining'], 2)
        self.assertIn("prompt1", updated_session['completed_prompts'])
        self.assertEqual(len(updated_session['results']), 1)
    
    def test_get_resumable_prompts(self):
        """Test getting resumable prompts."""
        session_id = create_attack_session(
            session_name="test_session",
            target_config=self.target_config,
            prompts=self.test_prompts,
            session_dir=self.test_dir
        )
        
        # Complete one prompt
        success_result = {'success': True, 'response': {'text': 'Test'}}
        update_session_progress(session_id, "prompt1", success_result, self.test_dir)
        
        # Get resumable prompts
        resumable = get_resumable_prompts(session_id, self.test_dir)
        
        self.assertEqual(len(resumable), 2)
        self.assertIn("prompt2", resumable)
        self.assertIn("prompt3", resumable)
        self.assertNotIn("prompt1", resumable)
    
    def test_list_sessions(self):
        """Test session listing."""
        # Create test sessions
        session1_id = create_attack_session(
            session_name="session1",
            target_config=self.target_config,
            prompts=["p1"],
            session_dir=self.test_dir
        )
        
        session2_id = create_attack_session(
            session_name="session2", 
            target_config=self.target_config,
            prompts=["p2"],
            session_dir=self.test_dir
        )
        
        sessions = list_sessions(self.test_dir)
        
        self.assertEqual(len(sessions), 2)
        session_ids = [s['session_id'] for s in sessions]
        self.assertIn(session1_id, session_ids)
        self.assertIn(session2_id, session_ids)
    
    def test_delete_session(self):
        """Test session deletion."""
        session_id = create_attack_session(
            session_name="test_session",
            target_config=self.target_config,
            prompts=self.test_prompts,
            session_dir=self.test_dir
        )
        
        # Verify session exists
        self.assertTrue(delete_session(session_id, self.test_dir))
        
        # Verify session file is gone
        session_file = Path(self.test_dir) / f"{session_id}.json"
        self.assertFalse(session_file.exists())
        
        # Verify delete of nonexistent session returns False
        self.assertFalse(delete_session(session_id, self.test_dir))
    
    def test_get_session_statistics(self):
        """Test session statistics."""
        session_id = create_attack_session(
            session_name="test_session",
            target_config=self.target_config,
            prompts=self.test_prompts,
            session_dir=self.test_dir
        )
        
        # Add some results
        success_result = {
            'success': True,
            'response': {'text': 'Success'},
            'execution_time': 1.0
        }
        failure_result = {
            'success': False,
            'error': 'Test error',
            'error_type': 'TestError',
            'execution_time': 0.5
        }
        
        update_session_progress(session_id, "prompt1", success_result, self.test_dir)
        update_session_progress(session_id, "prompt2", failure_result, self.test_dir)
        
        stats = get_session_statistics(session_id, self.test_dir)
        
        self.assertIn('session_info', stats)
        self.assertIn('progress', stats)
        self.assertEqual(stats['progress']['completed'], 1)
        self.assertEqual(stats['progress']['failed'], 1)
        
        # Should have performance stats
        self.assertIn('performance', stats)
        self.assertEqual(stats['performance']['min_response_time'], 0.5)
        self.assertEqual(stats['performance']['max_response_time'], 1.0)
        
        # Should have error analysis
        self.assertIn('error_analysis', stats)
        self.assertEqual(stats['error_analysis']['total_errors'], 1)
        self.assertIn('TestError', stats['error_analysis']['error_types'])


class TestProgressMonitor(unittest.TestCase):
    """Test progress monitoring functionality."""
    
    def test_create_progress_monitor(self):
        """Test progress monitor creation."""
        monitor = create_progress_monitor(100, update_interval=0.5)
        
        self.assertEqual(monitor['total'], 100)
        self.assertEqual(monitor['completed'], 0)
        self.assertEqual(monitor['failed'], 0)
        self.assertEqual(monitor['update_interval'], 0.5)
        self.assertIsInstance(monitor['lock'], threading.Lock)
    
    def test_update_progress(self):
        """Test progress updates."""
        monitor = create_progress_monitor(10)
        
        # Update with success
        update_progress(monitor, success=True, response_time=1.5)
        self.assertEqual(monitor['completed'], 1)
        self.assertEqual(monitor['failed'], 0)
        self.assertIn(1.5, monitor['response_times'])
        
        # Update with failure
        update_progress(monitor, success=False)
        self.assertEqual(monitor['completed'], 1)
        self.assertEqual(monitor['failed'], 1)
    
    def test_format_duration(self):
        """Test duration formatting."""
        self.assertEqual(format_duration(30), "30s")
        self.assertEqual(format_duration(90), "1m 30s")
        self.assertEqual(format_duration(3661), "1h 1m")
        self.assertEqual(format_duration(0), "0s")
        self.assertEqual(format_duration(-1), "unknown")
    
    def test_finalize_progress(self):
        """Test progress finalization."""
        monitor = create_progress_monitor(5)
        
        # Simulate some progress
        for i in range(3):
            update_progress(monitor, success=True)
        
        for i in range(2):
            update_progress(monitor, success=False)
        
        stats = finalize_progress(monitor, "Test completed")
        
        self.assertEqual(stats['total_items'], 5)
        self.assertEqual(stats['completed'], 3)
        self.assertEqual(stats['failed'], 2)
        self.assertEqual(stats['success_rate'], 0.6)
        self.assertIn('total_time', stats)
        self.assertIn('average_rate', stats)
    
    def test_get_progress_statistics(self):
        """Test progress statistics."""
        monitor = create_progress_monitor(20)
        
        # Make some progress
        for i in range(5):
            update_progress(monitor, success=True)
        
        for i in range(2):
            update_progress(monitor, success=False)
        
        stats = get_progress_statistics(monitor)
        
        self.assertEqual(stats['total'], 20)
        self.assertEqual(stats['completed'], 5)
        self.assertEqual(stats['failed'], 2)
        self.assertEqual(stats['processed'], 7)
        self.assertEqual(stats['remaining'], 13)
        self.assertEqual(stats['progress_percentage'], 35.0)
        self.assertAlmostEqual(stats['success_rate'], 5/7)


class TestAttackCoordinator(unittest.TestCase):
    """Test attack coordination functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.target_config = {
            'name': 'test_target',
            'type': 'openai',
            'base_url': 'http://test.example.com/v1/chat/completions',
            'auth': {'type': 'api_key', 'format': 'Bearer test-key', 'header': 'Authorization'},
            'model': 'test-model',
            'model_params': {'temperature': 0.7, 'max_tokens': 1000}
        }
    
    def test_normalize_attack_response_openai(self):
        """Test response normalization for OpenAI format."""
        raw_response = {
            'choices': [
                {
                    'message': {
                        'content': 'Test response content'
                    }
                }
            ],
            'usage': {'prompt_tokens': 10, 'completion_tokens': 20},
            'model': 'gpt-4'
        }
        
        normalized = normalize_attack_response(raw_response, 200, 'openai')
        
        self.assertTrue(normalized['success'])
        self.assertEqual(normalized['status_code'], 200)
        self.assertEqual(normalized['response_text'], 'Test response content')
        self.assertIn('usage', normalized)
        self.assertEqual(normalized['model'], 'gpt-4')
    
    def test_normalize_attack_response_anthropic(self):
        """Test response normalization for Anthropic format."""
        raw_response = {
            'content': [
                {'text': 'Test response from Claude'}
            ],
            'model': 'claude-3-opus-20240229'
        }
        
        normalized = normalize_attack_response(raw_response, 200, 'anthropic')
        
        self.assertTrue(normalized['success'])
        self.assertEqual(normalized['response_text'], 'Test response from Claude')
        self.assertEqual(normalized['model'], 'claude-3-opus-20240229')
    
    def test_normalize_attack_response_error(self):
        """Test response normalization for error cases."""
        normalized = normalize_attack_response({}, 500, 'openai')
        
        self.assertFalse(normalized['success'])
        self.assertEqual(normalized['status_code'], 500)
        self.assertEqual(normalized['response_text'], '')
    
    def test_handle_attack_error(self):
        """Test attack error handling."""
        error = ConnectionError("Connection timeout")
        prompt = "test prompt"
        
        error_response = handle_attack_error(error, prompt, self.target_config)
        
        self.assertFalse(error_response['success'])
        self.assertEqual(error_response['error'], "Connection timeout")
        self.assertEqual(error_response['error_type'], "ConnectionError")
        self.assertEqual(error_response['prompt'], prompt)
        self.assertIn('timestamp', error_response)
    
    def test_handle_attack_error_http(self):
        """Test HTTP error handling."""
        http_error = Exception("HTTP Error")
        response_mock = Mock()
        response_mock.status_code = 429
        response_mock.json.return_value = {"error": "Rate limited"}
        http_error.response = response_mock
        
        error_response = handle_attack_error(http_error, "test", self.target_config)
        
        self.assertEqual(error_response['status_code'], 429)
        self.assertEqual(error_response['error_category'], 'rate_limited')
        self.assertEqual(error_response['error_details'], {"error": "Rate limited"})
    
    def test_validate_attack_configuration_valid(self):
        """Test configuration validation with valid config."""
        result = validate_attack_configuration(self.target_config)
        
        self.assertTrue(result['valid'])
        self.assertEqual(len(result['errors']), 0)
        self.assertGreater(len(result['recommendations']), 0)
    
    def test_validate_attack_configuration_invalid(self):
        """Test configuration validation with invalid config."""
        invalid_config = {'name': 'test'}  # Missing required fields
        
        result = validate_attack_configuration(invalid_config)
        
        self.assertFalse(result['valid'])
        self.assertGreater(len(result['errors']), 0)
        
        # Check for specific missing fields
        error_messages = ' '.join(result['errors'])
        self.assertIn('base_url', error_messages)
        self.assertIn('type', error_messages)
        self.assertIn('auth', error_messages)
    
    @patch('attack_engine.attack_coordinator.get_config')
    @patch('attack_engine.attack_coordinator.get_target_configuration')
    def test_coordinate_attack_campaign_mock(self, mock_get_target, mock_get_config):
        """Test attack campaign coordination with mocks."""
        # Mock configuration
        mock_get_config.return_value = {'targets': {'test_target': self.target_config}}
        mock_get_target.return_value = self.target_config
        
        # Mock attack execution to avoid actual HTTP calls
        with patch('attack_engine.attack_coordinator.execute_concurrent_attacks') as mock_execute:
            mock_execute.return_value = [
                {'success': True, 'prompt': 'test1', 'response': {'text': 'response1'}},
                {'success': True, 'prompt': 'test2', 'response': {'text': 'response2'}}
            ]
            
            with patch('attack_engine.attack_coordinator.create_attack_session') as mock_create_session:
                mock_create_session.return_value = 'test-session-id'
                
                with patch('attack_engine.attack_coordinator.update_session_progress'):
                    result = coordinate_attack_campaign(
                        prompts=['test1', 'test2'],
                        target_name='test_target',
                        session_name='test_campaign',
                        max_workers=2,
                        rate_limit=5.0
                    )
                    
                    self.assertTrue(result['success'])
                    self.assertEqual(result['session_id'], 'test-session-id')
                    self.assertEqual(len(result['results']), 2)
                    self.assertIn('statistics', result)


if __name__ == '__main__':
    unittest.main()