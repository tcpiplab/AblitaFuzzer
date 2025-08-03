#!/usr/bin/env python3

"""
Session persistence functions for AblitaFuzzer.

Provides session management with persistent state, resume functionality,
and progress tracking for long-running attack campaigns.
"""

import json
import os
import time
import uuid
from typing import Dict, List, Optional, Any
from pathlib import Path
import threading


def get_default_session_dir() -> str:
    """
    Get the default directory for storing attack sessions.
    
    Returns:
        Path to default session directory
    """
    return str(Path.home() / ".ablitafuzzer" / "sessions")


def create_attack_session(
    session_name: str,
    target_config: Dict,
    prompts: List[str],
    session_dir: Optional[str] = None,
    metadata: Optional[Dict] = None
) -> str:
    """
    Create a new attack session with persistent state.
    
    Args:
        session_name: Human-readable name for the session
        target_config: Target API configuration
        prompts: List of attack prompts to execute
        session_dir: Directory to store session files
        metadata: Optional additional metadata for the session
        
    Returns:
        Session ID for tracking and resuming the session
    """
    if session_dir is None:
        session_dir = get_default_session_dir()
    
    session_id = str(uuid.uuid4())
    session_path = Path(session_dir) / f"{session_id}.json"
    session_path.parent.mkdir(parents=True, exist_ok=True)
    
    if metadata is None:
        metadata = {}
    
    session_data = {
        'session_id': session_id,
        'session_name': session_name,
        'created_at': time.time(),
        'updated_at': time.time(),
        'status': 'created',
        'target_config': target_config,
        'prompts': prompts,
        'completed_prompts': [],
        'failed_prompts': [],
        'results': [],
        'metadata': metadata,
        'progress': {
            'total': len(prompts),
            'completed': 0,
            'failed': 0,
            'remaining': len(prompts),
            'success_rate': 0.0
        },
        'timing': {
            'start_time': None,
            'end_time': None,
            'total_duration': 0.0,
            'average_response_time': 0.0
        },
        'statistics': {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'retry_attempts': 0,
            'rate_limited_requests': 0
        }
    }
    
    save_session_state(session_data, str(session_path))
    return session_id


def load_attack_session(
    session_id: str,
    session_dir: Optional[str] = None
) -> Dict:
    """
    Load an existing attack session from persistent storage.
    
    Args:
        session_id: Session ID to load
        session_dir: Directory where session files are stored
        
    Returns:
        Session data dictionary
        
    Raises:
        FileNotFoundError: If session file doesn't exist
        ValueError: If session data is corrupted
    """
    if session_dir is None:
        session_dir = get_default_session_dir()
    
    session_path = Path(session_dir) / f"{session_id}.json"
    
    if not session_path.exists():
        raise FileNotFoundError(f"Session {session_id} not found at {session_path}")
    
    try:
        with open(session_path, 'r') as f:
            session_data = json.load(f)
        
        # Validate required fields
        required_fields = ['session_id', 'session_name', 'status', 'prompts', 'progress']
        for field in required_fields:
            if field not in session_data:
                raise ValueError(f"Session data missing required field: {field}")
        
        return session_data
    
    except json.JSONDecodeError as e:
        raise ValueError(f"Session data corrupted: {e}")


def save_session_state(
    session_data: Dict,
    session_path: str
) -> None:
    """
    Save session state to persistent storage with atomic write.
    
    Args:
        session_data: Complete session data dictionary
        session_path: Full path to session file
    """
    session_data['updated_at'] = time.time()
    
    # Use temporary file for atomic write
    temp_path = session_path + '.tmp'
    
    try:
        with open(temp_path, 'w') as f:
            json.dump(session_data, f, indent=2, sort_keys=True)
        
        # Atomic rename
        os.rename(temp_path, session_path)
    
    except Exception:
        # Clean up temporary file if write failed
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def update_session_progress(
    session_id: str,
    completed_prompt: str,
    result: Dict,
    session_dir: Optional[str] = None
) -> None:
    """
    Update session progress with completed attack result.
    
    Args:
        session_id: Session ID to update
        completed_prompt: Prompt that was completed
        result: Attack result data
        session_dir: Directory where session files are stored
    """
    if session_dir is None:
        session_dir = get_default_session_dir()
    
    session_data = load_attack_session(session_id, session_dir)
    session_path = Path(session_dir) / f"{session_id}.json"
    
    # Update completed/failed tracking
    if result.get('success', False):
        if completed_prompt not in session_data['completed_prompts']:
            session_data['completed_prompts'].append(completed_prompt)
            session_data['progress']['completed'] += 1
            session_data['statistics']['successful_requests'] += 1
    else:
        if completed_prompt not in session_data['failed_prompts']:
            session_data['failed_prompts'].append(completed_prompt)
            session_data['progress']['failed'] += 1
            session_data['statistics']['failed_requests'] += 1
    
    # Update remaining count
    session_data['progress']['remaining'] = (
        session_data['progress']['total'] - 
        session_data['progress']['completed'] - 
        session_data['progress']['failed']
    )
    
    # Calculate success rate
    total_processed = session_data['progress']['completed'] + session_data['progress']['failed']
    if total_processed > 0:
        session_data['progress']['success_rate'] = (
            session_data['progress']['completed'] / total_processed
        )
    
    # Store result with timestamp
    result_with_metadata = result.copy()
    result_with_metadata['prompt'] = completed_prompt
    result_with_metadata['recorded_at'] = time.time()
    session_data['results'].append(result_with_metadata)
    
    # Update statistics
    session_data['statistics']['total_requests'] += 1
    if 'retry_attempts' in result:
        session_data['statistics']['retry_attempts'] += result['retry_attempts']
    if result.get('rate_limited', False):
        session_data['statistics']['rate_limited_requests'] += 1
    
    # Update timing information
    if session_data['timing']['start_time'] is None:
        session_data['timing']['start_time'] = time.time()
    
    # Calculate average response time
    response_times = [r.get('execution_time', 0) for r in session_data['results'] 
                     if 'execution_time' in r]
    if response_times:
        session_data['timing']['average_response_time'] = sum(response_times) / len(response_times)
    
    # Update status
    if session_data['progress']['remaining'] == 0:
        session_data['status'] = 'completed'
        session_data['timing']['end_time'] = time.time()
        if session_data['timing']['start_time']:
            session_data['timing']['total_duration'] = (
                session_data['timing']['end_time'] - session_data['timing']['start_time']
            )
    else:
        session_data['status'] = 'in_progress'
    
    save_session_state(session_data, str(session_path))


def get_resumable_prompts(
    session_id: str,
    session_dir: Optional[str] = None
) -> List[str]:
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


def list_sessions(
    session_dir: Optional[str] = None,
    status_filter: Optional[str] = None
) -> List[Dict]:
    """
    List all available attack sessions with summary information.
    
    Args:
        session_dir: Directory where session files are stored
        status_filter: Optional filter by session status
        
    Returns:
        List of session summary dictionaries
    """
    if session_dir is None:
        session_dir = get_default_session_dir()
    
    session_path = Path(session_dir)
    if not session_path.exists():
        return []
    
    sessions = []
    for session_file in session_path.glob("*.json"):
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
            
            # Skip if status filter doesn't match
            if status_filter and session_data.get('status') != status_filter:
                continue
            
            session_summary = {
                'session_id': session_data['session_id'],
                'session_name': session_data['session_name'],
                'status': session_data['status'],
                'created_at': session_data['created_at'],
                'updated_at': session_data.get('updated_at', session_data['created_at']),
                'progress': session_data['progress'],
                'timing': session_data.get('timing', {}),
                'file_path': str(session_file)
            }
            
            # Add target information if available
            if 'target_config' in session_data:
                target_config = session_data['target_config']
                session_summary['target_info'] = {
                    'provider': target_config.get('provider', 'unknown'),
                    'model': target_config.get('model', 'unknown')
                }
            
            sessions.append(session_summary)
            
        except (json.JSONDecodeError, KeyError):
            # Skip corrupted session files
            continue
    
    # Sort by creation time, newest first
    return sorted(sessions, key=lambda x: x['created_at'], reverse=True)


def delete_session(
    session_id: str,
    session_dir: Optional[str] = None
) -> bool:
    """
    Delete an attack session and its data.
    
    Args:
        session_id: Session ID to delete
        session_dir: Directory where session files are stored
        
    Returns:
        True if session was deleted, False if not found
    """
    if session_dir is None:
        session_dir = get_default_session_dir()
    
    session_path = Path(session_dir) / f"{session_id}.json"
    
    if session_path.exists():
        session_path.unlink()
        return True
    
    return False


def archive_completed_sessions(
    session_dir: Optional[str] = None,
    archive_dir: Optional[str] = None,
    older_than_days: int = 30
) -> int:
    """
    Archive completed sessions older than specified days.
    
    Args:
        session_dir: Directory where session files are stored
        archive_dir: Directory to archive sessions to
        older_than_days: Archive sessions older than this many days
        
    Returns:
        Number of sessions archived
    """
    if session_dir is None:
        session_dir = get_default_session_dir()
    
    if archive_dir is None:
        archive_dir = str(Path(session_dir) / "archive")
    
    Path(archive_dir).mkdir(parents=True, exist_ok=True)
    
    cutoff_time = time.time() - (older_than_days * 24 * 3600)
    archived_count = 0
    
    for session_file in Path(session_dir).glob("*.json"):
        try:
            with open(session_file, 'r') as f:
                session_data = json.load(f)
            
            # Only archive completed sessions
            if (session_data.get('status') == 'completed' and
                session_data.get('updated_at', 0) < cutoff_time):
                
                # Move to archive directory
                archive_path = Path(archive_dir) / session_file.name
                session_file.rename(archive_path)
                archived_count += 1
                
        except (json.JSONDecodeError, KeyError, OSError):
            # Skip problematic files
            continue
    
    return archived_count


def get_session_statistics(
    session_id: str,
    session_dir: Optional[str] = None
) -> Dict:
    """
    Get detailed statistics for a specific session.
    
    Args:
        session_id: Session ID to analyze
        session_dir: Directory where session files are stored
        
    Returns:
        Dictionary containing detailed session statistics
    """
    session_data = load_attack_session(session_id, session_dir)
    
    # Basic progress statistics
    progress = session_data['progress']
    statistics = session_data.get('statistics', {})
    timing = session_data.get('timing', {})
    
    stats = {
        'session_info': {
            'id': session_data['session_id'],
            'name': session_data['session_name'],
            'status': session_data['status'],
            'created_at': session_data['created_at'],
            'updated_at': session_data.get('updated_at')
        },
        'progress': progress,
        'statistics': statistics,
        'timing': timing
    }
    
    # Analyze results if available
    results = session_data.get('results', [])
    if results:
        execution_times = [r.get('execution_time', 0) for r in results if 'execution_time' in r]
        
        if execution_times:
            stats['performance'] = {
                'min_response_time': min(execution_times),
                'max_response_time': max(execution_times),
                'average_response_time': sum(execution_times) / len(execution_times),
                'total_response_time': sum(execution_times)
            }
        
        # Error analysis
        errors = [r for r in results if not r.get('success', True)]
        if errors:
            error_types = {}
            for error in errors:
                error_type = error.get('error_type', 'Unknown')
                error_types[error_type] = error_types.get(error_type, 0) + 1
            
            stats['error_analysis'] = {
                'total_errors': len(errors),
                'error_types': error_types,
                'error_rate': len(errors) / len(results)
            }
    
    return stats