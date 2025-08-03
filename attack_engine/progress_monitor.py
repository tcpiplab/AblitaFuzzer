#!/usr/bin/env python3

"""
Progress tracking functions for AblitaFuzzer.

Provides real-time progress monitoring with ETA calculations, success/failure tracking,
and configurable progress display for attack campaigns.
"""

import time
import sys
import threading
from typing import Dict, Optional, Callable, Any
from colorama import Fore, Style


def create_progress_monitor(
    total_items: int,
    update_interval: float = 1.0,
    display_width: int = 40,
    show_eta: bool = True,
    show_rate: bool = True
) -> Dict:
    """
    Create a progress monitor for tracking attack execution.
    
    Args:
        total_items: Total number of items to process
        update_interval: Seconds between progress updates
        display_width: Width of progress bar in characters
        show_eta: Whether to show estimated time remaining
        show_rate: Whether to show current processing rate
        
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
        'display_width': display_width,
        'show_eta': show_eta,
        'show_rate': show_rate,
        'lock': threading.Lock(),
        'response_times': [],
        'last_displayed': False,
        'custom_status': None
    }


def update_progress(
    monitor: Dict,
    success: bool = True,
    response_time: Optional[float] = None,
    custom_message: Optional[str] = None
) -> None:
    """
    Update progress monitor with completed item.
    
    Args:
        monitor: Progress monitor state dictionary
        success: Whether the item completed successfully
        response_time: Optional response time for the completed item
        custom_message: Optional custom status message
    """
    with monitor['lock']:
        if success:
            monitor['completed'] += 1
        else:
            monitor['failed'] += 1
        
        # Track response times for rate calculation
        if response_time is not None:
            monitor['response_times'].append(response_time)
            # Keep only recent response times for rate calculation
            if len(monitor['response_times']) > 100:
                monitor['response_times'] = monitor['response_times'][-100:]
        
        # Update custom status if provided
        if custom_message:
            monitor['custom_status'] = custom_message
        
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
    display_width = monitor['display_width']
    
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
    
    # Create progress bar
    filled_width = int(display_width * progress_pct / 100)
    bar = '█' * filled_width + '░' * (display_width - filled_width)
    
    # Format components
    progress_text = f"{progress_pct:5.1f}% ({processed}/{total})"
    
    # Success/failure indicators with colors
    success_text = f"{Fore.GREEN}✓{completed}{Style.RESET_ALL}"
    failure_text = f"{Fore.RED}✗{failed}{Style.RESET_ALL}" if failed > 0 else f"✗{failed}"
    
    status_components = [progress_text, success_text, failure_text]
    
    # Add rate if enabled
    if monitor['show_rate']:
        status_components.append(f"{rate:.1f}/s")
    
    # Add ETA if enabled and calculable
    if monitor['show_eta'] and eta_seconds > 0:
        eta_str = format_duration(eta_seconds)
        status_components.append(f"ETA: {eta_str}")
    
    # Add custom status if available
    if monitor['custom_status']:
        status_components.append(monitor['custom_status'])
    
    # Format complete status line
    status_line = f"\r[{bar}] " + " ".join(status_components)
    
    # Ensure line doesn't exceed reasonable terminal width
    if len(status_line) > 120:
        status_line = status_line[:117] + "..."
    
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
    if seconds < 0:
        return "unknown"
    
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


def finalize_progress(monitor: Dict, final_message: Optional[str] = None) -> Dict:
    """
    Complete progress monitoring and return final statistics.
    
    Args:
        monitor: Progress monitor state dictionary
        final_message: Optional final message to display
        
    Returns:
        Final execution statistics
    """
    with monitor['lock']:
        total_time = time.time() - monitor['start_time']
        total_processed = monitor['completed'] + monitor['failed']
        
        # Display final progress
        display_progress(monitor)
        
        # Clear progress line and show final results
        sys.stdout.write('\n')
        
        if final_message:
            print(final_message)
        
        # Calculate final statistics
        stats = {
            'total_items': monitor['total'],
            'completed': monitor['completed'],
            'failed': monitor['failed'],
            'success_rate': monitor['completed'] / total_processed if total_processed > 0 else 0,
            'total_time': total_time,
            'average_rate': total_processed / total_time if total_time > 0 else 0
        }
        
        # Add response time statistics if available
        if monitor['response_times']:
            response_times = monitor['response_times']
            stats['response_time_stats'] = {
                'min': min(response_times),
                'max': max(response_times),
                'average': sum(response_times) / len(response_times),
                'count': len(response_times)
            }
        
        monitor['last_displayed'] = True
        return stats


def create_multi_target_monitor(target_configs: Dict[str, int]) -> Dict:
    """
    Create progress monitor for multiple targets with individual tracking.
    
    Args:
        target_configs: Dictionary mapping target names to item counts
        
    Returns:
        Multi-target progress monitor configuration
    """
    total_items = sum(target_configs.values())
    
    return {
        'total_items': total_items,
        'target_configs': target_configs,
        'target_progress': {name: {'completed': 0, 'failed': 0} 
                          for name in target_configs.keys()},
        'start_time': time.time(),
        'last_update': time.time(),
        'update_interval': 1.0,
        'lock': threading.Lock()
    }


def update_target_progress(
    multi_monitor: Dict,
    target_name: str,
    success: bool = True
) -> None:
    """
    Update progress for specific target in multi-target monitor.
    
    Args:
        multi_monitor: Multi-target progress monitor configuration
        target_name: Name of target to update
        success: Whether the operation was successful
    """
    with multi_monitor['lock']:
        if target_name not in multi_monitor['target_progress']:
            return
        
        if success:
            multi_monitor['target_progress'][target_name]['completed'] += 1
        else:
            multi_monitor['target_progress'][target_name]['failed'] += 1
        
        current_time = time.time()
        if current_time - multi_monitor['last_update'] >= multi_monitor['update_interval']:
            display_multi_target_progress(multi_monitor)
            multi_monitor['last_update'] = current_time


def display_multi_target_progress(multi_monitor: Dict) -> None:
    """
    Display progress for multiple targets.
    
    Args:
        multi_monitor: Multi-target progress monitor configuration
    """
    print(f"\r{Fore.CYAN}Multi-Target Progress:{Style.RESET_ALL}")
    
    total_completed = 0
    total_failed = 0
    total_items = 0
    
    for target_name, config_count in multi_monitor['target_configs'].items():
        progress = multi_monitor['target_progress'][target_name]
        completed = progress['completed']
        failed = progress['failed']
        processed = completed + failed
        
        total_completed += completed
        total_failed += failed
        total_items += config_count
        
        # Calculate target progress percentage
        target_pct = (processed / config_count) * 100 if config_count > 0 else 0
        
        # Create mini progress bar
        bar_width = 20
        filled = int(bar_width * target_pct / 100)
        bar = '█' * filled + '░' * (bar_width - filled)
        
        print(f"  {target_name}: [{bar}] {target_pct:5.1f}% "
              f"({processed}/{config_count}) "
              f"{Fore.GREEN}✓{completed}{Style.RESET_ALL} "
              f"{Fore.RED}✗{failed}{Style.RESET_ALL}")
    
    # Overall progress
    overall_processed = total_completed + total_failed
    overall_pct = (overall_processed / total_items) * 100 if total_items > 0 else 0
    
    elapsed = time.time() - multi_monitor['start_time']
    rate = overall_processed / elapsed if elapsed > 0 else 0
    
    print(f"  {Fore.YELLOW}Overall: {overall_pct:5.1f}% "
          f"({overall_processed}/{total_items}) "
          f"{rate:.1f}/s{Style.RESET_ALL}")


def create_progress_callback(monitor: Dict) -> Callable[[bool], None]:
    """
    Create a callback function for updating progress monitor.
    
    Args:
        monitor: Progress monitor state dictionary
        
    Returns:
        Callback function that can be passed to other functions
    """
    def progress_callback(success: bool, response_time: Optional[float] = None) -> None:
        update_progress(monitor, success, response_time)
    
    return progress_callback


def set_progress_status(monitor: Dict, status: str) -> None:
    """
    Set custom status message for progress monitor.
    
    Args:
        monitor: Progress monitor state dictionary
        status: Custom status message to display
    """
    with monitor['lock']:
        monitor['custom_status'] = status


def get_progress_statistics(monitor: Dict) -> Dict:
    """
    Get current statistics from progress monitor.
    
    Args:
        monitor: Progress monitor state dictionary
        
    Returns:
        Dictionary containing current progress statistics
    """
    with monitor['lock']:
        total_processed = monitor['completed'] + monitor['failed']
        elapsed = time.time() - monitor['start_time']
        
        stats = {
            'total': monitor['total'],
            'completed': monitor['completed'],
            'failed': monitor['failed'],
            'processed': total_processed,
            'remaining': monitor['total'] - total_processed,
            'progress_percentage': (total_processed / monitor['total']) * 100 if monitor['total'] > 0 else 0,
            'success_rate': monitor['completed'] / total_processed if total_processed > 0 else 0,
            'elapsed_time': elapsed,
            'current_rate': total_processed / elapsed if elapsed > 0 else 0
        }
        
        # Add ETA if possible to calculate
        if stats['current_rate'] > 0 and stats['remaining'] > 0:
            stats['eta_seconds'] = stats['remaining'] / stats['current_rate']
            stats['eta_formatted'] = format_duration(stats['eta_seconds'])
        
        return stats


def pause_progress_display(monitor: Dict) -> None:
    """
    Temporarily pause progress display updates.
    
    Args:
        monitor: Progress monitor state dictionary
    """
    with monitor['lock']:
        monitor['paused'] = True


def resume_progress_display(monitor: Dict) -> None:
    """
    Resume progress display updates after pause.
    
    Args:
        monitor: Progress monitor state dictionary
    """
    with monitor['lock']:
        monitor['paused'] = False
        monitor['last_update'] = time.time()