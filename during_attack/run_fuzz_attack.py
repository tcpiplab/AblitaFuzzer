#!/usr/bin/env python3

"""
Attack execution with new concurrent engine for AblitaFuzzer.

This module integrates the new concurrent attack engine while maintaining
backwards compatibility with the existing CLI interface.
"""

import json
import time
from typing import Optional, List, Dict, Any

from colorama import Fore

from pre_attack.pre_attack_functions import generate_malicious_prompts
from attack_engine import coordinate_attack_campaign, execute_multi_target_campaign
from attack_engine.session_manager import list_sessions, get_session_statistics
from configs import config as config
from configs.config import ATTACK_ENGINE_CONFIG
from configs.config_loader import list_available_targets
from utilities.text_utilities import vprint


def run_fuzz_attack(args) -> None:
    """
    Main entry point for fuzzing attacks with new concurrent engine.
    
    Args:
        args: Command line arguments from argparse
    """
    try:
        # Check if resuming a session
        session_id = getattr(args, 'resume_session', None)
        if session_id:
            print(f"{Fore.CYAN}[*] Resuming attack session: {session_id}")
            resume_attack_session(session_id, args)
            return
        
        # Get target configuration
        target_name = getattr(args, 'target', None)
        if not target_name:
            # Use first available target as default
            current_config = config.get_config()
            available_targets = list_available_targets(current_config)
            if not available_targets:
                print(f"{Fore.RED}[!] No targets configured. Please configure targets first.")
                return
            target_name = available_targets[0]['name']
            print(f"{Fore.YELLOW}[*] Using default target: {target_name}")
        
        # Generate or load prompts
        prompts = prepare_attack_prompts(args)
        if not prompts:
            print(f"{Fore.RED}[!] No attack prompts available")
            return
        
        # Configure attack parameters
        max_workers = getattr(args, 'workers', ATTACK_ENGINE_CONFIG['max_workers'])
        rate_limit = getattr(args, 'rate_limit', ATTACK_ENGINE_CONFIG['default_rate_limit'])
        session_name = getattr(args, 'session_name', None)
        
        print(f"{Fore.GREEN}[+] Starting concurrent attack with {max_workers} workers")
        print(f"{Fore.GREEN}[+] Rate limit: {rate_limit} requests/second")
        print(f"{Fore.GREEN}[+] Target: {target_name}")
        print(f"{Fore.GREEN}[+] Prompts: {len(prompts)}")
        
        # Execute attack campaign
        campaign_result = coordinate_attack_campaign(
            prompts=prompts,
            target_name=target_name,
            session_name=session_name,
            max_workers=max_workers,
            rate_limit=rate_limit
        )
        
        if campaign_result.get('success'):
            handle_successful_campaign(campaign_result, args)
        else:
            handle_failed_campaign(campaign_result, args)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Attack interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[!] Attack failed: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()


def resume_attack_session(session_id: str, args) -> None:
    """
    Resume an interrupted attack session.
    
    Args:
        session_id: Session ID to resume
        args: Command line arguments
    """
    try:
        # Get session statistics first
        session_stats = get_session_statistics(session_id)
        session_info = session_stats['session_info']
        progress = session_stats['progress']
        
        print(f"{Fore.CYAN}[*] Session: {session_info['name']}")
        print(f"{Fore.CYAN}[*] Progress: {progress['completed']}/{progress['total']} completed")
        print(f"{Fore.CYAN}[*] Remaining: {progress['remaining']} prompts")
        
        if progress['remaining'] == 0:
            print(f"{Fore.GREEN}[+] Session already completed")
            return
        
        # Resume the campaign
        campaign_result = coordinate_attack_campaign(
            prompts=[],  # Will be loaded from session
            target_name=session_info.get('target_name', 'unknown'),
            resume_session_id=session_id
        )
        
        if campaign_result.get('success'):
            handle_successful_campaign(campaign_result, args)
        else:
            handle_failed_campaign(campaign_result, args)
            
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to resume session: {e}")


def prepare_attack_prompts(args) -> List[str]:
    """
    Generate or load attack prompts for the campaign.
    
    Args:
        args: Command line arguments
        
    Returns:
        List of attack prompts
    """
    try:
        # Check if prompts provided directly
        if hasattr(args, 'prompts') and args.prompts:
            return args.prompts
        
        # Generate prompts using existing system
        print(f"{Fore.GREEN}[+] Generating malicious prompts...")
        
        num_prompts = getattr(args, 'num_prompts', config.NUM_PROMPTS_TO_GENERATE)
        
        # Load prompt styles configuration
        prompt_styles_config = None
        try:
            with open(config.PROMPT_STYLES_FILE_PATH) as f:
                prompt_styles_config = json.load(f)
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[*] Prompt styles file not found, using defaults")
        except Exception as e:
            print(f"{Fore.YELLOW}[*] Error loading prompt styles: {e}")
        
        # Generate prompts
        malicious_prompts = generate_malicious_prompts(
            num_prompts=num_prompts,
            prompt_styles_config=prompt_styles_config,
            seed_prompt_csv_file_path=config.SEED_PROMPT_INPUT_FILE_PATH,
            target_prompt_style=config.TARGET_PROMPT_STYLE
        )
        
        print(f"{Fore.GREEN}[+] Generated {len(malicious_prompts)} malicious prompts")
        return malicious_prompts
        
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to prepare attack prompts: {e}")
        return []


def handle_successful_campaign(campaign_result: Dict, args) -> None:
    """
    Handle successful attack campaign completion.
    
    Args:
        campaign_result: Campaign execution results
        args: Command line arguments
    """
    session_id = campaign_result.get('session_id')
    session_name = campaign_result.get('session_name', 'unknown')
    statistics = campaign_result.get('statistics', {})
    results = campaign_result.get('results', [])
    
    print(f"\n{Fore.GREEN}[+] Attack campaign '{session_name}' completed successfully")
    print(f"{Fore.GREEN}[+] Session ID: {session_id}")
    
    # Display statistics
    if statistics:
        print(f"\n{Fore.CYAN}Campaign Statistics:")
        print(f"  Total attacks: {statistics.get('total_items', 0)}")
        print(f"  Successful: {statistics.get('completed', 0)}")
        print(f"  Failed: {statistics.get('failed', 0)}")
        print(f"  Success rate: {statistics.get('success_rate', 0):.2%}")
        print(f"  Total time: {statistics.get('total_time', 0):.2f}s")
        print(f"  Average rate: {statistics.get('average_rate', 0):.2f} req/s")
    
    # Save results to file for backwards compatibility
    try:
        # Convert results to legacy format for existing analyzers
        legacy_results = convert_to_legacy_format(results)
        
        with open(config.TEMP_RESULTS_FILE_PATH, 'w') as f:
            json.dump(legacy_results, f, indent=4)
        
        print(f"{Fore.GREEN}[+] Results saved to '{config.TEMP_RESULTS_FILE_PATH}'")
        
        # Also save detailed results with session info
        detailed_results = {
            'session_info': {
                'session_id': session_id,
                'session_name': session_name,
                'timestamp': time.time()
            },
            'campaign_config': campaign_result.get('execution_config', {}),
            'statistics': statistics,
            'results': results
        }
        
        detailed_path = f"results/detailed_results_{session_id[:8]}.json"
        with open(detailed_path, 'w') as f:
            json.dump(detailed_results, f, indent=4)
        
        print(f"{Fore.GREEN}[+] Detailed results saved to '{detailed_path}'")
        
    except Exception as e:
        print(f"{Fore.YELLOW}[*] Warning: Failed to save results to file: {e}")


def handle_failed_campaign(campaign_result: Dict, args) -> None:
    """
    Handle failed attack campaign.
    
    Args:
        campaign_result: Campaign execution results
        args: Command line arguments
    """
    session_id = campaign_result.get('session_id')
    error = campaign_result.get('error', 'Unknown error')
    error_type = campaign_result.get('error_type', 'Unknown')
    
    print(f"\n{Fore.RED}[!] Attack campaign failed: {error}")
    print(f"{Fore.RED}[!] Error type: {error_type}")
    
    if session_id:
        print(f"{Fore.YELLOW}[*] Session ID: {session_id}")
        print(f"{Fore.YELLOW}[*] You can resume this session later using: ablitafuzzer session resume {session_id}")


def convert_to_legacy_format(results: List[Dict]) -> List[Dict]:
    """
    Convert new attack results to legacy format for backwards compatibility.
    
    Args:
        results: New format attack results
        
    Returns:
        Results in legacy format
    """
    legacy_results = []
    
    for result in results:
        if result.get('success'):
            # Successful attack
            response_data = result.get('response', {})
            legacy_result = {
                'prompt': result.get('prompt', ''),
                'response': response_data.get('raw_response', {}),
                'attack_id': f"concurrent_{int(time.time())}"
            }
        else:
            # Failed attack
            legacy_result = {
                'prompt': result.get('prompt', ''),
                'error': result.get('error', 'Unknown error')
            }
        
        legacy_results.append(legacy_result)
    
    return legacy_results


def run_multi_target_attack(args) -> None:
    """
    Run attack campaign against multiple targets concurrently.
    
    Args:
        args: Command line arguments with target list
    """
    try:
        target_names = getattr(args, 'targets', [])
        if not target_names:
            print(f"{Fore.RED}[!] No targets specified for multi-target attack")
            return
        
        # Prepare prompts
        prompts = prepare_attack_prompts(args)
        if not prompts:
            return
        
        session_name = getattr(args, 'session_name', f"multi_target_{int(time.time())}")
        concurrent_targets = getattr(args, 'concurrent_targets', 
                                   ATTACK_ENGINE_CONFIG['max_concurrent_targets'])
        
        print(f"{Fore.GREEN}[+] Starting multi-target attack")
        print(f"{Fore.GREEN}[+] Targets: {', '.join(target_names)}")
        print(f"{Fore.GREEN}[+] Concurrent targets: {concurrent_targets}")
        print(f"{Fore.GREEN}[+] Prompts per target: {len(prompts)}")
        
        # Execute multi-target campaign
        campaign_result = execute_multi_target_campaign(
            prompts=prompts,
            target_names=target_names,
            session_name=session_name,
            concurrent_targets=concurrent_targets
        )
        
        # Handle results
        if campaign_result.get('success'):
            handle_multi_target_success(campaign_result, args)
        else:
            handle_multi_target_failure(campaign_result, args)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Multi-target attack interrupted by user")
    except Exception as e:
        print(f"{Fore.RED}[!] Multi-target attack failed: {e}")


def handle_multi_target_success(campaign_result: Dict, args) -> None:
    """
    Handle successful multi-target campaign.
    
    Args:
        campaign_result: Multi-target campaign results
        args: Command line arguments
    """
    session_name = campaign_result.get('session_name', 'unknown')
    statistics = campaign_result.get('combined_statistics', {})
    target_results = campaign_result.get('target_results', {})
    
    print(f"\n{Fore.GREEN}[+] Multi-target campaign '{session_name}' completed")
    
    # Display combined statistics
    if statistics:
        print(f"\n{Fore.CYAN}Combined Statistics:")
        print(f"  Total targets: {statistics.get('total_targets', 0)}")
        print(f"  Successful targets: {statistics.get('successful_targets', 0)}")
        print(f"  Total attacks: {statistics.get('total_attacks', 0)}")
        print(f"  Successful attacks: {statistics.get('successful_attacks', 0)}")
        print(f"  Overall success rate: {statistics.get('overall_success_rate', 0):.2%}")
    
    # Display per-target results
    print(f"\n{Fore.CYAN}Per-Target Results:")
    for target_name, target_result in target_results.items():
        if target_result.get('success'):
            target_stats = target_result.get('statistics', {})
            print(f"  {target_name}: ✓ Success - {target_stats.get('completed', 0)} attacks")
        else:
            print(f"  {target_name}: ✗ Failed - {target_result.get('error', 'Unknown error')}")


def handle_multi_target_failure(campaign_result: Dict, args) -> None:
    """
    Handle failed multi-target campaign.
    
    Args:
        campaign_result: Multi-target campaign results
        args: Command line arguments
    """
    errors = campaign_result.get('errors', [])
    print(f"\n{Fore.RED}[!] Multi-target campaign failed")
    
    if errors:
        print(f"{Fore.RED}[!] Errors encountered:")
        for error in errors:
            target_name = error.get('target_name', 'unknown')
            error_msg = error.get('error', 'Unknown error')
            print(f"  {target_name}: {error_msg}")


# Legacy function for backwards compatibility
def fuzz_target_model(args, session):
    """
    Legacy function wrapper for backwards compatibility.
    
    Args:
        args: Command line arguments
        session: HTTP session (now unused)
    """
    print(f"{Fore.YELLOW}[*] Using legacy compatibility mode")
    run_fuzz_attack(args)


# Legacy function for backwards compatibility  
def attack_target_model_api(args, session, prompt_styles_config, prompts, model_name):
    """
    Legacy function wrapper for backwards compatibility.
    
    Args:
        args: Command line arguments
        session: HTTP session (now unused)
        prompt_styles_config: Prompt styles configuration (now unused)
        prompts: List of prompts to attack with
        model_name: Model name (now unused)
        
    Returns:
        Results in legacy format
    """
    print(f"{Fore.YELLOW}[*] Using legacy API compatibility mode")
    
    # Set prompts on args for new system to use
    args.prompts = prompts
    
    # Execute using new system
    run_fuzz_attack(args)
    
    # Try to load results from file
    try:
        with open(config.TEMP_RESULTS_FILE_PATH, 'r') as f:
            return json.load(f)
    except:
        return []