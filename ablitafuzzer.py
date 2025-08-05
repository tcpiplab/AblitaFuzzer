import argparse
from post_attack.analyzers.run_all_analyzers import run_all_analyzers
from post_attack.analyzers.llm_results_analyzer import analyze_campaign_results, generate_comprehensive_reports
from post_attack.analyzers.nlp_results_analyzer import save_classification_results, generate_enhanced_nlp_report
from reporting_engine import generate_executive_report, generate_technical_report, export_to_json, export_to_csv
from during_attack.run_fuzz_attack import run_fuzz_attack
from tests.run_all_test_functions import run_all_test_functions
from utilities.dataset_registry import (print_all_datasets, print_dataset_info, 
                                      search_datasets, get_dataset_info, 
                                      get_dataset_url, get_dataset_hash)
from utilities.download_manager import (download_dataset, clear_dataset_cache, 
                                      get_cache_status, list_cached_datasets)
from configs.config_loader import (load_configuration, list_available_targets, 
                                 list_available_providers, get_campaign_configuration)
from configs.target_manager import (test_target_connectivity, list_targets_with_status,
                                   generate_target_health_report)
from configs.validator import (validate_configuration_file, validate_environment_setup,
                              get_configuration_recommendations)
from configs.migration import (migrate_legacy_config, create_default_config_from_template,
                             get_migration_status)
from attack_engine.session_manager import (list_sessions, get_session_statistics, 
                                          delete_session, archive_completed_sessions)
from colorama import init, Fore
import os

# TODO: Move this to main() and test if it still works correctly
# Initialize colorama and set autoreset to True
init(autoreset=True)


def handle_datasets_list(args):
    """Handle the datasets list command."""
    print_all_datasets()


def handle_datasets_info(args):
    """Handle the datasets info command."""
    print_dataset_info(args.dataset_id)


def handle_datasets_download(args):
    """Handle the datasets download command."""
    info = get_dataset_info(args.dataset_id)
    if not info:
        print(f"{Fore.RED}[!] Dataset '{args.dataset_id}' not found in registry")
        return
    
    url = get_dataset_url(args.dataset_id)
    expected_hash = get_dataset_hash(args.dataset_id)
    
    result = download_dataset(
        args.dataset_id, 
        url, 
        expected_hash,
        force_download=args.force,
        cache_dir=args.cache_dir
    )
    
    if result:
        print(f"{Fore.GREEN}[+] Dataset cached at: {result}")
    else:
        print(f"{Fore.RED}[!] Failed to download dataset '{args.dataset_id}'")


def handle_datasets_search(args):
    """Handle the datasets search command."""
    results = search_datasets(args.query)
    if results:
        print(f"{Fore.GREEN}Search results for '{args.query}':")
        for dataset_id, info in results.items():
            print(f"  {dataset_id}: {info['name']}")
            print(f"    {info['description']}")
    else:
        print(f"{Fore.YELLOW}[!] No datasets found matching '{args.query}'")


def handle_cache_status(args):
    """Handle the cache status command."""
    status = get_cache_status(args.cache_dir)
    print(f"Cache directory: {status['cache_dir']}")
    print(f"Total datasets: {status['total_datasets']}")
    print(f"Valid datasets: {status['valid_datasets']}")
    print(f"Total size: {status['total_size_mb']} MB")


def handle_cache_clear(args):
    """Handle the cache clear command."""
    clear_dataset_cache(args.dataset_id, args.cache_dir)


def handle_cache_list(args):
    """Handle the cache list command."""
    cached = list_cached_datasets(args.cache_dir)
    if not cached:
        print(f"{Fore.YELLOW}[!] No cached datasets found")
        return
    
    print(f"{Fore.GREEN}Cached datasets:")
    for dataset_id, info in cached.items():
        status = "valid" if info['valid'] else "expired/invalid"
        size_mb = round(info['size_bytes'] / (1024 * 1024), 2)
        print(f"  {dataset_id}: {info['filename']} ({size_mb} MB) - {status}")


# Configuration management handlers
def handle_config_init(args):
    """Handle the config init command."""
    result = create_default_config_from_template(args.template)
    
    if result['success']:
        print(f"{Fore.GREEN}[+] {result['message']}")
        print(f"Configuration created at: {result['config_path']}")
        print("\nNext steps:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
    else:
        print(f"{Fore.RED}[!] {result['message']}")
        if 'available_templates' in result:
            print(f"Available templates: {', '.join(result['available_templates'])}")


def handle_config_validate(args):
    """Handle the config validate command."""
    try:
        config = load_configuration(args.config_path, args.environment)
        print(f"{Fore.GREEN}[+] Configuration is valid")
        
        # Check environment setup
        env_status = validate_environment_setup(config)
        if env_status['missing_variables']:
            print(f"{Fore.YELLOW}[!] Missing environment variables:")
            for var in env_status['missing_variables']:
                print(f"  - {var}")
        
        if env_status['warnings']:
            print(f"{Fore.YELLOW}[!] Warnings:")
            for warning in env_status['warnings']:
                print(f"  - {warning}")
        
        # Show recommendations
        recommendations = get_configuration_recommendations(config)
        if recommendations:
            print(f"\n{Fore.CYAN}Recommendations:")
            for rec in recommendations:
                print(f"  - {rec}")
                
    except Exception as e:
        print(f"{Fore.RED}[!] Configuration validation failed: {e}")


def handle_config_list_targets(args):
    """Handle the config list-targets command."""
    try:
        config = load_configuration(args.config_path, args.environment)
        targets = list_available_targets(config)
        
        if not targets:
            print(f"{Fore.YELLOW}[!] No targets configured")
            return
        
        print(f"{Fore.GREEN}Available targets:")
        for target in targets:
            print(f"  {target['name']}: {target['description']}")
            print(f"    Provider: {target['provider']}, Model: {target['model']}")
            
    except Exception as e:
        print(f"{Fore.RED}[!] Error loading configuration: {e}")


def handle_config_test_target(args):
    """Handle the config test-target command."""
    try:
        config = load_configuration(args.config_path, args.environment)
        result = test_target_connectivity(config, args.target_name)
        
        if result['status'] == 'success':
            print(f"{Fore.GREEN}[+] Target '{args.target_name}' is reachable")
            print(f"Response time: {result['response_time']:.2f}s")
        else:
            print(f"{Fore.RED}[!] Target '{args.target_name}' failed connectivity test")
            print(f"Error: {result['error']}")
            if result['troubleshooting']:
                print(f"Troubleshooting: {result['troubleshooting']}")
                
    except Exception as e:
        print(f"{Fore.RED}[!] Error testing target: {e}")


def handle_config_list_providers(args):
    """Handle the config list-providers command."""
    try:
        config = load_configuration(args.config_path, args.environment)
        providers = list_available_providers(config)
        
        if not providers:
            print(f"{Fore.YELLOW}[!] No providers configured")
            return
        
        print(f"{Fore.GREEN}Available providers:")
        for provider in providers:
            print(f"  {provider['name']} ({provider['type']})")
            print(f"    Base URL: {provider['base_url']}")
            if provider['models']:
                print(f"    Models: {', '.join(provider['models'])}")
                
    except Exception as e:
        print(f"{Fore.RED}[!] Error loading configuration: {e}")


def handle_config_migrate(args):
    """Handle the config migrate command."""
    result = migrate_legacy_config()
    
    if result['success']:
        print(f"{Fore.GREEN}[+] {result['message']}")
        print(f"Configuration migrated to: {result['config_path']}")
        if result.get('env_template_path'):
            print(f"Environment template created: {result['env_template_path']}")
        print("\nRecommendations:")
        for rec in result['recommendations']:
            print(f"  - {rec}")
    else:
        print(f"{Fore.RED}[!] {result['message']}")
        if result.get('recommendations'):
            print("Recommendations:")
            for rec in result['recommendations']:
                print(f"  - {rec}")


def handle_targets_list(args):
    """Handle the targets list command."""
    try:
        config = load_configuration(args.config_path, args.environment)
        targets = list_targets_with_status(config, test_connectivity=not args.no_test)
        
        if not targets:
            print(f"{Fore.YELLOW}[!] No targets configured")
            return
        
        print(f"{Fore.GREEN}Configured targets:")
        for target in targets:
            status_color = Fore.GREEN if target['status'] == 'success' else Fore.RED
            status_text = target['status']
            if target['response_time']:
                status_text += f" ({target['response_time']:.2f}s)"
            
            print(f"  {target['name']}: {target['description']}")
            print(f"    Provider: {target['provider']}, Model: {target['model']}")
            print(f"    Status: {status_color}{status_text}{Fore.RESET}")
            if target['error']:
                print(f"    Error: {target['error']}")
                
    except Exception as e:
        print(f"{Fore.RED}[!] Error listing targets: {e}")


def handle_targets_health(args):
    """Handle the targets health command."""
    try:
        config = load_configuration(args.config_path, args.environment)
        report = generate_target_health_report(config)
        
        print(f"{Fore.GREEN}Target Health Report:")
        print(f"Total targets: {report['summary']['total_targets']}")
        print(f"Healthy: {report['summary']['healthy_count']} ({report['summary']['health_percentage']:.1f}%)")
        print(f"Warning: {report['summary']['warning_count']}")
        print(f"Failed: {report['summary']['failed_count']}")
        
        if report['performance']['average_response_time'] > 0:
            print(f"\nPerformance:")
            print(f"Average response time: {report['performance']['average_response_time']:.2f}s")
            if report['performance']['fastest_target']:
                print(f"Fastest target: {report['performance']['fastest_target']}")
            if report['performance']['slowest_target']:
                print(f"Slowest target: {report['performance']['slowest_target']}")
        
        if report['details']['failed_targets']:
            print(f"\n{Fore.RED}Failed targets:")
            for target in report['details']['failed_targets']:
                print(f"  {target['name']}: {target['error']}")
                
    except Exception as e:
        print(f"{Fore.RED}[!] Error generating health report: {e}")


# Session management handlers
def handle_session_list(args):
    """Handle the session list command."""
    try:
        sessions = list_sessions(status_filter=args.status)
        
        if not sessions:
            print(f"{Fore.YELLOW}[!] No attack sessions found")
            if args.status:
                print(f"    (filtered by status: {args.status})")
            return
        
        print(f"{Fore.GREEN}Attack Sessions:")
        for session in sessions:
            status_color = {
                'created': Fore.CYAN,
                'in_progress': Fore.YELLOW, 
                'completed': Fore.GREEN
            }.get(session['status'], Fore.WHITE)
            
            print(f"  {session['session_id'][:8]}... - {session['session_name']}")
            print(f"    Status: {status_color}{session['status']}{Fore.RESET}")
            print(f"    Progress: {session['progress']['completed']}/{session['progress']['total']} completed")
            
            # Format creation time
            import datetime
            created_time = datetime.datetime.fromtimestamp(session['created_at'])
            print(f"    Created: {created_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if 'target_info' in session:
                target_info = session['target_info']
                print(f"    Target: {target_info['provider']} - {target_info['model']}")
            
    except Exception as e:
        print(f"{Fore.RED}[!] Error listing sessions: {e}")


def handle_session_status(args):
    """Handle the session status command."""
    try:
        stats = get_session_statistics(args.session_id)
        session_info = stats['session_info']
        progress = stats['progress']
        timing = stats.get('timing', {})
        
        print(f"{Fore.GREEN}Session Status: {session_info['name']}")
        print(f"ID: {session_info['id']}")
        print(f"Status: {session_info['status']}")
        
        # Progress information
        print(f"\n{Fore.CYAN}Progress:")
        print(f"  Total prompts: {progress['total']}")
        print(f"  Completed: {progress['completed']}")
        print(f"  Failed: {progress['failed']}")
        print(f"  Remaining: {progress['remaining']}")
        print(f"  Success rate: {progress['success_rate']:.2%}")
        
        # Timing information
        if timing.get('start_time'):
            import datetime
            start_time = datetime.datetime.fromtimestamp(timing['start_time'])
            print(f"\n{Fore.CYAN}Timing:")
            print(f"  Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            if timing.get('end_time'):
                end_time = datetime.datetime.fromtimestamp(timing['end_time'])
                print(f"  Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"  Duration: {timing.get('total_duration', 0):.2f}s")
            
            if timing.get('average_response_time'):
                print(f"  Avg response time: {timing['average_response_time']:.2f}s")
        
        # Performance information
        if 'performance' in stats:
            perf = stats['performance']
            print(f"\n{Fore.CYAN}Performance:")
            print(f"  Min response time: {perf['min_response_time']:.2f}s")
            print(f"  Max response time: {perf['max_response_time']:.2f}s")
            print(f"  Average response time: {perf['average_response_time']:.2f}s")
        
        # Error analysis
        if 'error_analysis' in stats:
            error_analysis = stats['error_analysis']
            print(f"\n{Fore.RED}Errors:")
            print(f"  Total errors: {error_analysis['total_errors']}")
            print(f"  Error rate: {error_analysis['error_rate']:.2%}")
            
            if error_analysis['error_types']:
                print(f"  Error types:")
                for error_type, count in error_analysis['error_types'].items():
                    print(f"    {error_type}: {count}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error getting session status: {e}")


def handle_session_resume(args):
    """Handle the session resume command."""
    try:
        from during_attack.run_fuzz_attack import run_fuzz_attack
        
        # Set resume session on args and call main attack function
        args.resume_session = args.session_id
        
        print(f"{Fore.CYAN}[*] Resuming attack session: {args.session_id}")
        run_fuzz_attack(args)
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error resuming session: {e}")


def handle_session_delete(args):
    """Handle the session delete command."""
    try:
        session_id = args.session_id
        
        # Confirmation unless --confirm flag is used
        if not args.confirm:
            try:
                # Show session info first
                stats = get_session_statistics(session_id)
                session_info = stats['session_info']
                print(f"Session: {session_info['name']} ({session_info['id']})")
                print(f"Status: {session_info['status']}")
                
                response = input(f"\n{Fore.YELLOW}Are you sure you want to delete this session? (y/N): ")
                if response.lower() not in ['y', 'yes']:
                    print(f"{Fore.CYAN}[*] Session deletion cancelled")
                    return
            except:
                # Session might not exist, but still ask for confirmation
                response = input(f"\n{Fore.YELLOW}Are you sure you want to delete session {session_id}? (y/N): ")
                if response.lower() not in ['y', 'yes']:
                    print(f"{Fore.CYAN}[*] Session deletion cancelled")
                    return
        
        # Delete the session
        if delete_session(session_id):
            print(f"{Fore.GREEN}[+] Session {session_id} deleted successfully")
        else:
            print(f"{Fore.RED}[!] Session {session_id} not found")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error deleting session: {e}")


def handle_session_clean(args):
    """Handle the session clean command."""
    try:
        days = args.days
        archived_count = archive_completed_sessions(older_than_days=days)
        
        if archived_count > 0:
            print(f"{Fore.GREEN}[+] Archived {archived_count} completed sessions older than {days} days")
        else:
            print(f"{Fore.YELLOW}[*] No sessions found to archive")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error cleaning sessions: {e}")


# Analysis and Reporting handlers
def handle_report_generate(args):
    """Handle the report generate command."""
    try:
        import json
        import configs.config as config
        
        print(f"{Fore.CYAN}[*] Generating professional analysis report...")
        
        # Load campaign results
        if args.results_file:
            results_file = args.results_file
        else:
            results_file = config.TEMP_RESULTS_FILE_PATH
        
        if not os.path.exists(results_file):
            print(f"{Fore.RED}[!] Results file not found: {results_file}")
            print(f"{Fore.YELLOW}[*] Please run an attack campaign first")
            return
        
        with open(results_file, 'r', encoding='utf-8') as f:
            campaign_data = {'results': json.load(f)}
        
        # Set target context
        target_context = {
            'name': args.target_name or 'Target LLM System',
            'type': 'llm',
            'data_classification': args.data_classification or 'internal',
            'system_criticality': args.criticality or 'medium',
            'user_count': args.user_count or 1000,
            'compliance_requirements': args.compliance or ['SOC2'],
            'exposure': args.exposure or 'internal'
        }
        
        # Run professional analysis
        analysis_results = analyze_campaign_results(campaign_data, target_context)
        
        # Generate reports
        output_dir = args.output_dir or 'reports'
        report_files = generate_comprehensive_reports(analysis_results, output_dir)
        
        print(f"{Fore.GREEN}[+] Professional analysis report generated successfully")
        print(f"{Fore.GREEN}[+] Reports saved to: {output_dir}")
        
        for report_type, file_path in report_files.items():
            print(f"{Fore.GREEN}  - {report_type}: {file_path}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error generating report: {e}")


def handle_report_export(args):
    """Handle the report export command."""
    try:
        import json
        import configs.config as config
        import os
        
        print(f"{Fore.CYAN}[*] Exporting analysis results to {args.format} format...")
        
        # Load campaign results
        if args.results_file:
            results_file = args.results_file
        else:
            results_file = config.TEMP_RESULTS_FILE_PATH
        
        if not os.path.exists(results_file):
            print(f"{Fore.RED}[!] Results file not found: {results_file}")
            return
        
        with open(results_file, 'r', encoding='utf-8') as f:
            campaign_data = {'results': json.load(f)}
        
        # Set target context
        target_context = {
            'name': args.target_name or 'Target LLM System',
            'type': 'llm',
            'data_classification': 'internal',
            'system_criticality': 'medium'
        }
        
        # Run analysis if needed
        analysis_results = analyze_campaign_results(campaign_data, target_context)
        
        # Set output file
        if args.output:
            output_file = args.output
        else:
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
            output_file = f"reports/Export_{timestamp}.{args.format}"
        
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        # Export based on format
        if args.format == 'json':
            export_to_json(analysis_results, output_file)
        elif args.format == 'csv':
            vulnerabilities = analysis_results.get('vulnerabilities', [])
            export_to_csv(vulnerabilities, output_file)
        else:
            print(f"{Fore.RED}[!] Unsupported export format: {args.format}")
            return
        
        print(f"{Fore.GREEN}[+] Results exported to: {output_file}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error exporting results: {e}")


def handle_analysis_classify(args):
    """Handle the analysis classify command."""
    try:
        print(f"{Fore.CYAN}[*] Running enhanced NLP classification...")
        
        # Run enhanced classification
        use_professional = not args.legacy_only
        save_classification_results(use_professional=use_professional)
        
        # Generate enhanced report if requested
        if args.generate_report:
            report_file = generate_enhanced_nlp_report(args.output)
            print(f"{Fore.GREEN}[+] Enhanced NLP report generated: {report_file}")
        
        print(f"{Fore.GREEN}[+] Enhanced NLP classification completed")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Error running NLP classification: {e}")


def setup_arguments():
    parser = argparse.ArgumentParser(description='AblitaFuzzer')

    subparsers = parser.add_subparsers(title='subcommands', description='valid subcommands', help='additional help')

    parser.add_argument('--version', action='store_true', help='Show version and exit')
    parser.add_argument('--verbose', action='store_true', help='Print more information during runtime')

    parser_analyze = subparsers.add_parser('analyze', help='Analyze results from the most recent fuzzing attack')
    parser_analyze.set_defaults(func=run_all_analyzers)

    parser_fuzz = subparsers.add_parser('fuzz', help='Fuzz the target model')
    parser_fuzz.add_argument('--proxy', metavar='IP:PORT', help='Specify the proxy to use')
    parser_fuzz.set_defaults(func=run_fuzz_attack)

    parser_test = subparsers.add_parser('test', help='Test calling both APIs but do not fuzz')
    parser_test.add_argument('--proxy', metavar='IP:PORT', help='Specify the proxy to use')
    parser_test.set_defaults(func=run_all_test_functions)

    # Dataset management commands
    parser_datasets = subparsers.add_parser('datasets', help='Dataset management commands')
    datasets_subparsers = parser_datasets.add_subparsers(dest='datasets_command', help='Dataset commands')
    
    # datasets list
    datasets_list = datasets_subparsers.add_parser('list', help='List available datasets')
    datasets_list.set_defaults(func=handle_datasets_list)
    
    # datasets info
    datasets_info = datasets_subparsers.add_parser('info', help='Show dataset information')
    datasets_info.add_argument('dataset_id', help='Dataset identifier')
    datasets_info.set_defaults(func=handle_datasets_info)
    
    # datasets download  
    datasets_download = datasets_subparsers.add_parser('download', help='Download a dataset')
    datasets_download.add_argument('dataset_id', help='Dataset identifier')
    datasets_download.add_argument('--force', action='store_true', help='Force download even if cached')
    datasets_download.add_argument('--cache-dir', help='Custom cache directory')
    datasets_download.set_defaults(func=handle_datasets_download)
    
    # datasets search
    datasets_search = datasets_subparsers.add_parser('search', help='Search datasets')
    datasets_search.add_argument('query', help='Search query')
    datasets_search.set_defaults(func=handle_datasets_search)
    
    # Cache management commands
    parser_cache = subparsers.add_parser('cache', help='Cache management commands')
    cache_subparsers = parser_cache.add_subparsers(dest='cache_command', help='Cache commands')
    
    # cache status
    cache_status = cache_subparsers.add_parser('status', help='Show cache status')
    cache_status.add_argument('--cache-dir', help='Custom cache directory')
    cache_status.set_defaults(func=handle_cache_status)
    
    # cache clear
    cache_clear = cache_subparsers.add_parser('clear', help='Clear cache')
    cache_clear.add_argument('dataset_id', nargs='?', help='Dataset to clear (optional, clears all if not specified)')
    cache_clear.add_argument('--cache-dir', help='Custom cache directory')
    cache_clear.set_defaults(func=handle_cache_clear)
    
    # cache list
    cache_list = cache_subparsers.add_parser('list', help='List cached datasets')
    cache_list.add_argument('--cache-dir', help='Custom cache directory')
    cache_list.set_defaults(func=handle_cache_list)

    # Configuration management commands
    parser_config = subparsers.add_parser('config', help='Configuration management commands')
    config_subparsers = parser_config.add_subparsers(dest='config_command', help='Configuration commands')
    
    # config init
    config_init = config_subparsers.add_parser('init', help='Initialize configuration')
    config_init.add_argument('--template', default='openai', 
                           help='Configuration template to use (openai, anthropic, azure_openai, enterprise, multi_target)')
    config_init.set_defaults(func=handle_config_init)
    
    # config validate
    config_validate = config_subparsers.add_parser('validate', help='Validate configuration')
    config_validate.add_argument('--config-path', help='Path to configuration file')
    config_validate.add_argument('--environment', help='Environment to validate (development, staging, production)')
    config_validate.set_defaults(func=handle_config_validate)
    
    # config list-targets
    config_list_targets = config_subparsers.add_parser('list-targets', help='List available targets')
    config_list_targets.add_argument('--config-path', help='Path to configuration file')
    config_list_targets.add_argument('--environment', help='Environment to use')
    config_list_targets.set_defaults(func=handle_config_list_targets)
    
    # config test-target
    config_test_target = config_subparsers.add_parser('test-target', help='Test connectivity to specific target')
    config_test_target.add_argument('target_name', help='Name of target to test')
    config_test_target.add_argument('--config-path', help='Path to configuration file')
    config_test_target.add_argument('--environment', help='Environment to use')
    config_test_target.set_defaults(func=handle_config_test_target)
    
    # config list-providers
    config_list_providers = config_subparsers.add_parser('list-providers', help='Show supported API providers')
    config_list_providers.add_argument('--config-path', help='Path to configuration file')
    config_list_providers.add_argument('--environment', help='Environment to use')
    config_list_providers.set_defaults(func=handle_config_list_providers)
    
    # config migrate
    config_migrate = config_subparsers.add_parser('migrate', help='Migrate from old configuration')
    config_migrate.set_defaults(func=handle_config_migrate)
    
    # Target management commands
    parser_targets = subparsers.add_parser('targets', help='Target management commands')
    targets_subparsers = parser_targets.add_subparsers(dest='targets_command', help='Target commands')
    
    # targets list
    targets_list = targets_subparsers.add_parser('list', help='List configured targets with status')
    targets_list.add_argument('--config-path', help='Path to configuration file')
    targets_list.add_argument('--environment', help='Environment to use')
    targets_list.add_argument('--no-test', action='store_true', help='Skip connectivity testing')
    targets_list.set_defaults(func=handle_targets_list)
    
    # targets health
    targets_health = targets_subparsers.add_parser('health', help='Generate target health report')
    targets_health.add_argument('--config-path', help='Path to configuration file')
    targets_health.add_argument('--environment', help='Environment to use')
    targets_health.set_defaults(func=handle_targets_health)

    # Session management commands
    parser_session = subparsers.add_parser('session', help='Attack session management commands')
    session_subparsers = parser_session.add_subparsers(dest='session_command', help='Session commands')
    
    # session list
    session_list = session_subparsers.add_parser('list', help='List attack sessions')
    session_list.add_argument('--status', help='Filter by session status (created, in_progress, completed)')
    session_list.set_defaults(func=handle_session_list)
    
    # session status
    session_status = session_subparsers.add_parser('status', help='Show session progress and statistics')
    session_status.add_argument('session_id', help='Session ID to check')
    session_status.set_defaults(func=handle_session_status)
    
    # session resume
    session_resume = session_subparsers.add_parser('resume', help='Resume interrupted session')
    session_resume.add_argument('session_id', help='Session ID to resume')
    session_resume.set_defaults(func=handle_session_resume)
    
    # session delete
    session_delete = session_subparsers.add_parser('delete', help='Delete attack session')
    session_delete.add_argument('session_id', help='Session ID to delete')
    session_delete.add_argument('--confirm', action='store_true', help='Skip confirmation prompt')
    session_delete.set_defaults(func=handle_session_delete)
    
    # session clean
    session_clean = session_subparsers.add_parser('clean', help='Clean up old completed sessions')
    session_clean.add_argument('--days', type=int, default=30, help='Archive sessions older than N days')
    session_clean.set_defaults(func=handle_session_clean)
    
    # Enhanced fuzz command with new attack engine options
    parser_fuzz.add_argument('--workers', type=int, help='Number of concurrent worker threads')
    parser_fuzz.add_argument('--rate-limit', type=float, help='Rate limit in requests per second')
    parser_fuzz.add_argument('--session-name', help='Name for attack session')
    parser_fuzz.add_argument('--target', help='Target configuration name')
    parser_fuzz.add_argument('--resume-session', help='Resume specific session ID')
    
    # Analysis and Reporting commands
    parser_report = subparsers.add_parser('report', help='Professional analysis and reporting commands')
    report_subparsers = parser_report.add_subparsers(dest='report_command', help='Reporting commands')
    
    # report generate
    report_generate = report_subparsers.add_parser('generate', help='Generate comprehensive security assessment report')
    report_generate.add_argument('--results-file', help='Path to results file (defaults to latest)')
    report_generate.add_argument('--output-dir', default='reports', help='Output directory for reports')
    report_generate.add_argument('--target-name', help='Target system name for report')
    report_generate.add_argument('--data-classification', choices=['public', 'internal', 'confidential', 'restricted'], 
                               help='Data classification level')
    report_generate.add_argument('--criticality', choices=['low', 'medium', 'high', 'critical'], 
                               help='System criticality level')
    report_generate.add_argument('--user-count', type=int, help='Estimated user count')
    report_generate.add_argument('--compliance', nargs='*', choices=['SOC2', 'ISO27001', 'NIST', 'PCI_DSS'], 
                               help='Compliance framework requirements')
    report_generate.add_argument('--exposure', choices=['internal', 'external', 'public'], 
                               help='System exposure level')
    report_generate.set_defaults(func=handle_report_generate)
    
    # report export
    report_export = report_subparsers.add_parser('export', help='Export analysis results to different formats')
    report_export.add_argument('format', choices=['json', 'csv'], help='Export format')
    report_export.add_argument('--results-file', help='Path to results file (defaults to latest)')
    report_export.add_argument('--output', help='Output file path')
    report_export.add_argument('--target-name', help='Target system name')
    report_export.set_defaults(func=handle_report_export)
    
    # Analysis commands
    parser_analysis = subparsers.add_parser('analysis', help='Enhanced analysis commands')
    analysis_subparsers = parser_analysis.add_subparsers(dest='analysis_command', help='Analysis commands')
    
    # analysis classify
    analysis_classify = analysis_subparsers.add_parser('classify', help='Run enhanced NLP classification with professional analysis')
    analysis_classify.add_argument('--legacy-only', action='store_true', help='Use only legacy classification methods')
    analysis_classify.add_argument('--generate-report', action='store_true', help='Generate enhanced analysis report')
    analysis_classify.add_argument('--output', help='Output file for report')
    analysis_classify.set_defaults(func=handle_analysis_classify)

    return parser


def main():
    parser = setup_arguments()
    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

    if hasattr(args, 'version') and args.version:
        print(f'AblitaFuzzer version 1.0.0-beta')
        print(f'Professional Analysis & Reporting Engine')
        exit()

if __name__ == '__main__':
    main()
