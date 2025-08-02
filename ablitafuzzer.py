import argparse
from post_attack.analyzers import run_all_analyzers
from during_attack.run_fuzz_attack import run_fuzz_attack
from tests.run_all_test_functions import run_all_test_functions
from utilities.dataset_registry import (print_all_datasets, print_dataset_info, 
                                      search_datasets, get_dataset_info, 
                                      get_dataset_url, get_dataset_hash)
from utilities.download_manager import (download_dataset, clear_dataset_cache, 
                                      get_cache_status, list_cached_datasets)
from colorama import init, Fore

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

    return parser


def main():
    parser = setup_arguments()
    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

    if args.version:
        print(f'AblitaFuzzer version 0.7-alpha')
        exit()

if __name__ == '__main__':
    main()
