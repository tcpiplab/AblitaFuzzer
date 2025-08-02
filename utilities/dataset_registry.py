#!/usr/bin/env python3

from typing import Dict, List, Optional, Any
from colorama import Fore

# Dataset registry with metadata for available datasets
DATASETS = {
    "advbench_harmful": {
        "name": "AdvBench Harmful Behaviors",
        "url": "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv",
        "description": "Standard harmful behavior prompts from AdvBench research",
        "format": "csv",
        "columns": ["goal", "target"],
        "sha256": None,  # No known hash available
        "size_mb": 0.1
    },
    "jailbreak_2023": {
        "name": "Jailbreak Prompts 2023",
        "url": "https://github.com/verazuo/jailbreak_llms/raw/main/data/prompts/jailbreak_prompts_2023_12_25.csv",
        "description": "Jailbreak prompts collection from December 2023",
        "format": "csv",
        "columns": ["platform", "source", "prompt", "jailbreak", "created_at", "date", "community", "community_id", "previous_community_id"],
        "sha256": None,  # No known hash available
        "size_mb": 2.5
    }
}


def get_available_datasets() -> Dict[str, Dict[str, Any]]:
    """
    Get all available datasets from the registry.
    
    Returns:
        Dictionary mapping dataset IDs to their metadata
    """
    return DATASETS.copy()


def get_dataset_info(dataset_id: str) -> Optional[Dict[str, Any]]:
    """
    Get information about a specific dataset.
    
    Args:
        dataset_id: Identifier for the dataset
        
    Returns:
        Dataset metadata dictionary, or None if not found
    """
    return DATASETS.get(dataset_id)


def list_dataset_names() -> List[str]:
    """
    Get list of available dataset identifiers.
    
    Returns:
        List of dataset ID strings
    """
    return list(DATASETS.keys())


def search_datasets(query: str) -> Dict[str, Dict[str, Any]]:
    """
    Search for datasets by name or description.
    
    Args:
        query: Search query string
        
    Returns:
        Dictionary of matching datasets
    """
    query_lower = query.lower()
    results = {}
    
    for dataset_id, info in DATASETS.items():
        if (query_lower in dataset_id.lower() or 
            query_lower in info["name"].lower() or 
            query_lower in info["description"].lower()):
            results[dataset_id] = info
    
    return results


def validate_dataset_info(dataset_info: Dict[str, Any]) -> List[str]:
    """
    Validate dataset information structure.
    
    Args:
        dataset_info: Dataset metadata dictionary
        
    Returns:
        List of validation error messages (empty if valid)
    """
    errors = []
    required_fields = ["name", "url", "description", "format", "columns"]
    
    for field in required_fields:
        if field not in dataset_info:
            errors.append(f"Missing required field: {field}")
    
    if "url" in dataset_info and not dataset_info["url"].startswith(("http://", "https://")):
        errors.append("URL must start with http:// or https://")
    
    if "format" in dataset_info and dataset_info["format"] not in ["csv", "json", "txt"]:
        errors.append("Format must be csv, json, or txt")
    
    if "columns" in dataset_info and not isinstance(dataset_info["columns"], list):
        errors.append("Columns must be a list")
    
    return errors


def add_custom_dataset(dataset_id: str, dataset_info: Dict[str, Any]) -> bool:
    """
    Add a custom dataset to the registry.
    
    Args:
        dataset_id: Unique identifier for the dataset
        dataset_info: Dataset metadata dictionary
        
    Returns:
        True if added successfully, False otherwise
    """
    # Validate dataset info
    errors = validate_dataset_info(dataset_info)
    if errors:
        print(f"{Fore.RED}[!] Invalid dataset info:")
        for error in errors:
            print(f"{Fore.RED}    - {error}")
        return False
    
    if dataset_id in DATASETS:
        print(f"{Fore.YELLOW}[!] Dataset '{dataset_id}' already exists")
        return False
    
    DATASETS[dataset_id] = dataset_info
    print(f"{Fore.GREEN}[+] Added custom dataset '{dataset_id}'")
    return True


def print_dataset_info(dataset_id: str) -> None:
    """
    Print detailed information about a dataset.
    
    Args:
        dataset_id: Identifier for the dataset
    """
    info = get_dataset_info(dataset_id)
    if not info:
        print(f"{Fore.RED}[!] Dataset '{dataset_id}' not found")
        return
    
    print(f"{Fore.GREEN}Dataset: {dataset_id}")
    print(f"  Name: {info['name']}")
    print(f"  Description: {info['description']}")
    print(f"  URL: {info['url']}")
    print(f"  Format: {info['format']}")
    print(f"  Columns: {', '.join(info['columns'])}")
    print(f"  Estimated size: {info['size_mb']} MB")
    if info.get('sha256'):
        print(f"  SHA256: {info['sha256']}")


def print_all_datasets() -> None:
    """Print information about all available datasets."""
    datasets = get_available_datasets()
    if not datasets:
        print(f"{Fore.YELLOW}[!] No datasets available")
        return
    
    print(f"{Fore.GREEN}Available datasets:")
    for dataset_id in sorted(datasets.keys()):
        info = datasets[dataset_id]
        print(f"  {dataset_id}: {info['name']} ({info['size_mb']} MB)")
        print(f"    {info['description']}")


def get_dataset_url(dataset_id: str) -> Optional[str]:
    """
    Get the download URL for a dataset.
    
    Args:
        dataset_id: Identifier for the dataset
        
    Returns:
        Dataset URL, or None if not found
    """
    info = get_dataset_info(dataset_id)
    return info["url"] if info else None


def get_dataset_hash(dataset_id: str) -> Optional[str]:
    """
    Get the expected hash for a dataset.
    
    Args:
        dataset_id: Identifier for the dataset
        
    Returns:
        Expected SHA256 hash, or None if not available
    """
    info = get_dataset_info(dataset_id)
    return info.get("sha256") if info else None


def is_dataset_available(dataset_id: str) -> bool:
    """
    Check if a dataset is available in the registry.
    
    Args:
        dataset_id: Identifier for the dataset
        
    Returns:
        True if dataset exists, False otherwise
    """
    return dataset_id in DATASETS


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Dataset registry management')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List all available datasets')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show detailed dataset information')
    info_parser.add_argument('dataset_id', help='Dataset identifier')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search datasets')
    search_parser.add_argument('query', help='Search query')
    
    args = parser.parse_args()
    
    if args.command == 'list':
        print_all_datasets()
    elif args.command == 'info':
        print_dataset_info(args.dataset_id)
    elif args.command == 'search':
        results = search_datasets(args.query)
        if results:
            print(f"{Fore.GREEN}Search results for '{args.query}':")
            for dataset_id, info in results.items():
                print(f"  {dataset_id}: {info['name']}")
        else:
            print(f"{Fore.YELLOW}[!] No datasets found matching '{args.query}'")
    else:
        parser.print_help()