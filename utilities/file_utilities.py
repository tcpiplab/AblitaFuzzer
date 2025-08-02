import csv
import os
from pathlib import Path
from typing import List, Tuple, Optional
from colorama import Fore
from utilities.dataset_registry import get_dataset_info, get_dataset_url, get_dataset_hash, is_dataset_available
from utilities.download_manager import download_dataset, get_cached_dataset_path
import configs.config as config


def resolve_dataset_path(dataset_identifier: str) -> Optional[str]:
    """
    Resolve a dataset identifier to a local file path.
    
    Args:
        dataset_identifier: Either a dataset registry ID or a local file path
        
    Returns:
        Path to the dataset file, or None if not available
    """
    # Check if it's already a local file path
    if os.path.exists(dataset_identifier):
        return dataset_identifier
    
    # Check if it's a dataset registry ID
    if is_dataset_available(dataset_identifier):
        # Try to get cached version first
        cached_path = get_cached_dataset_path(dataset_identifier, config.DATASET_CACHE_DIR)
        if cached_path:
            return str(cached_path)
        
        # Download the dataset
        print(f"{Fore.GREEN}[+] Dataset '{dataset_identifier}' not cached, downloading...")
        url = get_dataset_url(dataset_identifier)
        expected_hash = get_dataset_hash(dataset_identifier)
        
        downloaded_path = download_dataset(
            dataset_identifier,
            url,
            expected_hash,
            force_download=config.FORCE_DATASET_DOWNLOAD,
            cache_dir=config.DATASET_CACHE_DIR,
            show_progress=config.SHOW_DOWNLOAD_PROGRESS
        )
        
        if downloaded_path:
            return str(downloaded_path)
        else:
            print(f"{Fore.RED}[!] Failed to download dataset '{dataset_identifier}'")
            return None
    
    print(f"{Fore.RED}[!] Unknown dataset identifier: '{dataset_identifier}'")
    return None


def get_seed_prompts_dataset_path() -> Optional[str]:
    """
    Get the path to the seed prompts dataset based on configuration.
    
    Returns:
        Path to the dataset file, or None if not available
    """
    # First try the new dataset configuration
    if hasattr(config, 'SEED_PROMPT_DATASET') and config.SEED_PROMPT_DATASET:
        dataset_path = resolve_dataset_path(config.SEED_PROMPT_DATASET)
        if dataset_path:
            return dataset_path
    
    # Fall back to legacy file path configuration
    if hasattr(config, 'SEED_PROMPT_INPUT_FILE_PATH') and config.SEED_PROMPT_INPUT_FILE_PATH:
        legacy_path = config.SEED_PROMPT_INPUT_FILE_PATH
        if os.path.exists(legacy_path):
            print(f"{Fore.YELLOW}[!] Using legacy file path configuration: {legacy_path}")
            return legacy_path
    
    print(f"{Fore.RED}[!] No valid seed prompts dataset configured")
    return None


def read_seed_prompts_from_csv(path_to_seed_prompts_csv_file: Optional[str] = None) -> List[Tuple[str, str]]:
    """
    Reads seed prompts and responses from a CSV file or dataset.

    Args:
        path_to_seed_prompts_csv_file: Optional path to CSV file or dataset ID. 
                                     If None, uses configuration to determine dataset.

    Returns:
        List of tuples where each tuple contains a prompt and its corresponding response.
    """
    # If no path provided, try to resolve from configuration
    if path_to_seed_prompts_csv_file is None:
        path_to_seed_prompts_csv_file = get_seed_prompts_dataset_path()
        if path_to_seed_prompts_csv_file is None:
            print(f"{Fore.RED}[!] No seed prompts dataset available")
            return []
    else:
        # If path is provided but might be a dataset ID, try to resolve it
        resolved_path = resolve_dataset_path(path_to_seed_prompts_csv_file)
        if resolved_path:
            path_to_seed_prompts_csv_file = resolved_path
        elif not os.path.exists(path_to_seed_prompts_csv_file):
            print(f"{Fore.RED}[!] Dataset path could not be resolved: {path_to_seed_prompts_csv_file}")
            return []

    seed_prompt_response_tuples = []

    print(f"{Fore.GREEN}[+] Will try reading seed prompts/responses from {path_to_seed_prompts_csv_file}...")

    try:
        with open(path_to_seed_prompts_csv_file, 'r') as file:
            reader = csv.reader(file)
            num_rows = sum(1 for _ in reader)

            file.seek(0)  # Reset file pointer

            print(f"{Fore.GREEN}[+] Reading seed prompts/responses from {path_to_seed_prompts_csv_file}...")

            print(f"{Fore.GREEN}[+] Appending {num_rows} seed prompts/responses to seed_prompt_response_tuples list", end='')

            line_num = 0  # Track line number manually

            for row in reader:
                line_num += 1

                if not row:
                    print(f"{Fore.RED}[!] Error: Seed prompts CSV file contains empty rows.")
                    continue

                if len(row) < 1:
                    print(f"{Fore.RED}[!] Error: Seed prompts CSV file contains rows with no columns.")
                    continue

                if line_num == 1:
                    continue

                # TODO: Append and propagate the response also. It will require pairs of prompts and responses.
                # Put prompt and response pairs into a tuple
                seed_prompt_response_tuples.append((row[0], row[1]))  # First column is prompt and second column is response


                # Append seed attack prompt to list, not the response though
                # TODO: This is an experimental bugfix, need to add support for response propagation
                # seed_prompt_response_tuples.append(row[0])

                # Print progress with dots
                print(f"{Fore.GREEN}.", end="")

            print(f'{Fore.GREEN}\n[+] Finished creating seed attack prompt/response list.')

            if len(seed_prompt_response_tuples) > 0:
                print(f"{Fore.GREEN}[+] Seed attack prompt/response list successfully created with {len(seed_prompt_response_tuples)} prompts.")
            else:
                print(f"{Fore.RED}[!] Seed attack prompt/response list is empty, please check the CSV file and try again.")

    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Seed attack prompt/response CSV file '{path_to_seed_prompts_csv_file}' not found.")
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading seed attack prompts/responses from CSV file: {e}")

    # Return the seed prompts
    return seed_prompt_response_tuples
