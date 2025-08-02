#!/usr/bin/env python3

import os
import json
import hashlib
import requests
import time
import urllib3
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from colorama import Fore

# Disable SSL warnings when using insecure mode
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default configuration
DEFAULT_CACHE_DIR = Path.home() / ".ablitafuzzer" / "cache"
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BASE_DELAY = 1
MAX_CACHE_AGE_DAYS = 7
PROGRESS_THRESHOLD_MB = 5


def get_cache_directories(cache_dir: Optional[str] = None) -> Tuple[Path, Path, Path]:
    """
    Get cache directory paths.
    
    Args:
        cache_dir: Optional custom cache directory path
        
    Returns:
        Tuple of (cache_dir, datasets_dir, metadata_file) paths
    """
    cache_path = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
    datasets_path = cache_path / "datasets"
    metadata_file = datasets_path / "metadata.json"
    
    # Create directories if they don't exist
    datasets_path.mkdir(parents=True, exist_ok=True)
    
    return cache_path, datasets_path, metadata_file


def load_cache_metadata(metadata_file: Path) -> Dict[str, Any]:
    """
    Load metadata from cache file.
    
    Args:
        metadata_file: Path to metadata JSON file
        
    Returns:
        Dictionary containing cache metadata
    """
    try:
        if metadata_file.exists():
            with open(metadata_file, 'r') as f:
                return json.load(f)
        return {}
    except (json.JSONDecodeError, OSError) as e:
        print(f"{Fore.YELLOW}[!] Warning: Could not load cache metadata: {e}")
        return {}


def save_cache_metadata(metadata_file: Path, metadata: Dict[str, Any]) -> None:
    """
    Save metadata to cache file.
    
    Args:
        metadata_file: Path to metadata JSON file
        metadata: Dictionary containing cache metadata
    """
    try:
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        # Set appropriate permissions
        os.chmod(metadata_file, 0o600)
    except OSError as e:
        print(f"{Fore.RED}[!] Error saving cache metadata: {e}")


def calculate_file_hash(filepath: Path) -> str:
    """
    Calculate SHA256 hash of a file.
    
    Args:
        filepath: Path to file to hash
        
    Returns:
        SHA256 hash as hexadecimal string
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except OSError as e:
        print(f"{Fore.RED}[!] Error calculating file hash: {e}")
        return ""


def is_cache_valid(dataset_name: str, metadata: Dict[str, Any], datasets_dir: Path,
                  expected_hash: Optional[str] = None, max_age_days: int = MAX_CACHE_AGE_DAYS) -> bool:
    """
    Check if cached dataset is valid and not expired.
    
    Args:
        dataset_name: Name of the dataset
        metadata: Cache metadata dictionary
        datasets_dir: Path to datasets directory
        expected_hash: Expected SHA256 hash for verification
        max_age_days: Maximum age in days before cache expires
        
    Returns:
        True if cache is valid, False otherwise
    """
    cache_entry = metadata.get(dataset_name)
    if not cache_entry:
        return False
    
    cached_file = datasets_dir / cache_entry['filename']
    if not cached_file.exists():
        return False
    
    # Check age
    download_time = cache_entry.get('download_time', 0)
    if time.time() - download_time > (max_age_days * 24 * 3600):
        return False
    
    # Check hash if provided
    if expected_hash and cache_entry.get('hash') != expected_hash:
        return False
    
    return True


def download_file_with_retry(url: str, filepath: Path, timeout: int = DEFAULT_TIMEOUT,
                           show_progress: bool = True, verify_ssl: bool = True,
                           proxies: Optional[Dict[str, str]] = None) -> bool:
    """
    Download file with retry logic and exponential backoff.
    
    Args:
        url: URL to download from
        filepath: Local path to save file
        timeout: Request timeout in seconds
        show_progress: Whether to show progress for large files
        verify_ssl: Whether to verify SSL certificates
        proxies: Optional proxy configuration
        
    Returns:
        True if download succeeded, False otherwise
    """
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, timeout=timeout, stream=True, 
                                  verify=verify_ssl, proxies=proxies)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        
                        # Show progress for large files
                        if (show_progress and total_size > 0 and 
                            total_size > PROGRESS_THRESHOLD_MB * 1024 * 1024):
                            percent = (downloaded_size / total_size) * 100
                            print(f"\r{Fore.GREEN}[+] Downloaded {downloaded_size}/{total_size} "
                                 f"bytes ({percent:.1f}%)", end='')
            
            if show_progress and total_size > PROGRESS_THRESHOLD_MB * 1024 * 1024:
                print()  # New line after progress
            
            # Set appropriate file permissions
            os.chmod(filepath, 0o600)
            return True
            
        except requests.exceptions.RequestException as e:
            if attempt < MAX_RETRIES - 1:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                print(f"{Fore.YELLOW}[!] Download attempt {attempt + 1} failed: {e}")
                print(f"{Fore.YELLOW}[!] Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                print(f"{Fore.RED}[!] Download failed after {MAX_RETRIES} attempts: {e}")
                return False
        except OSError as e:
            print(f"{Fore.RED}[!] File system error during download: {e}")
            return False
    
    return False


def download_dataset(dataset_name: str, url: str, expected_hash: Optional[str] = None,
                    force_download: bool = False, cache_dir: Optional[str] = None,
                    show_progress: bool = True, verify_ssl: bool = True,
                    proxies: Optional[Dict[str, str]] = None) -> Optional[Path]:
    """
    Download a dataset from URL and cache it locally.
    
    Args:
        dataset_name: Name identifier for the dataset
        url: URL to download from
        expected_hash: Expected SHA256 hash for verification
        force_download: Force download even if cached version exists
        cache_dir: Optional custom cache directory
        show_progress: Show download progress for large files
        verify_ssl: Whether to verify SSL certificates
        proxies: Optional proxy configuration
        
    Returns:
        Path to the cached file, or None if download failed
    """
    cache_path, datasets_dir, metadata_file = get_cache_directories(cache_dir)
    metadata = load_cache_metadata(metadata_file)
    
    # Check if we have a valid cached version
    if not force_download and is_cache_valid(dataset_name, metadata, datasets_dir, expected_hash):
        cached_file = datasets_dir / metadata[dataset_name]['filename']
        print(f"{Fore.GREEN}[+] Using cached dataset: {cached_file}")
        return cached_file
    
    # Determine filename from URL or use dataset name
    filename = dataset_name + ".csv"  # Default to CSV extension
    if url.endswith('.csv'):
        filename = url.split('/')[-1]
    elif '.' in url.split('/')[-1]:
        filename = url.split('/')[-1]
    
    filepath = datasets_dir / filename
    
    print(f"{Fore.GREEN}[+] Downloading dataset '{dataset_name}' from {url}")
    
    # Attempt download
    if download_file_with_retry(url, filepath, show_progress=show_progress, 
                               verify_ssl=verify_ssl, proxies=proxies):
        
        # Verify hash if provided
        if expected_hash:
            actual_hash = calculate_file_hash(filepath)
            if actual_hash != expected_hash:
                print(f"{Fore.RED}[!] Hash verification failed for {dataset_name}")
                print(f"{Fore.RED}[!] Expected: {expected_hash}")
                print(f"{Fore.RED}[!] Actual: {actual_hash}")
                try:
                    filepath.unlink()  # Remove corrupted file
                except OSError:
                    pass
                return None
        
        # Update metadata
        file_hash = calculate_file_hash(filepath) if not expected_hash else expected_hash
        metadata[dataset_name] = {
            'filename': filename,
            'url': url,
            'download_time': time.time(),
            'hash': file_hash,
            'size_bytes': filepath.stat().st_size
        }
        save_cache_metadata(metadata_file, metadata)
        
        print(f"{Fore.GREEN}[+] Successfully downloaded and cached dataset '{dataset_name}'")
        return filepath
    
    return None


def get_cached_dataset_path(dataset_name: str, cache_dir: Optional[str] = None) -> Optional[Path]:
    """
    Get path to cached dataset if it exists and is valid.
    
    Args:
        dataset_name: Name of the dataset
        cache_dir: Optional custom cache directory
        
    Returns:
        Path to cached file, or None if not available
    """
    cache_path, datasets_dir, metadata_file = get_cache_directories(cache_dir)
    metadata = load_cache_metadata(metadata_file)
    
    if is_cache_valid(dataset_name, metadata, datasets_dir):
        return datasets_dir / metadata[dataset_name]['filename']
    return None


def clear_dataset_cache(dataset_name: Optional[str] = None, cache_dir: Optional[str] = None) -> None:
    """
    Clear cache for specific dataset or all datasets.
    
    Args:
        dataset_name: Name of dataset to clear, or None to clear all
        cache_dir: Optional custom cache directory
    """
    cache_path, datasets_dir, metadata_file = get_cache_directories(cache_dir)
    metadata = load_cache_metadata(metadata_file)
    
    if dataset_name:
        if dataset_name in metadata:
            cached_file = datasets_dir / metadata[dataset_name]['filename']
            try:
                if cached_file.exists():
                    cached_file.unlink()
                del metadata[dataset_name]
                save_cache_metadata(metadata_file, metadata)
                print(f"{Fore.GREEN}[+] Cleared cache for dataset '{dataset_name}'")
            except OSError as e:
                print(f"{Fore.RED}[!] Error clearing cache for '{dataset_name}': {e}")
        else:
            print(f"{Fore.YELLOW}[!] Dataset '{dataset_name}' not found in cache")
    else:
        # Clear all cached files
        try:
            for file in datasets_dir.glob("*"):
                if file.is_file() and file.name != "metadata.json":
                    file.unlink()
            save_cache_metadata(metadata_file, {})
            print(f"{Fore.GREEN}[+] Cleared all cached datasets")
        except OSError as e:
            print(f"{Fore.RED}[!] Error clearing cache: {e}")


def get_cache_status(cache_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Get information about cached datasets.
    
    Args:
        cache_dir: Optional custom cache directory
        
    Returns:
        Dictionary with cache status information
    """
    cache_path, datasets_dir, metadata_file = get_cache_directories(cache_dir)
    metadata = load_cache_metadata(metadata_file)
    
    total_size = 0
    valid_datasets = 0
    
    for dataset_name, info in metadata.items():
        cached_file = datasets_dir / info['filename']
        if cached_file.exists():
            try:
                total_size += cached_file.stat().st_size
                if is_cache_valid(dataset_name, metadata, datasets_dir):
                    valid_datasets += 1
            except OSError:
                continue
    
    return {
        'cache_dir': str(cache_path),
        'total_datasets': len(metadata),
        'valid_datasets': valid_datasets,
        'total_size_bytes': total_size,
        'total_size_mb': round(total_size / (1024 * 1024), 2)
    }


def list_cached_datasets(cache_dir: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    List all cached datasets with their information.
    
    Args:
        cache_dir: Optional custom cache directory
        
    Returns:
        Dictionary mapping dataset names to their information
    """
    cache_path, datasets_dir, metadata_file = get_cache_directories(cache_dir)
    metadata = load_cache_metadata(metadata_file)
    result = {}
    
    for dataset_name, info in metadata.items():
        cached_file = datasets_dir / info['filename']
        result[dataset_name] = {
            'filename': info['filename'],
            'url': info['url'],
            'download_time': info['download_time'],
            'size_bytes': info['size_bytes'],
            'exists': cached_file.exists(),
            'valid': is_cache_valid(dataset_name, metadata, datasets_dir)
        }
    
    return result


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Dataset download and cache manager')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Download command
    download_parser = subparsers.add_parser('download', help='Download a dataset')
    download_parser.add_argument('name', help='Dataset name')
    download_parser.add_argument('url', help='Dataset URL')
    download_parser.add_argument('--hash', help='Expected SHA256 hash')
    download_parser.add_argument('--force', action='store_true', help='Force download')
    download_parser.add_argument('--cache-dir', help='Custom cache directory')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show cache status')
    status_parser.add_argument('--cache-dir', help='Custom cache directory')
    
    # Clear command
    clear_parser = subparsers.add_parser('clear', help='Clear cache')
    clear_parser.add_argument('name', nargs='?', help='Dataset name (optional)')
    clear_parser.add_argument('--cache-dir', help='Custom cache directory')
    
    args = parser.parse_args()
    
    if args.command == 'download':
        result = download_dataset(args.name, args.url, args.hash, args.force, args.cache_dir)
        if result:
            print(f"Dataset cached at: {result}")
        else:
            exit(1)
    elif args.command == 'status':
        status = get_cache_status(args.cache_dir)
        print(f"Cache directory: {status['cache_dir']}")
        print(f"Total datasets: {status['total_datasets']}")
        print(f"Valid datasets: {status['valid_datasets']}")
        print(f"Total size: {status['total_size_mb']} MB")
    elif args.command == 'clear':
        clear_dataset_cache(args.name, args.cache_dir)
    else:
        parser.print_help()