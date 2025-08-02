#!/usr/bin/env python3

import unittest
import tempfile
import shutil
import json
import os
from pathlib import Path
from unittest.mock import patch, Mock, mock_open
import requests

from utilities.download_manager import (
    download_dataset, get_cached_dataset_path, clear_dataset_cache,
    get_cache_status, list_cached_datasets, download_file_with_retry,
    load_cache_metadata, save_cache_metadata, calculate_file_hash,
    is_cache_valid, get_cache_directories
)


class TestDownloadManager(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures with temporary directory."""
        self.test_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.test_dir) / "test_cache"
        self.datasets_dir = self.cache_dir / "datasets"
        self.metadata_file = self.datasets_dir / "metadata.json"
        
        # Create test directories
        self.datasets_dir.mkdir(parents=True, exist_ok=True)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_get_cache_directories(self):
        """Test cache directory creation and path resolution."""
        cache_path, datasets_path, metadata_path = get_cache_directories(str(self.cache_dir))
        
        self.assertEqual(cache_path, self.cache_dir)
        self.assertEqual(datasets_path, self.datasets_dir)
        self.assertEqual(metadata_path, self.metadata_file)
        self.assertTrue(datasets_path.exists())
    
    def test_load_save_cache_metadata(self):
        """Test loading and saving cache metadata."""
        test_metadata = {
            "test_dataset": {
                "filename": "test.csv",
                "url": "https://example.com/test.csv",
                "download_time": 1234567890,
                "hash": "abcd1234",
                "size_bytes": 1024
            }
        }
        
        # Test save
        save_cache_metadata(self.metadata_file, test_metadata)
        self.assertTrue(self.metadata_file.exists())
        
        # Test load
        loaded_metadata = load_cache_metadata(self.metadata_file)
        self.assertEqual(loaded_metadata, test_metadata)
    
    def test_load_cache_metadata_missing_file(self):
        """Test loading metadata when file doesn't exist."""
        nonexistent_file = self.datasets_dir / "nonexistent.json"
        metadata = load_cache_metadata(nonexistent_file)
        self.assertEqual(metadata, {})
    
    def test_calculate_file_hash(self):
        """Test file hash calculation."""
        test_content = b"test content for hashing"
        test_file = self.datasets_dir / "test_hash.txt"
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        file_hash = calculate_file_hash(test_file)
        self.assertIsInstance(file_hash, str)
        self.assertEqual(len(file_hash), 64)  # SHA256 hex length
    
    def test_is_cache_valid_fresh_file(self):
        """Test cache validation with fresh file."""
        # Create test file and metadata
        test_file = self.datasets_dir / "fresh_test.csv"
        test_content = b"test,data\n1,2\n"
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        file_hash = calculate_file_hash(test_file)
        metadata = {
            "fresh_test": {
                "filename": "fresh_test.csv",
                "download_time": 9999999999,  # Far future time
                "hash": file_hash
            }
        }
        
        self.assertTrue(is_cache_valid("fresh_test", metadata, self.datasets_dir))
    
    def test_is_cache_valid_expired_file(self):
        """Test cache validation with expired file."""
        test_file = self.datasets_dir / "expired_test.csv"
        test_content = b"test,data\n1,2\n"
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        metadata = {
            "expired_test": {
                "filename": "expired_test.csv",
                "download_time": 0,  # Very old time
                "hash": "somehash"
            }
        }
        
        self.assertFalse(is_cache_valid("expired_test", metadata, self.datasets_dir, max_age_days=1))
    
    def test_is_cache_valid_missing_file(self):
        """Test cache validation with missing file."""
        metadata = {
            "missing_test": {
                "filename": "missing_file.csv",
                "download_time": 9999999999,
                "hash": "somehash"
            }
        }
        
        self.assertFalse(is_cache_valid("missing_test", metadata, self.datasets_dir))
    
    @patch('utilities.download_manager.requests.get')
    def test_download_file_with_retry_success(self, mock_get):
        """Test successful file download."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '100'}
        mock_response.iter_content.return_value = [b'test data chunk 1', b'test data chunk 2']
        mock_get.return_value = mock_response
        
        test_file = self.datasets_dir / "download_test.csv"
        
        result = download_file_with_retry("https://example.com/test.csv", test_file, show_progress=False)
        
        self.assertTrue(result)
        self.assertTrue(test_file.exists())
        
        with open(test_file, 'rb') as f:
            content = f.read()
            self.assertEqual(content, b'test data chunk 1test data chunk 2')
    
    @patch('utilities.download_manager.requests.get')
    def test_download_file_with_retry_failure(self, mock_get):
        """Test file download with network failure."""
        # Mock network failure
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        
        test_file = self.datasets_dir / "failed_download.csv"
        
        result = download_file_with_retry("https://example.com/test.csv", test_file, show_progress=False)
        
        self.assertFalse(result)
        self.assertFalse(test_file.exists())
    
    @patch('utilities.download_manager.requests.get')
    @patch('utilities.download_manager.time.sleep')  # Mock sleep to speed up test
    def test_download_file_with_retry_eventually_succeeds(self, mock_sleep, mock_get):
        """Test file download that fails initially but eventually succeeds."""
        # First two calls fail, third succeeds
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '10'}
        mock_response.iter_content.return_value = [b'success']
        
        mock_get.side_effect = [
            requests.exceptions.RequestException("First failure"),
            requests.exceptions.RequestException("Second failure"),
            mock_response
        ]
        
        test_file = self.datasets_dir / "retry_test.csv"
        
        result = download_file_with_retry("https://example.com/test.csv", test_file, show_progress=False)
        
        self.assertTrue(result)
        self.assertTrue(test_file.exists())
        self.assertEqual(mock_get.call_count, 3)
        self.assertEqual(mock_sleep.call_count, 2)  # Sleep called after first two failures
    
    @patch('utilities.download_manager.download_file_with_retry')
    @patch('utilities.download_manager.calculate_file_hash')
    def test_download_dataset_success(self, mock_hash, mock_download):
        """Test successful dataset download and caching."""
        mock_download.return_value = True
        mock_hash.return_value = "testhash123"
        
        result = download_dataset(
            "test_dataset",
            "https://example.com/test.csv", 
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNotNone(result)
        self.assertTrue(result.name.endswith(".csv"))
        
        # Check metadata was saved
        metadata = load_cache_metadata(self.metadata_file)
        self.assertIn("test_dataset", metadata)
        self.assertEqual(metadata["test_dataset"]["url"], "https://example.com/test.csv")
    
    @patch('utilities.download_manager.download_file_with_retry')
    def test_download_dataset_failure(self, mock_download):
        """Test failed dataset download."""
        mock_download.return_value = False
        
        result = download_dataset(
            "failed_dataset",
            "https://example.com/nonexistent.csv",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNone(result)
    
    @patch('utilities.download_manager.download_file_with_retry')
    @patch('utilities.download_manager.calculate_file_hash')
    def test_download_dataset_hash_verification_failure(self, mock_hash, mock_download):
        """Test dataset download with hash verification failure."""
        mock_download.return_value = True
        mock_hash.return_value = "wronghash"
        
        result = download_dataset(
            "hash_fail_dataset",
            "https://example.com/test.csv",
            expected_hash="expectedhash123",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNone(result)
    
    def test_get_cached_dataset_path_exists(self):
        """Test getting path to cached dataset that exists."""
        # Create test file and metadata
        test_file = self.datasets_dir / "cached_test.csv"
        test_content = b"cached,data\n1,2\n"
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        metadata = {
            "cached_test": {
                "filename": "cached_test.csv",
                "download_time": 9999999999,  # Far future
                "hash": calculate_file_hash(test_file)
            }
        }
        save_cache_metadata(self.metadata_file, metadata)
        
        result = get_cached_dataset_path("cached_test", str(self.cache_dir))
        self.assertEqual(result, test_file)
    
    def test_get_cached_dataset_path_missing(self):
        """Test getting path to cached dataset that doesn't exist."""
        result = get_cached_dataset_path("nonexistent_dataset", str(self.cache_dir))
        self.assertIsNone(result)
    
    def test_clear_dataset_cache_specific(self):
        """Test clearing cache for specific dataset."""
        # Create test file and metadata
        test_file = self.datasets_dir / "clear_test.csv"
        test_content = b"test,data\n"
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        metadata = {
            "clear_test": {
                "filename": "clear_test.csv",
                "download_time": 1234567890,
                "hash": "testhash"
            },
            "keep_test": {
                "filename": "keep_test.csv", 
                "download_time": 1234567890,
                "hash": "keephash"
            }
        }
        save_cache_metadata(self.metadata_file, metadata)
        
        clear_dataset_cache("clear_test", str(self.cache_dir))
        
        # Check file was removed and metadata updated
        self.assertFalse(test_file.exists())
        updated_metadata = load_cache_metadata(self.metadata_file)
        self.assertNotIn("clear_test", updated_metadata)
        self.assertIn("keep_test", updated_metadata)
    
    def test_clear_dataset_cache_all(self):
        """Test clearing all cached datasets."""
        # Create test files
        test_file1 = self.datasets_dir / "clear_all_1.csv"
        test_file2 = self.datasets_dir / "clear_all_2.csv"
        
        with open(test_file1, 'w') as f:
            f.write("test1")
        with open(test_file2, 'w') as f:
            f.write("test2")
        
        metadata = {
            "dataset1": {"filename": "clear_all_1.csv"},
            "dataset2": {"filename": "clear_all_2.csv"}
        }
        save_cache_metadata(self.metadata_file, metadata)
        
        clear_dataset_cache(None, str(self.cache_dir))
        
        # Check all files removed and metadata cleared
        self.assertFalse(test_file1.exists())
        self.assertFalse(test_file2.exists())
        updated_metadata = load_cache_metadata(self.metadata_file)
        self.assertEqual(updated_metadata, {})
    
    def test_get_cache_status(self):
        """Test getting cache status information."""
        # Create test files
        test_file1 = self.datasets_dir / "status_test1.csv"
        test_file2 = self.datasets_dir / "status_test2.csv"
        
        with open(test_file1, 'w') as f:
            f.write("a" * 100)  # 100 bytes
        with open(test_file2, 'w') as f:
            f.write("b" * 200)  # 200 bytes
        
        metadata = {
            "dataset1": {
                "filename": "status_test1.csv",
                "download_time": 9999999999  # Valid
            },
            "dataset2": {
                "filename": "status_test2.csv", 
                "download_time": 0  # Expired
            }
        }
        save_cache_metadata(self.metadata_file, metadata)
        
        status = get_cache_status(str(self.cache_dir))
        
        self.assertEqual(status['total_datasets'], 2)
        self.assertEqual(status['valid_datasets'], 1)
        self.assertEqual(status['total_size_bytes'], 300)
        self.assertEqual(status['total_size_mb'], 0.0)  # Rounds to 0.0
    
    def test_list_cached_datasets(self):
        """Test listing cached datasets with their information."""
        # Create test file
        test_file = self.datasets_dir / "list_test.csv"
        with open(test_file, 'w') as f:
            f.write("test data")
        
        metadata = {
            "list_dataset": {
                "filename": "list_test.csv",
                "url": "https://example.com/test.csv",
                "download_time": 9999999999,
                "size_bytes": 9
            }
        }
        save_cache_metadata(self.metadata_file, metadata)
        
        result = list_cached_datasets(str(self.cache_dir))
        
        self.assertIn("list_dataset", result)
        dataset_info = result["list_dataset"]
        self.assertEqual(dataset_info["filename"], "list_test.csv")
        self.assertEqual(dataset_info["url"], "https://example.com/test.csv")
        self.assertEqual(dataset_info["size_bytes"], 9)
        self.assertTrue(dataset_info["exists"])
        self.assertTrue(dataset_info["valid"])


if __name__ == '__main__':
    unittest.main()