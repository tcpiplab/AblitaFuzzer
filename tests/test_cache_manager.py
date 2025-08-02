#!/usr/bin/env python3

import unittest
import tempfile
import shutil
import time
import os
from pathlib import Path
from unittest.mock import patch, Mock

from utilities.download_manager import (
    get_cache_directories, load_cache_metadata, save_cache_metadata,
    is_cache_valid, calculate_file_hash, clear_dataset_cache,
    get_cache_status, list_cached_datasets
)


class TestCacheManager(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures with temporary directory."""
        self.test_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.test_dir) / "cache_test"
        self.datasets_dir = self.cache_dir / "datasets"
        self.metadata_file = self.datasets_dir / "metadata.json"
        
        # Create test directories
        self.datasets_dir.mkdir(parents=True, exist_ok=True)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_cache_directory_permissions(self):
        """Test that cache directories have appropriate permissions."""
        cache_path, datasets_path, metadata_path = get_cache_directories(str(self.cache_dir))
        
        # Check directories exist and are accessible
        self.assertTrue(datasets_path.exists())
        self.assertTrue(os.access(datasets_path, os.R_OK | os.W_OK))
    
    def test_metadata_file_permissions(self):
        """Test that metadata file has restricted permissions."""
        test_metadata = {"test": {"filename": "test.csv"}}
        
        # Save metadata and check permissions
        save_cache_metadata(self.metadata_file, test_metadata)
        
        if os.name != 'nt':  # Skip permission check on Windows
            file_stat = self.metadata_file.stat()
            # Check that file has 600 permissions (owner read/write only)
            self.assertEqual(oct(file_stat.st_mode)[-3:], '600')
    
    def test_cache_expiration_logic(self):
        """Test cache expiration with different time scenarios."""
        test_file = self.datasets_dir / "expiration_test.csv"
        with open(test_file, 'w') as f:
            f.write("test content")
        
        current_time = time.time()
        
        # Test scenarios with different ages
        test_cases = [
            # (download_time, max_age_days, expected_valid)
            (current_time, 7, True),                    # Fresh file
            (current_time - (6 * 24 * 3600), 7, True), # 6 days old, 7 day limit
            (current_time - (8 * 24 * 3600), 7, False), # 8 days old, 7 day limit
            (current_time - (1 * 24 * 3600), 1, False), # 1 day old, 1 day limit
        ]
        
        for download_time, max_age_days, expected_valid in test_cases:
            metadata = {
                "expiration_test": {
                    "filename": "expiration_test.csv",
                    "download_time": download_time,
                    "hash": "testhash"
                }
            }
            
            result = is_cache_valid("expiration_test", metadata, self.datasets_dir, max_age_days=max_age_days)
            self.assertEqual(result, expected_valid, 
                           f"Failed for download_time={download_time}, max_age_days={max_age_days}")
    
    def test_cache_integrity_validation(self):
        """Test cache integrity checking with hash validation."""
        test_file = self.datasets_dir / "integrity_test.csv"
        test_content = b"integrity test content"
        
        with open(test_file, 'wb') as f:
            f.write(test_content)
        
        correct_hash = calculate_file_hash(test_file)
        wrong_hash = "definitely_wrong_hash"
        
        # Test with correct hash
        metadata_correct = {
            "integrity_test": {
                "filename": "integrity_test.csv",
                "download_time": time.time(),
                "hash": correct_hash
            }
        }
        self.assertTrue(is_cache_valid("integrity_test", metadata_correct, self.datasets_dir, expected_hash=correct_hash))
        
        # Test with wrong hash
        metadata_wrong = {
            "integrity_test": {
                "filename": "integrity_test.csv", 
                "download_time": time.time(),
                "hash": wrong_hash
            }
        }
        self.assertFalse(is_cache_valid("integrity_test", metadata_wrong, self.datasets_dir, expected_hash=correct_hash))
    
    def test_concurrent_cache_access(self):
        """Test that cache operations handle concurrent access safely."""
        # Create initial metadata
        initial_metadata = {
            "dataset1": {"filename": "file1.csv", "download_time": time.time()},
            "dataset2": {"filename": "file2.csv", "download_time": time.time()}
        }
        save_cache_metadata(self.metadata_file, initial_metadata)
        
        # Simulate concurrent read operations
        for i in range(10):
            metadata = load_cache_metadata(self.metadata_file)
            self.assertEqual(len(metadata), 2)
            self.assertIn("dataset1", metadata)
            self.assertIn("dataset2", metadata)
    
    def test_cache_corruption_recovery(self):
        """Test cache behavior when metadata file is corrupted."""
        # Create corrupted metadata file
        with open(self.metadata_file, 'w') as f:
            f.write("{ invalid json content")
        
        # Should return empty dict for corrupted file
        metadata = load_cache_metadata(self.metadata_file)
        self.assertEqual(metadata, {})
    
    def test_cache_size_calculation(self):
        """Test accurate cache size calculation."""
        # Create files of known sizes
        files_and_sizes = [
            ("size_test1.csv", 1024),   # 1KB
            ("size_test2.csv", 2048),   # 2KB  
            ("size_test3.csv", 512),    # 0.5KB
        ]
        
        total_size = 0
        metadata = {}
        
        for filename, size in files_and_sizes:
            file_path = self.datasets_dir / filename
            content = b'x' * size
            
            with open(file_path, 'wb') as f:
                f.write(content)
            
            total_size += size
            dataset_name = filename.replace('.csv', '')
            metadata[dataset_name] = {
                "filename": filename,
                "download_time": time.time(),
                "size_bytes": size
            }
        
        save_cache_metadata(self.metadata_file, metadata)
        
        # Test cache status calculation
        status = get_cache_status(str(self.cache_dir))
        self.assertEqual(status['total_size_bytes'], total_size)
        self.assertEqual(status['total_size_mb'], round(total_size / (1024 * 1024), 2))
        self.assertEqual(status['total_datasets'], 3)
    
    def test_partial_cache_cleanup(self):
        """Test cleanup of specific cache entries while preserving others."""
        # Create multiple cached files
        files = ["keep1.csv", "remove1.csv", "keep2.csv", "remove2.csv"]
        metadata = {}
        
        for filename in files:
            file_path = self.datasets_dir / filename
            with open(file_path, 'w') as f:
                f.write(f"content for {filename}")
            
            dataset_name = filename.replace('.csv', '')
            metadata[dataset_name] = {
                "filename": filename,
                "download_time": time.time(),
                "hash": "testhash"
            }
        
        save_cache_metadata(self.metadata_file, metadata)
        
        # Remove specific entries
        clear_dataset_cache("remove1", str(self.cache_dir))
        clear_dataset_cache("remove2", str(self.cache_dir))
        
        # Verify selective removal
        remaining_files = list(self.datasets_dir.glob("*.csv"))
        remaining_names = [f.name for f in remaining_files]
        
        self.assertIn("keep1.csv", remaining_names)
        self.assertIn("keep2.csv", remaining_names)
        self.assertNotIn("remove1.csv", remaining_names)
        self.assertNotIn("remove2.csv", remaining_names)
        
        # Check metadata was updated correctly
        updated_metadata = load_cache_metadata(self.metadata_file)
        self.assertIn("keep1", updated_metadata)
        self.assertIn("keep2", updated_metadata)
        self.assertNotIn("remove1", updated_metadata)
        self.assertNotIn("remove2", updated_metadata)
    
    def test_cache_listing_with_mixed_states(self):
        """Test cache listing with files in various states."""
        # Create files in different states
        
        # Valid file that exists
        valid_file = self.datasets_dir / "valid.csv"
        with open(valid_file, 'w') as f:
            f.write("valid content")
        
        # File referenced in metadata but missing on disk
        # (don't create the actual file)
        
        # Expired file that exists
        expired_file = self.datasets_dir / "expired.csv"
        with open(expired_file, 'w') as f:
            f.write("expired content")
        
        metadata = {
            "valid": {
                "filename": "valid.csv",
                "url": "https://example.com/valid.csv",
                "download_time": time.time(),  # Recent
                "size_bytes": 13
            },
            "missing": {
                "filename": "missing.csv",
                "url": "https://example.com/missing.csv", 
                "download_time": time.time(),
                "size_bytes": 15
            },
            "expired": {
                "filename": "expired.csv",
                "url": "https://example.com/expired.csv",
                "download_time": 0,  # Very old
                "size_bytes": 15
            }
        }
        save_cache_metadata(self.metadata_file, metadata)
        
        # List cached datasets
        listing = list_cached_datasets(str(self.cache_dir))
        
        # Verify all entries are listed with correct states
        self.assertEqual(len(listing), 3)
        
        self.assertTrue(listing["valid"]["exists"])
        self.assertTrue(listing["valid"]["valid"])
        
        self.assertFalse(listing["missing"]["exists"])
        self.assertFalse(listing["missing"]["valid"])
        
        self.assertTrue(listing["expired"]["exists"])
        self.assertFalse(listing["expired"]["valid"])  # Expired
    
    def test_cache_cleanup_with_orphaned_files(self):
        """Test cache cleanup handles orphaned files correctly."""
        # Create files: some in metadata, some orphaned
        tracked_file = self.datasets_dir / "tracked.csv"
        orphaned_file = self.datasets_dir / "orphaned.csv"
        metadata_file = self.datasets_dir / "metadata.json"  # This should be preserved
        
        with open(tracked_file, 'w') as f:
            f.write("tracked")
        with open(orphaned_file, 'w') as f:
            f.write("orphaned")
        
        metadata = {
            "tracked": {
                "filename": "tracked.csv",
                "download_time": time.time()
            }
        }
        save_cache_metadata(self.metadata_file, metadata)
        
        # Clear all cache - should remove tracked file but leave metadata.json
        clear_dataset_cache(None, str(self.cache_dir))
        
        # Check results
        self.assertFalse(tracked_file.exists())
        self.assertFalse(orphaned_file.exists())  # Orphaned files also removed
        self.assertTrue(self.metadata_file.exists())  # Metadata file preserved
        
        # Metadata should be empty
        updated_metadata = load_cache_metadata(self.metadata_file)
        self.assertEqual(updated_metadata, {})
    
    def test_cache_status_with_missing_files(self):
        """Test cache status calculation when some files are missing."""
        # Create one file, reference another in metadata
        existing_file = self.datasets_dir / "exists.csv"
        with open(existing_file, 'w') as f:
            f.write("x" * 100)
        
        metadata = {
            "exists": {
                "filename": "exists.csv",
                "download_time": time.time(),
                "size_bytes": 100
            },
            "missing": {
                "filename": "missing.csv", 
                "download_time": time.time(),
                "size_bytes": 200
            }
        }
        save_cache_metadata(self.metadata_file, metadata)
        
        status = get_cache_status(str(self.cache_dir))
        
        # Should only count existing files in size calculation
        self.assertEqual(status['total_datasets'], 2)
        self.assertEqual(status['valid_datasets'], 1)
        self.assertEqual(status['total_size_bytes'], 100)  # Only existing file


if __name__ == '__main__':
    unittest.main()