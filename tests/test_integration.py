#!/usr/bin/env python3

import unittest
import tempfile
import shutil
import time
import os
from pathlib import Path
from unittest.mock import patch, Mock
import requests

from utilities.download_manager import download_dataset, get_cache_status, clear_dataset_cache
from utilities.dataset_registry import get_dataset_url, get_dataset_hash
from utilities.file_utilities import read_seed_prompts_from_csv


class TestIntegration(unittest.TestCase):
    """Integration tests for end-to-end dataset management scenarios."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.cache_dir = Path(self.test_dir) / "integration_cache"
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    @patch('utilities.download_manager.requests.get')
    def test_end_to_end_dataset_download_and_usage(self, mock_get):
        """Test complete workflow: download dataset and use it for reading prompts."""
        # Mock successful download
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '100'}
        test_csv_content = b'goal,target\n"Test goal 1","Test target 1"\n"Test goal 2","Test target 2"\n'
        mock_response.iter_content.return_value = [test_csv_content]
        mock_get.return_value = mock_response
        
        # Download dataset
        dataset_path = download_dataset(
            "test_integration",
            "https://example.com/test.csv",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNotNone(dataset_path)
        self.assertTrue(dataset_path.exists())
        
        # Use downloaded dataset for reading prompts
        prompts = read_seed_prompts_from_csv(str(dataset_path))
        
        self.assertEqual(len(prompts), 2)
        self.assertEqual(prompts[0], ("Test goal 1", "Test target 1"))
        self.assertEqual(prompts[1], ("Test goal 2", "Test target 2"))
    
    @patch('utilities.download_manager.requests.get')
    def test_cache_behavior_across_multiple_runs(self, mock_get):
        """Test that cache works correctly across multiple tool runs."""
        # Mock successful download
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '50'}
        mock_response.iter_content.return_value = [b'goal,target\n"Goal","Target"\n']
        mock_get.return_value = mock_response
        
        # First run - should download
        dataset_path1 = download_dataset(
            "cache_test",
            "https://example.com/cache_test.csv",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNotNone(dataset_path1)
        self.assertEqual(mock_get.call_count, 1)
        
        # Second run - should use cache
        dataset_path2 = download_dataset(
            "cache_test", 
            "https://example.com/cache_test.csv",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNotNone(dataset_path2)
        self.assertEqual(dataset_path1, dataset_path2)
        # Should not have made another HTTP request
        self.assertEqual(mock_get.call_count, 1)
    
    @patch('utilities.download_manager.requests.get')
    def test_error_recovery_network_failure(self, mock_get):
        """Test error recovery scenarios with network failures."""
        # Simulate network failure
        mock_get.side_effect = requests.exceptions.RequestException("Network error")
        
        # Attempt download
        dataset_path = download_dataset(
            "network_fail_test",
            "https://example.com/fail.csv", 
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNone(dataset_path)
        
        # Verify no corrupted cache entries
        status = get_cache_status(str(self.cache_dir))
        self.assertEqual(status['total_datasets'], 0)
    
    @patch('utilities.download_manager.requests.get')
    def test_error_recovery_corrupted_download(self, mock_get):
        """Test recovery from corrupted downloads."""
        # Mock response that will fail hash verification
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '20'}
        mock_response.iter_content.return_value = [b'corrupted content']
        mock_get.return_value = mock_response
        
        # Attempt download with expected hash
        dataset_path = download_dataset(
            "corruption_test",
            "https://example.com/test.csv",
            expected_hash="expected_hash_that_wont_match",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNone(dataset_path)
        
        # Verify no corrupted files left in cache
        cache_files = list((self.cache_dir / "datasets").glob("*.csv"))
        self.assertEqual(len(cache_files), 0)
    
    @patch('utilities.download_manager.requests.get')
    def test_offline_operation_with_existing_cache(self, mock_get):
        """Test that tool works offline when cache is available."""
        # First, populate cache with successful download
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '30'}
        mock_response.iter_content.return_value = [b'goal,target\n"Offline","Test"\n']
        mock_get.return_value = mock_response
        
        # Initial download to populate cache
        dataset_path = download_dataset(
            "offline_test",
            "https://example.com/offline.csv",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNotNone(dataset_path)
        
        # Now simulate offline condition by making requests fail
        mock_get.side_effect = requests.exceptions.RequestException("Offline")
        
        # Should still work using cache
        dataset_path_offline = download_dataset(
            "offline_test",
            "https://example.com/offline.csv", 
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNotNone(dataset_path_offline)
        self.assertEqual(dataset_path, dataset_path_offline)
        
        # Should be able to read from cached file
        prompts = read_seed_prompts_from_csv(str(dataset_path_offline))
        self.assertEqual(len(prompts), 1)
        self.assertEqual(prompts[0], ("Offline", "Test"))
    
    @patch('utilities.download_manager.requests.get')
    def test_cache_corruption_and_recovery(self, mock_get):
        """Test behavior when cache metadata is corrupted."""
        # Set up initial successful download
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {'content-length': '40'}
        mock_response.iter_content.return_value = [b'goal,target\n"Recovery","Test"\n']
        mock_get.return_value = mock_response
        
        # Initial download
        dataset_path = download_dataset(
            "recovery_test",
            "https://example.com/recovery.csv", 
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNotNone(dataset_path)
        
        # Corrupt the metadata file
        metadata_file = self.cache_dir / "datasets" / "metadata.json"
        with open(metadata_file, 'w') as f:
            f.write("{ corrupted json")
        
        # Should handle corruption gracefully and re-download
        dataset_path_recovered = download_dataset(
            "recovery_test",
            "https://example.com/recovery.csv",
            cache_dir=str(self.cache_dir), 
            show_progress=False
        )
        
        self.assertIsNotNone(dataset_path_recovered)
        # Should have made two requests (initial + recovery)
        self.assertEqual(mock_get.call_count, 2)
    
    def test_invalid_dataset_url_handling(self):
        """Test handling of invalid dataset URLs."""
        # Test with completely invalid URL
        result = download_dataset(
            "invalid_test",
            "not-a-url-at-all",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNone(result)
    
    @patch('utilities.download_manager.requests.get')
    def test_large_file_handling(self, mock_get):
        """Test handling of large file downloads (simulated)."""
        # Mock large file response
        mock_response = Mock() 
        mock_response.status_code = 200
        mock_response.headers = {'content-length': str(10 * 1024 * 1024)}  # 10MB
        
        # Simulate chunked content
        chunk_size = 8192
        total_chunks = (10 * 1024 * 1024) // chunk_size
        chunks = [b'x' * chunk_size for _ in range(total_chunks)]
        mock_response.iter_content.return_value = chunks
        mock_get.return_value = mock_response
        
        # Download large file
        dataset_path = download_dataset(
            "large_file_test",
            "https://example.com/large.csv",
            cache_dir=str(self.cache_dir),
            show_progress=False  # Disable progress to avoid output during tests
        )
        
        self.assertIsNotNone(dataset_path)
        self.assertTrue(dataset_path.exists())
        
        # Verify file size
        file_size = dataset_path.stat().st_size
        self.assertEqual(file_size, 10 * 1024 * 1024)
    
    @patch('utilities.download_manager.requests.get')
    def test_migration_from_old_to_new_configuration(self, mock_get):
        """Test migration scenario from old file-based to new dataset-based config."""
        # Create old-style local file
        old_file = Path(self.test_dir) / "old_style.csv"
        old_content = 'goal,target\n"Old style","prompt"\n'
        with open(old_file, 'w') as f:
            f.write(old_content)
        
        # Read using old approach (direct file path)
        old_prompts = read_seed_prompts_from_csv(str(old_file))
        self.assertEqual(len(old_prompts), 1)
        self.assertEqual(old_prompts[0], ("Old style", "prompt"))
        
        # Now simulate new approach with dataset download
        mock_response = Mock()
        mock_response.status_code = 200 
        mock_response.headers = {'content-length': '50'}
        new_content = b'goal,target\n"New style","dataset"\n'
        mock_response.iter_content.return_value = [new_content]
        mock_get.return_value = mock_response
        
        # Download new dataset
        new_dataset_path = download_dataset(
            "migration_test",
            "https://example.com/new.csv",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        # Read using new approach
        new_prompts = read_seed_prompts_from_csv(str(new_dataset_path))
        self.assertEqual(len(new_prompts), 1)
        self.assertEqual(new_prompts[0], ("New style", "dataset"))
        
        # Both approaches should work independently
        self.assertNotEqual(old_prompts, new_prompts)
    
    def test_first_time_tool_setup_no_cache(self):
        """Test first-time tool setup with no existing cache."""
        # Verify clean state
        self.assertFalse(self.cache_dir.exists())
        
        # Get initial cache status
        status = get_cache_status(str(self.cache_dir))
        
        self.assertEqual(status['total_datasets'], 0)
        self.assertEqual(status['valid_datasets'], 0) 
        self.assertEqual(status['total_size_bytes'], 0)
        self.assertTrue(status['cache_dir'].endswith('integration_cache'))
        
        # Verify cache directory was created
        self.assertTrue(self.cache_dir.exists())
    
    @patch('utilities.download_manager.requests.get')
    def test_network_interruption_during_download(self, mock_get):
        """Test handling of network interruption during download."""
        # Mock partial download followed by network error
        def side_effect(*args, **kwargs):
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.headers = {'content-length': '100'}
            
            def iter_content_side_effect(chunk_size=8192):
                yield b'partial content'
                raise requests.exceptions.RequestException("Connection interrupted")
            
            mock_response.iter_content = iter_content_side_effect
            return mock_response
        
        mock_get.side_effect = side_effect
        
        # Attempt download
        dataset_path = download_dataset(
            "interruption_test",
            "https://example.com/interrupted.csv",
            cache_dir=str(self.cache_dir),
            show_progress=False
        )
        
        self.assertIsNone(dataset_path)
        
        # Verify no partial files left behind
        cache_files = list((self.cache_dir / "datasets").glob("*interrupted*"))
        self.assertEqual(len(cache_files), 0)


if __name__ == '__main__':
    unittest.main()