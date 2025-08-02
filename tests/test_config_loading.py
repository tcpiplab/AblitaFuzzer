#!/usr/bin/env python3

import unittest
import tempfile
import shutil
import os
from pathlib import Path
from unittest.mock import patch, Mock

from utilities.file_utilities import (
    resolve_dataset_path, get_seed_prompts_dataset_path, 
    read_seed_prompts_from_csv
)


class TestConfigLoading(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = Path(self.test_dir) / "test_config.csv"
        
        # Create a test CSV file
        test_content = """goal,target
"Test goal 1","Test target 1"
"Test goal 2","Test target 2"
"""
        with open(self.test_file, 'w') as f:
            f.write(test_content)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_resolve_dataset_path_local_file_exists(self):
        """Test resolving dataset path for existing local file."""
        result = resolve_dataset_path(str(self.test_file))
        self.assertEqual(result, str(self.test_file))
    
    def test_resolve_dataset_path_local_file_missing(self):
        """Test resolving dataset path for missing local file."""
        missing_file = str(Path(self.test_dir) / "missing.csv")
        result = resolve_dataset_path(missing_file)
        self.assertIsNone(result)
    
    @patch('utilities.file_utilities.is_dataset_available')
    @patch('utilities.file_utilities.get_cached_dataset_path')
    def test_resolve_dataset_path_cached_dataset(self, mock_cached_path, mock_available):
        """Test resolving dataset path for cached dataset."""
        mock_available.return_value = True
        mock_cached_path.return_value = Path("/cache/dataset.csv")
        
        result = resolve_dataset_path("test_dataset")
        
        self.assertEqual(result, "/cache/dataset.csv")
        mock_available.assert_called_once_with("test_dataset")
        mock_cached_path.assert_called_once()
    
    @patch('utilities.file_utilities.is_dataset_available')
    @patch('utilities.file_utilities.get_cached_dataset_path')
    @patch('utilities.file_utilities.download_dataset')
    @patch('utilities.file_utilities.get_dataset_url')
    @patch('utilities.file_utilities.get_dataset_hash')
    def test_resolve_dataset_path_download_needed(self, mock_hash, mock_url, mock_download, 
                                                 mock_cached_path, mock_available):
        """Test resolving dataset path when download is needed."""
        mock_available.return_value = True
        mock_cached_path.return_value = None  # Not cached
        mock_url.return_value = "https://example.com/dataset.csv"
        mock_hash.return_value = "testhash"
        mock_download.return_value = Path("/cache/downloaded.csv")
        
        result = resolve_dataset_path("test_dataset")
        
        self.assertEqual(result, "/cache/downloaded.csv")
        mock_download.assert_called_once()
    
    @patch('utilities.file_utilities.is_dataset_available')
    def test_resolve_dataset_path_unknown_dataset(self, mock_available):
        """Test resolving dataset path for unknown dataset."""
        mock_available.return_value = False
        
        result = resolve_dataset_path("unknown_dataset")
        
        self.assertIsNone(result)
    
    @patch('configs.config.SEED_PROMPT_DATASET', 'test_dataset')
    @patch('utilities.file_utilities.resolve_dataset_path')
    def test_get_seed_prompts_dataset_path_new_config(self, mock_resolve):
        """Test getting seed prompts path using new dataset configuration."""
        mock_resolve.return_value = "/path/to/dataset.csv"
        
        result = get_seed_prompts_dataset_path()
        
        self.assertEqual(result, "/path/to/dataset.csv")
        mock_resolve.assert_called_once_with('test_dataset')
    
    @patch('configs.config.SEED_PROMPT_DATASET', None)
    @patch('configs.config.SEED_PROMPT_INPUT_FILE_PATH', None)
    def test_get_seed_prompts_dataset_path_no_config(self):
        """Test getting seed prompts path when no configuration is set."""
        result = get_seed_prompts_dataset_path()
        self.assertIsNone(result)
    
    @patch('configs.config.SEED_PROMPT_DATASET', None)
    def test_get_seed_prompts_dataset_path_legacy_fallback(self):
        """Test fallback to legacy configuration."""
        with patch('configs.config.SEED_PROMPT_INPUT_FILE_PATH', str(self.test_file)):
            result = get_seed_prompts_dataset_path()
            self.assertEqual(result, str(self.test_file))
    
    @patch('configs.config.SEED_PROMPT_DATASET', 'invalid_dataset')  
    @patch('configs.config.SEED_PROMPT_INPUT_FILE_PATH', None)
    @patch('utilities.file_utilities.resolve_dataset_path')
    def test_get_seed_prompts_dataset_path_invalid_dataset_no_fallback(self, mock_resolve):
        """Test behavior when new config points to invalid dataset and no fallback."""
        mock_resolve.return_value = None
        
        result = get_seed_prompts_dataset_path()
        
        self.assertIsNone(result)
    
    @patch('configs.config.SEED_PROMPT_DATASET', 'invalid_dataset')
    @patch('utilities.file_utilities.resolve_dataset_path')
    def test_get_seed_prompts_dataset_path_invalid_dataset_with_fallback(self, mock_resolve):
        """Test fallback when new config points to invalid dataset."""
        mock_resolve.return_value = None
        
        with patch('configs.config.SEED_PROMPT_INPUT_FILE_PATH', str(self.test_file)):
            result = get_seed_prompts_dataset_path()
            self.assertEqual(result, str(self.test_file))
    
    def test_read_seed_prompts_from_csv_with_path(self):
        """Test reading seed prompts when path is provided."""
        result = read_seed_prompts_from_csv(str(self.test_file))
        
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ("Test goal 1", "Test target 1"))
        self.assertEqual(result[1], ("Test goal 2", "Test target 2"))
    
    @patch('utilities.file_utilities.get_seed_prompts_dataset_path')
    def test_read_seed_prompts_from_csv_no_path_provided(self, mock_get_path):
        """Test reading seed prompts when no path is provided (uses config)."""
        mock_get_path.return_value = str(self.test_file)
        
        result = read_seed_prompts_from_csv()
        
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        mock_get_path.assert_called_once()
    
    @patch('utilities.file_utilities.get_seed_prompts_dataset_path')
    def test_read_seed_prompts_from_csv_config_returns_none(self, mock_get_path):
        """Test reading seed prompts when config resolution fails."""
        mock_get_path.return_value = None
        
        result = read_seed_prompts_from_csv()
        
        self.assertEqual(result, [])
    
    @patch('utilities.file_utilities.resolve_dataset_path')
    def test_read_seed_prompts_from_csv_dataset_id_provided(self, mock_resolve):
        """Test reading seed prompts when dataset ID is provided."""
        mock_resolve.return_value = str(self.test_file)
        
        result = read_seed_prompts_from_csv("test_dataset_id")
        
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        mock_resolve.assert_called_once_with("test_dataset_id")
    
    @patch('utilities.file_utilities.resolve_dataset_path')
    def test_read_seed_prompts_from_csv_dataset_resolution_fails(self, mock_resolve):
        """Test reading seed prompts when dataset resolution fails."""
        mock_resolve.return_value = None
        
        result = read_seed_prompts_from_csv("invalid_dataset")
        
        self.assertEqual(result, [])
    
    def test_read_seed_prompts_from_csv_empty_file(self):
        """Test reading seed prompts from empty CSV file."""
        empty_file = Path(self.test_dir) / "empty.csv"
        with open(empty_file, 'w') as f:
            f.write("")
        
        result = read_seed_prompts_from_csv(str(empty_file))
        self.assertEqual(result, [])
    
    def test_read_seed_prompts_from_csv_header_only(self):
        """Test reading seed prompts from CSV with only header."""
        header_only_file = Path(self.test_dir) / "header_only.csv"
        with open(header_only_file, 'w') as f:
            f.write("goal,target\n")
        
        result = read_seed_prompts_from_csv(str(header_only_file))
        self.assertEqual(result, [])
    
    def test_read_seed_prompts_from_csv_malformed_rows(self):
        """Test reading seed prompts with malformed CSV rows."""
        malformed_file = Path(self.test_dir) / "malformed.csv"
        malformed_content = """goal,target
"Valid goal","Valid target"
""
"Only one column"
"Another valid goal","Another valid target"
"""
        with open(malformed_file, 'w') as f:
            f.write(malformed_content)
        
        result = read_seed_prompts_from_csv(str(malformed_file))
        
        # Should skip malformed rows and only return valid ones
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ("Valid goal", "Valid target"))
        self.assertEqual(result[1], ("Another valid goal", "Another valid target"))
    
    def test_read_seed_prompts_from_csv_file_not_found(self):
        """Test reading seed prompts from non-existent file."""
        missing_file = str(Path(self.test_dir) / "missing.csv")
        
        result = read_seed_prompts_from_csv(missing_file)
        
        self.assertEqual(result, [])
    
    @patch('utilities.file_utilities.resolve_dataset_path')
    def test_backwards_compatibility_file_path_resolution(self, mock_resolve):
        """Test that file paths still work when dataset resolution is available."""
        # When a valid file path is provided, it should be used directly
        # without trying dataset resolution
        mock_resolve.return_value = str(self.test_file)
        
        result = read_seed_prompts_from_csv(str(self.test_file))
        
        # Should read from the file directly, not call resolve_dataset_path
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)
        # resolve_dataset_path should have been called during the resolution process
        mock_resolve.assert_called_once()


if __name__ == '__main__':
    unittest.main()