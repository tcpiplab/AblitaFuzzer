#!/usr/bin/env python3

import unittest
from unittest.mock import patch

from utilities.dataset_registry import (
    get_available_datasets, get_dataset_info, list_dataset_names,
    search_datasets, validate_dataset_info, add_custom_dataset,
    get_dataset_url, get_dataset_hash, is_dataset_available,
    DATASETS
)


class TestDatasetRegistry(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        # Store original datasets to restore later
        self.original_datasets = DATASETS.copy()
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Restore original datasets
        DATASETS.clear()
        DATASETS.update(self.original_datasets)
    
    def test_get_available_datasets(self):
        """Test getting all available datasets."""
        datasets = get_available_datasets()
        
        self.assertIsInstance(datasets, dict)
        self.assertIn("advbench_harmful", datasets)
        self.assertIn("jailbreak_2023", datasets)
        
        # Verify it returns a copy, not the original
        datasets["test_modification"] = {"name": "test"}
        self.assertNotIn("test_modification", DATASETS)
    
    def test_get_dataset_info_existing(self):
        """Test getting info for existing dataset."""
        info = get_dataset_info("advbench_harmful")
        
        self.assertIsNotNone(info)
        self.assertEqual(info["name"], "AdvBench Harmful Behaviors")
        self.assertEqual(info["format"], "csv")
        self.assertIn("url", info)
        self.assertIn("description", info)
        self.assertIn("columns", info)
    
    def test_get_dataset_info_nonexistent(self):
        """Test getting info for non-existent dataset."""
        info = get_dataset_info("nonexistent_dataset")
        self.assertIsNone(info)
    
    def test_list_dataset_names(self):
        """Test listing dataset names."""
        names = list_dataset_names()
        
        self.assertIsInstance(names, list)
        self.assertIn("advbench_harmful", names)
        self.assertIn("jailbreak_2023", names)
        self.assertEqual(len(names), len(DATASETS))
    
    def test_search_datasets_by_name(self):
        """Test searching datasets by name."""
        results = search_datasets("advbench")
        
        self.assertIn("advbench_harmful", results)
        self.assertEqual(len(results), 1)
    
    def test_search_datasets_by_description(self):
        """Test searching datasets by description."""
        results = search_datasets("jailbreak")
        
        self.assertIn("jailbreak_2023", results)
        # Should find datasets with "jailbreak" in ID or description
        found_ids = list(results.keys())
        self.assertTrue(any("jailbreak" in dataset_id.lower() for dataset_id in found_ids))
    
    def test_search_datasets_case_insensitive(self):
        """Test that search is case insensitive."""
        results_lower = search_datasets("advbench")
        results_upper = search_datasets("ADVBENCH")
        results_mixed = search_datasets("AdvBench")
        
        self.assertEqual(results_lower, results_upper)
        self.assertEqual(results_lower, results_mixed)
    
    def test_search_datasets_no_matches(self):
        """Test search with no matches."""
        results = search_datasets("nonexistent_search_term")
        self.assertEqual(results, {})
    
    def test_validate_dataset_info_valid(self):
        """Test validation with valid dataset info."""
        valid_info = {
            "name": "Test Dataset",
            "url": "https://example.com/test.csv",
            "description": "A test dataset",
            "format": "csv",
            "columns": ["col1", "col2"]
        }
        
        errors = validate_dataset_info(valid_info)
        self.assertEqual(errors, [])
    
    def test_validate_dataset_info_missing_fields(self):
        """Test validation with missing required fields."""
        invalid_info = {
            "name": "Test Dataset",
            # Missing required fields
        }
        
        errors = validate_dataset_info(invalid_info)
        self.assertGreater(len(errors), 0)
        
        # Check that specific missing fields are reported
        error_text = " ".join(errors)
        self.assertIn("url", error_text)
        self.assertIn("description", error_text)
        self.assertIn("format", error_text)
        self.assertIn("columns", error_text)
    
    def test_validate_dataset_info_invalid_url(self):
        """Test validation with invalid URL."""
        invalid_info = {
            "name": "Test Dataset",
            "url": "not-a-url",
            "description": "A test dataset",
            "format": "csv",
            "columns": ["col1"]
        }
        
        errors = validate_dataset_info(invalid_info)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("URL must start with http" in error for error in errors))
    
    def test_validate_dataset_info_invalid_format(self):
        """Test validation with invalid format."""
        invalid_info = {
            "name": "Test Dataset",
            "url": "https://example.com/test.xml",
            "description": "A test dataset", 
            "format": "xml",  # Invalid format
            "columns": ["col1"]
        }
        
        errors = validate_dataset_info(invalid_info)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("Format must be" in error for error in errors))
    
    def test_validate_dataset_info_invalid_columns(self):
        """Test validation with invalid columns."""
        invalid_info = {
            "name": "Test Dataset",
            "url": "https://example.com/test.csv",
            "description": "A test dataset",
            "format": "csv", 
            "columns": "not_a_list"  # Should be a list
        }
        
        errors = validate_dataset_info(invalid_info)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("Columns must be a list" in error for error in errors))
    
    @patch('utilities.dataset_registry.print')
    def test_add_custom_dataset_success(self, mock_print):
        """Test successfully adding a custom dataset."""
        custom_info = {
            "name": "Custom Test Dataset",
            "url": "https://example.com/custom.csv",
            "description": "A custom test dataset",
            "format": "csv",
            "columns": ["custom_col1", "custom_col2"]
        }
        
        result = add_custom_dataset("custom_test", custom_info)
        
        self.assertTrue(result)
        self.assertIn("custom_test", DATASETS)
        self.assertEqual(DATASETS["custom_test"], custom_info)
    
    @patch('utilities.dataset_registry.print')
    def test_add_custom_dataset_invalid(self, mock_print):
        """Test adding invalid custom dataset."""
        invalid_info = {
            "name": "Invalid Dataset"
            # Missing required fields
        }
        
        result = add_custom_dataset("invalid_test", invalid_info)
        
        self.assertFalse(result)
        self.assertNotIn("invalid_test", DATASETS)
    
    @patch('utilities.dataset_registry.print')
    def test_add_custom_dataset_duplicate(self, mock_print):
        """Test adding custom dataset with existing ID."""
        custom_info = {
            "name": "Duplicate Test",
            "url": "https://example.com/duplicate.csv", 
            "description": "A duplicate test",
            "format": "csv",
            "columns": ["col1"]
        }
        
        result = add_custom_dataset("advbench_harmful", custom_info)  # Existing ID
        
        self.assertFalse(result)
        # Original dataset should be unchanged
        self.assertEqual(DATASETS["advbench_harmful"]["name"], "AdvBench Harmful Behaviors")
    
    def test_get_dataset_url_existing(self):
        """Test getting URL for existing dataset."""
        url = get_dataset_url("advbench_harmful")
        
        self.assertIsNotNone(url)
        self.assertTrue(url.startswith("https://"))
    
    def test_get_dataset_url_nonexistent(self):
        """Test getting URL for non-existent dataset."""
        url = get_dataset_url("nonexistent_dataset")
        self.assertIsNone(url)
    
    def test_get_dataset_hash_with_hash(self):
        """Test getting hash for dataset that has one."""
        # Temporarily add a dataset with a hash
        DATASETS["test_with_hash"] = {
            "name": "Test With Hash",
            "url": "https://example.com/test.csv",
            "description": "Test dataset with hash",
            "format": "csv",
            "columns": ["col1"],
            "sha256": "testhash123"
        }
        
        hash_value = get_dataset_hash("test_with_hash")
        self.assertEqual(hash_value, "testhash123")
    
    def test_get_dataset_hash_without_hash(self):
        """Test getting hash for dataset without one."""
        hash_value = get_dataset_hash("advbench_harmful")
        self.assertIsNone(hash_value)
    
    def test_get_dataset_hash_nonexistent(self):
        """Test getting hash for non-existent dataset."""
        hash_value = get_dataset_hash("nonexistent_dataset")
        self.assertIsNone(hash_value)
    
    def test_is_dataset_available_existing(self):
        """Test checking availability of existing dataset."""
        self.assertTrue(is_dataset_available("advbench_harmful"))
        self.assertTrue(is_dataset_available("jailbreak_2023"))
    
    def test_is_dataset_available_nonexistent(self):
        """Test checking availability of non-existent dataset."""
        self.assertFalse(is_dataset_available("nonexistent_dataset"))
    
    def test_dataset_registry_structure(self):
        """Test that all datasets in registry have required structure."""
        required_fields = ["name", "url", "description", "format", "columns"]
        
        for dataset_id, dataset_info in DATASETS.items():
            with self.subTest(dataset_id=dataset_id):
                for field in required_fields:
                    self.assertIn(field, dataset_info, 
                                f"Dataset '{dataset_id}' missing required field '{field}'")
                
                # Validate field types
                self.assertIsInstance(dataset_info["name"], str)
                self.assertIsInstance(dataset_info["url"], str) 
                self.assertIsInstance(dataset_info["description"], str)
                self.assertIsInstance(dataset_info["format"], str)
                self.assertIsInstance(dataset_info["columns"], list)
                
                # Validate URL format
                self.assertTrue(dataset_info["url"].startswith(("http://", "https://")))
                
                # Validate format value
                self.assertIn(dataset_info["format"], ["csv", "json", "txt"])
    
    def test_dataset_ids_are_valid(self):
        """Test that dataset IDs follow valid naming conventions."""
        for dataset_id in DATASETS.keys():
            with self.subTest(dataset_id=dataset_id):
                # Should be lowercase with underscores
                self.assertEqual(dataset_id, dataset_id.lower())
                self.assertRegex(dataset_id, r'^[a-z0-9_]+$', 
                               f"Dataset ID '{dataset_id}' contains invalid characters")


if __name__ == '__main__':
    unittest.main()