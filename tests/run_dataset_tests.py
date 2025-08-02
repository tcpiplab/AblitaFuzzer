#!/usr/bin/env python3

import unittest
import sys
import os
from pathlib import Path

# Add the project root to the Python path so imports work
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Import test modules
from tests.test_download_manager import TestDownloadManager
from tests.test_cache_manager import TestCacheManager
from tests.test_dataset_registry import TestDatasetRegistry
from tests.test_config_loading import TestConfigLoading
from tests.test_integration import TestIntegration


def run_dataset_tests():
    """Run all dataset management tests."""
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases from each module
    test_classes = [
        TestDownloadManager,
        TestCacheManager, 
        TestDatasetRegistry,
        TestConfigLoading,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(
        verbosity=2,
        stream=sys.stdout,
        descriptions=True,
        failfast=False
    )
    
    print("=" * 70)
    print("Running Dataset Management System Tests")
    print("=" * 70)
    print()
    
    result = runner.run(test_suite)
    
    print()
    print("=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    success = len(result.failures) == 0 and len(result.errors) == 0
    print(f"\nOverall result: {'PASSED' if success else 'FAILED'}")
    
    return success


def run_specific_test(test_name):
    """Run a specific test module or test case."""
    
    test_mapping = {
        'download': TestDownloadManager,
        'cache': TestCacheManager,
        'registry': TestDatasetRegistry,
        'config': TestConfigLoading,
        'integration': TestIntegration
    }
    
    if test_name in test_mapping:
        test_class = test_mapping[test_name]
        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        return len(result.failures) == 0 and len(result.errors) == 0
    else:
        print(f"Unknown test: {test_name}")
        print(f"Available tests: {', '.join(test_mapping.keys())}")
        return False


if __name__ == '__main__':
    if len(sys.argv) > 1:
        # Run specific test
        test_name = sys.argv[1]
        success = run_specific_test(test_name)
    else:
        # Run all tests
        success = run_dataset_tests()
    
    sys.exit(0 if success else 1)