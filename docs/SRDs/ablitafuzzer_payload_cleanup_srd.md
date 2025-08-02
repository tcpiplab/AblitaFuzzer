# Software Requirements Document: AblitaFuzzer Repository Cleanup

## Document Information
- **Project**: AblitaFuzzer
- **Component**: Repository Payload Cleanup and Download Mechanism
- **Version**: 1.0
- **Date**: 2025-01-02

## Executive Summary

This SRD defines the requirements for removing stored attack payloads from the AblitaFuzzer repository and implementing a robust download mechanism for external payload datasets. This change will reduce repository size, improve tool vendor compatibility, and follow security tool best practices.

## Current State Analysis

### Files to be Removed
- `inputs/seed-prompts/harmful-behaviors/harmful_behaviors.csv` (520+ lines of stored attack prompts)
- `inputs/seed-prompts/jailbreaks/jailbreak_prompts_2023_12_25.csv` (if present)
- `inputs/seed-prompts/jailbreaks/jailbreaks_only.csv` (if present)

### Current Dependencies
- `utilities/file_utilities.py::read_seed_prompts_from_csv()` reads local CSV files
- `pre_attack/pre_attack_functions.py::generate_malicious_prompts()` depends on local seed files
- `configs/config.py::SEED_PROMPT_INPUT_FILE_PATH` points to local file
- `tools/create_jailbreaks_csv.py` already downloads remote content but saves locally

## Requirements

### Functional Requirements

#### FR-1: Dataset Registry System
- **Requirement**: Create a centralized registry of available attack payload datasets
- **Implementation**: New module `utilities/dataset_registry.py`
- **Details**: 
  - Define standardized dataset metadata (name, URL, description, format, hash)
  - Support multiple dataset sources (AdvBench, jailbreak collections, custom URLs)
  - Include dataset versioning and integrity verification
  - Provide easy mechanism for users to add custom dataset URLs

#### FR-2: Download Manager
- **Requirement**: Implement robust download mechanism for remote datasets
- **Implementation**: New module `utilities/download_manager.py`
- **Details**:
  - Support HTTP/HTTPS downloads with proper error handling
  - Implement retry logic with exponential backoff
  - Include timeout handling (default 30 seconds)
  - Support proxy configuration for corporate environments
  - Verify file integrity using checksums when available
  - Handle large files efficiently with streaming downloads

#### FR-3: Local Cache System
- **Requirement**: Cache downloaded datasets locally to avoid repeated downloads
- **Implementation**: Extend `utilities/download_manager.py`
- **Details**:
  - Create cache directory structure under `~/.ablitafuzzer/cache/`
  - Implement cache expiration policies (default 7 days)
  - Support cache invalidation and manual cache clearing
  - Store metadata about cached files (download date, source URL, hash)
  - Respect HTTP cache headers when available

#### FR-4: Configuration System Updates
- **Requirement**: Update configuration to support remote dataset URLs
- **Implementation**: Modify `configs/config.py`
- **Details**:
  - Replace hardcoded local file paths with dataset registry references
  - Support both local file paths and remote URLs for backwards compatibility
  - Add configuration options for cache behavior
  - Include network timeout and retry settings

#### FR-5: File Utilities Refactoring
- **Requirement**: Update file reading functions to work with download manager
- **Implementation**: Modify `utilities/file_utilities.py`
- **Details**:
  - Modify `read_seed_prompts_from_csv()` to accept URLs or local paths
  - Automatically download and cache remote files as needed
  - Maintain existing function signatures for backwards compatibility
  - Add progress indicators for large downloads

#### FR-6: Command Line Interface for Dataset Management
- **Requirement**: Provide CLI commands for dataset operations
- **Implementation**: Extend `ablitafuzzer.py` with new subcommands
- **Details**:
  - `ablitafuzzer datasets list` - Show available datasets
  - `ablitafuzzer datasets download <dataset_name>` - Pre-download specific dataset
  - `ablitafuzzer datasets cache clear` - Clear local cache
  - `ablitafuzzer datasets cache status` - Show cache status and sizes

### Non-Functional Requirements

#### NFR-1: Performance Requirements
- Downloads must not significantly impact tool startup time
- Cache lookups must complete in under 100ms
- Large dataset downloads must show progress indicators
- Concurrent downloads must be supported for multiple datasets

#### NFR-2: Reliability Requirements
- Network failures must not crash the application
- Download interruptions must be recoverable
- Cache corruption must be detectable and recoverable
- Offline operation must work with cached datasets

#### NFR-3: Security Requirements
- HTTPS must be enforced for all downloads
- Downloaded files must be validated against expected checksums when available
- Cache files must have appropriate file permissions (600)
- No sensitive information must be logged during downloads

#### NFR-4: Usability Requirements
- Clear error messages for network issues
- Progress indicators for downloads over 5MB
- Automatic fallback to cached versions when remote is unavailable
- Option to operate in offline mode

## Implementation Specifications

### Dataset Registry Format

```python
DATASETS = {
    "advbench_harmful": {
        "name": "AdvBench Harmful Behaviors",
        "url": "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv",
        "description": "Standard harmful behavior prompts from AdvBench",
        "format": "csv",
        "columns": ["goal", "target"],
        "sha256": "expected_hash_if_available",
        "size_mb": 0.1
    },
    "jailbreak_2023": {
        "name": "Jailbreak Prompts 2023",
        "url": "https://github.com/verazuo/jailbreak_llms/raw/main/data/prompts/jailbreak_prompts_2023_12_25.csv",
        "description": "Jailbreak prompts collection from December 2023",
        "format": "csv",
        "columns": ["platform", "source", "prompt", "jailbreak", "created_at", "date", "community", "community_id", "previous_community_id"],
        "sha256": "expected_hash_if_available",
        "size_mb": 2.5
    }
}
```

### Cache Directory Structure

```
~/.ablitafuzzer/
├── cache/
│   ├── datasets/
│   │   ├── advbench_harmful.csv
│   │   ├── jailbreak_2023.csv
│   │   └── metadata.json
│   └── config/
│       └── user_datasets.json
└── logs/
    └── download.log
```

### Error Handling Strategy

- Network timeouts: Retry with exponential backoff (max 3 attempts)
- HTTP errors: Log specific error codes and provide user-friendly messages
- File corruption: Detect via checksum mismatch, re-download automatically
- Cache issues: Fall back to direct download, warn user about cache problems
- Missing datasets: Provide clear instructions for manual download

### Configuration Migration Strategy

- Maintain backwards compatibility with existing local file configurations
- Automatically detect and warn about missing local files
- Provide migration utility to help users transition to new dataset system
- Include comprehensive documentation for configuration changes

## File Modifications Required

### New Files to Create
1. `utilities/dataset_registry.py` - Dataset definitions and metadata
2. `utilities/download_manager.py` - Download and cache management
3. `utilities/cache_manager.py` - Cache operations and cleanup
4. `tests/test_download_manager.py` - Unit tests for download functionality
5. `tests/test_cache_manager.py` - Unit tests for cache functionality

### Existing Files to Modify
1. `configs/config.py` - Update dataset configuration
2. `utilities/file_utilities.py` - Add download support to file reading
3. `pre_attack/pre_attack_functions.py` - Update to use new dataset system
4. `ablitafuzzer.py` - Add dataset management subcommands
5. `requirements.txt` - Add any new dependencies (if needed)
6. `README.md` - Update documentation for new dataset system
7. `.gitignore` - Add cache directories and downloaded files

### Files to Remove
1. `inputs/seed-prompts/harmful-behaviors/harmful_behaviors.csv`
2. `inputs/seed-prompts/jailbreaks/` (entire directory if present)
3. `tools/create_jailbreaks_csv.py` (functionality merged into download manager)

## Testing Requirements

### Unit Tests
- Download manager with mocked HTTP responses
- Cache manager operations (store, retrieve, expire)
- Dataset registry validation
- Configuration loading with new dataset format

### Integration Tests
- End-to-end download and usage of real datasets
- Cache behavior across multiple tool runs
- Error recovery scenarios (network failures, corrupted downloads)
- Migration from old configuration format

### Manual Testing Scenarios
- First-time tool setup with no cache
- Offline operation with existing cache
- Network interruption during large download
- Cache corruption and recovery
- Invalid dataset URL handling

## Migration Plan

### Phase 1: Implementation
1. Create new download and cache management modules
2. Implement dataset registry with initial datasets
3. Update configuration system to support new format
4. Add CLI commands for dataset management

### Phase 2: Integration
1. Modify existing file utilities to use download manager
2. Update main tool flow to work with new system
3. Add comprehensive error handling and user feedback
4. Create migration utility for existing users

### Phase 3: Cleanup
1. Remove stored payload files from repository
2. Update documentation and README
3. Add deprecation warnings for old configuration format
4. Test thoroughly in various network environments

## Success Criteria

- Repository size reduced by removal of payload CSV files
- Tool startup time not significantly impacted by download system
- All existing functionality preserved with new download mechanism
- Clear user feedback for all download and cache operations
- Robust error handling for all network failure scenarios
- Comprehensive test coverage for new functionality

## Dependencies

### External Dependencies
- Python `requests` library (already in requirements.txt)
- Python `hashlib` library (built-in)
- Python `pathlib` library (built-in)

### Internal Dependencies
- Existing configuration system
- Existing file utilities
- Existing error handling patterns
- Existing CLI framework

## Risk Mitigation

### Risk: Network dependency introduces reliability issues
- **Mitigation**: Robust caching system with offline operation support

### Risk: Download failures impact tool usability
- **Mitigation**: Clear error messages and fallback options

### Risk: Large downloads impact user experience
- **Mitigation**: Progress indicators and background download options

### Risk: Cache corruption causes data integrity issues
- **Mitigation**: Checksum validation and automatic re-download

### Risk: Configuration migration breaks existing setups
- **Mitigation**: Backwards compatibility and migration utilities