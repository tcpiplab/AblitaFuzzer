# AblitaFuzzer Ollama Unification SRD

## Document Information
- **Title**: Ollama Unification System Requirements Document
- **Version**: 1.0
- **Date**: 2025-08-06
- **Project**: AblitaFuzzer LLM Security Assessment Platform
- **Branch**: replace-lmstudio-with-ollama-turbo

## Executive Summary

This SRD defines the requirements for unifying AblitaFuzzer's attack and target model configurations to use Ollama exclusively. The implementation eliminates LM Studio dependencies, resolves resource contention kernel panics, and establishes a professional testing architecture using Ollama's local and cloud services.

## Current System Issues

### Resource Contention Problems
- Concurrent local models (Ollama + LM Studio) cause kernel panics on macOS
- System crashes when both APIs are active simultaneously
- Memory/GPU resource conflicts between competing inference engines

### API Complexity
- Dual API formats (Ollama native vs OpenAI-compatible)
- Configuration inconsistencies between attacker and target models
- LM Studio API quirks requiring workarounds

### Professional Standards Gap
- Security research community standardizes on Ollama
- LM Studio rarely used in professional penetration testing
- Mixed toolchain creates unnecessary complexity

## System Requirements

### Functional Requirements

#### FR-1: Unified Ollama Architecture
- **Requirement**: Replace LM Studio with Ollama for all model operations
- **Target Model**: Ollama Turbo cloud service (professional target scenario)
- **Attacker Model**: Local Ollama instance (controlled testing environment)
- **Analyzer Model**: Reuse attacker model configuration

#### FR-2: Cloud-Local Hybrid Configuration
- **Target**: Cloud-hosted model via Ollama Turbo API
  - Host: `https://ollama.com`
  - Authentication: Bearer token via API key
  - Model: `gpt-oss:20b` or `gpt-oss:120b`
- **Attacker**: Local Ollama instance
  - Host: `http://api.promptmaker.local:11434`
  - Model: `huihui_ai/granite3.2-abliterated:8b`
  - No authentication required

#### FR-3: Configuration System Updates
- Update legacy configuration to use consistent Ollama API format
- Implement API key management for Ollama Turbo
- Maintain backward compatibility with existing workflows

#### FR-4: Testing Infrastructure
- Implement safe API connectivity testing
- Prevent resource conflicts through sequential testing
- Validate both local and cloud endpoints

### Non-Functional Requirements

#### NFR-1: Performance Requirements
- Eliminate kernel panic conditions
- Support concurrent requests to different endpoints
- Maintain response time SLAs for local model operations

#### NFR-2: Security Requirements
- Secure API key management for Ollama Turbo
- Isolated model operations (cloud vs local)
- Maintain audit trail for all API interactions

#### NFR-3: Reliability Requirements
- Graceful handling of cloud service interruptions
- Fallback mechanisms for API failures
- Comprehensive error handling and logging

## Technical Architecture

### API Endpoint Configuration

#### Target Model (Cloud)
```python
target_config = {
    'type': 'ollama_cloud',
    'base_url': 'https://ollama.com/api/chat',
    'auth': {
        'type': 'api_key',
        'header': 'Authorization',
        'format': 'Bearer {api_key}'
    },
    'model': 'gpt-oss:20b'
}
```

#### Attacker Model (Local)
```python
attacker_config = {
    'type': 'ollama_local',
    'base_url': 'http://api.promptmaker.local:11434/api/chat',
    'auth': {'type': 'none'},
    'model': 'huihui_ai/granite3.2-abliterated:8b'
}
```

### Configuration Migration Strategy

#### Phase 1: Configuration Updates
1. Update `configs/config.py` legacy configuration
2. Modify API URL endpoints and authentication
3. Update model names to match available Ollama models

#### Phase 2: Testing Infrastructure
1. Update API test functions in `tests/test_calling_apis.py`
2. Implement sequential testing to prevent resource conflicts
3. Add cloud API connectivity validation

#### Phase 3: Integration Testing
1. Validate end-to-end fuzzing workflow
2. Test analysis engine with new API responses
3. Verify reporting functionality with actual attack data

### API Authentication Management

#### Local Ollama
- No authentication required
- Direct HTTP requests to localhost
- Standard Ollama API format

#### Ollama Turbo Cloud
- API key authentication via Authorization header
- Bearer token format: `Bearer <api_key>`
- Environment variable storage: `OLLAMA_TURBO_API_KEY`

## Implementation Plan

### Task Breakdown

#### Task 1: Configuration System Updates
- **File**: `configs/config.py`
- **Changes**:
  - Update `legacy_attacker` provider to use local Ollama
  - Update `legacy_target` provider to use Ollama Turbo
  - Modify authentication configurations
  - Update model names and endpoints

#### Task 2: API Testing Updates
- **File**: `tests/test_calling_apis.py`
- **Changes**:
  - Replace LM Studio test with local Ollama test
  - Add Ollama Turbo cloud API test
  - Implement sequential testing to prevent conflicts
  - Add proper error handling for cloud service

#### Task 3: Attack Engine Integration
- **Files**: Attack engine modules
- **Changes**:
  - Verify compatibility with Ollama API responses
  - Update any LM Studio-specific handling
  - Test temperature and parameter handling

#### Task 4: Documentation Updates
- **Files**: README.md, configuration guides
- **Changes**:
  - Update setup instructions for Ollama-only architecture
  - Document Ollama Turbo API key configuration
  - Remove LM Studio references

### Risk Mitigation

#### Risk 1: Ollama Turbo Availability
- **Mitigation**: Implement fallback to local Ollama for target model
- **Implementation**: Configuration option for target model location

#### Risk 2: API Key Management
- **Mitigation**: Environment variable-based key storage
- **Implementation**: Clear documentation and validation

#### Risk 3: Model Compatibility
- **Mitigation**: Test with multiple Ollama models
- **Implementation**: Configurable model selection

## Acceptance Criteria

### Primary Success Criteria
1. **Kernel Panic Elimination**: No system crashes during API operations
2. **Unified API**: Single Ollama API format for all model interactions
3. **Cloud Integration**: Successful Ollama Turbo integration
4. **Professional Architecture**: Industry-standard toolchain

### Testing Validation
1. API connectivity tests pass for both endpoints
2. Full fuzzing workflow executes without errors
3. Analysis engine processes responses correctly
4. Reporting system generates complete reports

### Performance Benchmarks
1. No resource conflicts between local and cloud APIs
2. Response times within acceptable limits
3. Stable operation under concurrent load

## Code Standards and Quality Requirements

### Coding Style Compliance
All new and modified code implemented for this SRD must strictly adhere to the coding style rules specified in `docs/Coding_Style_Rules/CODING_STYLE_RULES.md`. This includes:

#### Functional Programming Requirements
- Prefer functional programming over object-oriented programming
- Avoid classes unless absolutely necessary
- Use pure functions when possible
- Minimize state and side effects

#### Code Structure Standards
- Write modular functions with single responsibilities
- Keep functions focused and relatively short
- Use descriptive function and variable names
- Include clear docstrings for functions using Google style

#### Error Handling Requirements
- Use explicit error handling with try/except blocks
- Specify exact exceptions to catch
- Include helpful error messages
- Document expected exceptions in docstrings

#### Type Hints and Documentation
- Use type hints for all function parameters and return values
- Employ type hints for complex variables where type is not obvious
- Use Optional[] for parameters that may be None
- Document any type-related assumptions in docstrings

#### HTTP Request Standards
- Use the Requests library for HTTP operations
- Include proper timeout settings
- Handle HTTP errors gracefully with appropriate status messages
- Log relevant request/response details at debug level

#### Professional Output Standards
- Use concise, professional output messages
- Employ color coding for different message types (error, warning, info)
- Maintain clean, minimal output formatting
- Avoid decorative characters in professional tool output

## Dependencies

### External Dependencies
- Ollama Turbo API service and account
- Local Ollama installation and configuration
- Network connectivity for cloud API access

### Internal Dependencies
- Existing analysis and reporting engine
- Attack engine modifications for Ollama compatibility
- Configuration system updates

## Future Considerations

### Extensibility
- Support for additional Ollama Turbo models
- Multi-cloud provider support
- Enhanced authentication methods

### Scalability
- Concurrent target testing with multiple cloud models
- Load balancing across Ollama Turbo endpoints
- Professional subscription tier features

## Appendix

### Ollama Turbo Model Specifications
- **gpt-oss:20b**: 20 billion parameter model, fast inference
- **gpt-oss:120b**: 120 billion parameter model, highest quality

### Configuration Examples
See technical architecture section for detailed configuration examples.

### Migration Checklist
- [ ] Update configuration files
- [ ] Modify API test functions  
- [ ] Test local Ollama connectivity
- [ ] Configure Ollama Turbo API key
- [ ] Validate end-to-end workflow
- [ ] Update documentation