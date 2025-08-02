# Software Requirements Document: AblitaFuzzer Configuration System Overhaul

## Document Information
- **Project**: AblitaFuzzer
- **Component**: Configuration System and API Target Management
- **Version**: 1.0
- **Date**: 2025-01-02

## Executive Summary

This SRD defines the requirements for replacing AblitaFuzzer's hardcoded localhost configuration with a flexible, professional-grade configuration system that supports real-world pentesting scenarios against production LLM APIs. The new system will enable targeting of major cloud LLM providers, enterprise APIs, and custom deployments while maintaining security best practices for credential management.

## Current State Analysis

### Current Configuration Limitations
- **Hardcoded localhost URLs**: Target API at `localhost:11434`, attacker model at `localhost:8181`
- **Fixed API formats**: Only supports Ollama-style JSON payloads
- **No authentication support**: Cannot handle API keys, bearer tokens, or custom headers
- **Single target limitation**: Cannot test multiple APIs in one engagement
- **No environment separation**: Same config for dev/test/prod scenarios
- **Embedded secrets**: API keys would need to be hardcoded in source

### Current Configuration Architecture
```python
# configs/config.py - Current problematic approach
TARGET_MODEL_API_URL = "http://localhost:11434/api/chat"
TARGET_MODEL_NAME = "gemma:2b"
ATTACK_MODEL_API_URL = "http://localhost:8181/v1"
ATTACK_MODEL_API_KEY = "lm-studio"
```

### Real-World Requirements Gap
Professional pentesting requires targeting:
- OpenAI GPT models (`https://api.openai.com/v1/chat/completions`)
- Anthropic Claude models (`https://api.anthropic.com/v1/messages`)
- Azure OpenAI deployments (`https://{resource}.openai.azure.com/openai/deployments/{model}/chat/completions`)
- Google Vertex AI endpoints
- Custom enterprise LLM deployments
- Multiple targets simultaneously for comparative testing

## Requirements

### Functional Requirements

#### FR-1: Multi-Provider API Support
- **Requirement**: Support major LLM API providers with provider-specific configurations
- **Implementation**: New module `configs/api_providers.py`
- **Details**:
  - OpenAI-compatible APIs (OpenAI, Azure OpenAI, local OpenAI-compatible)
  - Anthropic Claude API format
  - Google Vertex AI format
  - Custom API format definitions
  - Provider-specific parameter mapping (temperature, max_tokens, etc.)
  - Automatic API format detection based on provider type

#### FR-2: Flexible Authentication System
- **Requirement**: Support multiple authentication methods per API provider
- **Implementation**: New module `configs/auth_manager.py`
- **Details**:
  - API key authentication (header-based)
  - Bearer token authentication
  - Custom header authentication
  - OAuth 2.0 flow support for enterprise deployments
  - Azure AD integration for Azure OpenAI
  - Environment variable integration for secrets
  - Credential validation before test execution

#### FR-3: Environment-Based Configuration
- **Requirement**: Support multiple configuration environments and profiles
- **Implementation**: New configuration file structure and loader
- **Details**:
  - Development, staging, production environment configs
  - Named profiles for different clients or engagements
  - Configuration inheritance and overrides
  - Environment variable substitution
  - Profile switching via CLI arguments
  - Configuration validation per environment

#### FR-4: Network and Performance Configuration
- **Requirement**: Configurable network settings for enterprise environments
- **Implementation**: Extend configuration system with networking section
- **Details**:
  - Proxy configuration (HTTP/HTTPS/SOCKS)
  - Request timeout settings (connection, read, total)
  - Rate limiting configuration per provider
  - Retry logic configuration (attempts, backoff strategy)
  - TLS/SSL configuration and certificate handling
  - User-Agent string customization

#### FR-5: Target Management System
- **Requirement**: Support multiple target APIs in single engagement
- **Implementation**: New module `configs/target_manager.py`
- **Details**:
  - Define multiple target APIs with different configurations
  - Group targets by engagement or test scenario
  - Sequential or parallel testing of multiple targets
  - Target-specific attack configurations
  - Results correlation across multiple targets
  - Target health checking and availability validation

#### FR-6: Configuration Validation and Error Handling
- **Requirement**: Comprehensive validation of all configuration parameters
- **Implementation**: New module `configs/validator.py`
- **Details**:
  - Schema validation for configuration files
  - Network connectivity testing for target APIs
  - Authentication credential validation
  - Configuration completeness checking
  - Clear error messages for misconfigurations
  - Configuration troubleshooting guidance

### Non-Functional Requirements

#### NFR-1: Security Requirements
- Secrets must never be stored in configuration files or source code
- Environment variables must be used for all sensitive credentials
- Configuration files must support credential references, not values
- Audit logging of configuration changes and credential usage
- Support for encrypted configuration files in sensitive environments

#### NFR-2: Usability Requirements
- Configuration must be manageable via both files and CLI arguments
- Clear documentation and examples for each supported provider
- Configuration templates for common scenarios
- Interactive configuration wizard for initial setup
- Configuration validation with helpful error messages

#### NFR-3: Performance Requirements
- Configuration loading must complete in under 500ms
- Target validation must not significantly delay test execution
- Support for configuration caching to avoid repeated validation
- Lazy loading of provider-specific modules

#### NFR-4: Reliability Requirements
- Graceful degradation when some targets are unavailable
- Automatic retry logic for transient authentication failures
- Configuration backup and recovery mechanisms
- Rolling back to previous working configurations

## Implementation Specifications

### Configuration File Structure

```yaml
# ~/.ablitafuzzer/config.yaml
version: "1.0"

# Global settings
global:
  proxy:
    http: "${HTTP_PROXY}"
    https: "${HTTPS_PROXY}"
  timeout:
    connection: 30
    read: 60
    total: 120
  retry:
    attempts: 3
    backoff: "exponential"
    max_delay: 30

# Environment configurations
environments:
  development:
    log_level: "DEBUG"
    rate_limit: 1  # requests per second
    
  production:
    log_level: "INFO"
    rate_limit: 10
    require_confirmation: true

# Provider configurations
providers:
  openai:
    type: "openai"
    base_url: "https://api.openai.com/v1"
    auth:
      type: "api_key"
      header: "Authorization"
      format: "Bearer ${OPENAI_API_KEY}"
    models:
      - "gpt-4"
      - "gpt-3.5-turbo"
    
  anthropic:
    type: "anthropic"
    base_url: "https://api.anthropic.com/v1"
    auth:
      type: "api_key"
      header: "x-api-key"
      format: "${ANTHROPIC_API_KEY}"
    models:
      - "claude-3-opus-20240229"
      - "claude-3-sonnet-20240229"
  
  azure_openai:
    type: "azure_openai"
    base_url: "https://${AZURE_RESOURCE}.openai.azure.com"
    auth:
      type: "api_key"
      header: "api-key"
      format: "${AZURE_OPENAI_API_KEY}"
    api_version: "2023-12-01-preview"
    deployment: "${AZURE_DEPLOYMENT_NAME}"

# Target definitions for specific engagements
targets:
  client_prod_openai:
    provider: "openai"
    model: "gpt-4"
    description: "Client production OpenAI deployment"
    
  client_azure_test:
    provider: "azure_openai"
    model: "gpt-35-turbo"
    description: "Client Azure OpenAI test environment"
    
  internal_test:
    provider: "custom"
    base_url: "https://internal-llm.company.com/v1"
    auth:
      type: "bearer"
      token: "${INTERNAL_API_TOKEN}"

# Attack configurations
attack:
  attacker_model:
    provider: "openai"  # Can use any configured provider
    model: "gpt-4"
    temperature: 0.7
    
  analyzer_model:
    provider: "openai"
    model: "gpt-3.5-turbo"
    temperature: 0.3

# Campaign configurations
campaigns:
  standard_pentest:
    targets: ["client_prod_openai", "client_azure_test"]
    datasets: ["advbench_harmful", "jailbreak_2023"]
    concurrent_targets: 2
    
  quick_assessment:
    targets: ["client_prod_openai"]
    datasets: ["advbench_harmful"]
    prompt_limit: 20
```

### Configuration Loading Architecture

```python
# configs/config_loader.py
class ConfigurationManager:
    def __init__(self, config_path=None, environment=None, profile=None):
        self.config_path = config_path or self._get_default_config_path()
        self.environment = environment or os.getenv('ABLITAFUZZER_ENV', 'development')
        self.profile = profile
        self.config = self._load_and_validate_config()
    
    def get_target_config(self, target_name):
        """Get complete configuration for a specific target"""
        
    def get_provider_config(self, provider_name):
        """Get provider-specific configuration with auth resolution"""
        
    def validate_target_connectivity(self, target_name):
        """Test network connectivity and auth to target"""
        
    def list_available_targets(self):
        """List all configured targets with status"""
```

### API Provider Abstraction

```python
# configs/api_providers.py
class BaseAPIProvider:
    def format_request(self, prompt, model_params):
        """Format request for this provider's API"""
        
    def parse_response(self, response):
        """Parse response from this provider's API"""
        
    def get_auth_headers(self, auth_config):
        """Generate authentication headers"""

class OpenAIProvider(BaseAPIProvider):
    def format_request(self, prompt, model_params):
        return {
            "model": model_params["model"],
            "messages": [{"role": "user", "content": prompt}],
            "temperature": model_params.get("temperature", 0.7)
        }

class AnthropicProvider(BaseAPIProvider):
    def format_request(self, prompt, model_params):
        return {
            "model": model_params["model"],
            "max_tokens": model_params.get("max_tokens", 1000),
            "messages": [{"role": "user", "content": prompt}]
        }
```

### Environment Variable Integration

```python
# configs/env_resolver.py
class EnvironmentResolver:
    @staticmethod
    def resolve_env_vars(config_value):
        """Resolve ${VAR_NAME} references in configuration values"""
        
    @staticmethod
    def validate_required_env_vars(config):
        """Ensure all required environment variables are set"""
        
    @staticmethod
    def get_env_var_template():
        """Generate template .env file for user reference"""
```

## File Modifications Required

### New Files to Create
1. `configs/config_loader.py` - Main configuration management
2. `configs/api_providers.py` - API provider implementations
3. `configs/auth_manager.py` - Authentication handling
4. `configs/target_manager.py` - Target configuration management
5. `configs/validator.py` - Configuration validation
6. `configs/env_resolver.py` - Environment variable resolution
7. `configs/migration.py` - Migration from old config format
8. `tests/test_config_system.py` - Comprehensive config system tests
9. `configs/templates/` - Configuration templates for common scenarios

### Existing Files to Modify
1. `configs/config.py` - Replace with new configuration loader
2. `during_attack/run_fuzz_attack.py` - Use new target management system
3. `tests/test_calling_apis.py` - Update for new configuration system
4. `ablitafuzzer.py` - Add configuration management CLI commands
5. `pre_attack/pre_attack_functions.py` - Use new API provider system
6. `post_attack/analyzers/llm_results_analyzer.py` - Use new config for analyzer models
7. `README.md` - Update with new configuration documentation

### Configuration Templates to Create
1. `configs/templates/openai.yaml` - OpenAI configuration template
2. `configs/templates/anthropic.yaml` - Anthropic configuration template
3. `configs/templates/azure_openai.yaml` - Azure OpenAI configuration template
4. `configs/templates/enterprise.yaml` - Enterprise deployment template
5. `configs/templates/multi_target.yaml` - Multi-target engagement template

## CLI Integration

### New CLI Commands
```bash
# Configuration management
ablitafuzzer config init                    # Interactive configuration wizard
ablitafuzzer config validate               # Validate current configuration
ablitafuzzer config list-targets           # List available targets
ablitafuzzer config test-target <name>     # Test connectivity to specific target
ablitafuzzer config list-providers         # Show supported API providers
ablitafuzzer config migrate                # Migrate from old configuration

# Environment management
ablitafuzzer config set-env <environment>  # Switch environment (dev/staging/prod)
ablitafuzzer config show-env               # Show current environment configuration

# Target management
ablitafuzzer targets list                  # List configured targets with status
ablitafuzzer targets add <name>            # Add new target interactively
ablitafuzzer targets remove <name>         # Remove target configuration
ablitafuzzer targets test <name>           # Test specific target

# Campaign execution with new config
ablitafuzzer fuzz --target <name>          # Fuzz specific target
ablitafuzzer fuzz --campaign <name>        # Run predefined campaign
ablitafuzzer fuzz --environment <env>      # Use specific environment
```

## Testing Requirements

### Unit Tests
- Configuration file parsing and validation
- Environment variable resolution
- API provider request/response formatting
- Authentication header generation
- Target connectivity testing
- Error handling for malformed configurations

### Integration Tests
- End-to-end configuration loading and usage
- Authentication with real API providers (using test credentials)
- Multi-target execution scenarios
- Environment switching functionality
- Configuration migration from old format

### Manual Testing Scenarios
- Initial setup with configuration wizard
- Authentication failure handling
- Network connectivity issues
- Rate limiting behavior
- Configuration validation with various error conditions

## Migration Strategy

### Phase 1: Core Infrastructure
1. Implement configuration loading and validation system
2. Create API provider abstraction layer
3. Implement authentication management
4. Build configuration templates

### Phase 2: Integration
1. Update existing modules to use new configuration system
2. Implement CLI configuration management commands
3. Create migration utility from old hardcoded approach
4. Add comprehensive error handling and user feedback

### Phase 3: Professional Features
1. Add multi-target campaign support
2. Implement advanced networking features (proxy, TLS)
3. Add configuration backup and recovery
4. Create deployment automation for enterprise scenarios

## Security Considerations

### Credential Management
- All sensitive credentials must be stored as environment variables
- Configuration files must only contain credential references
- Support for encrypted configuration files in high-security environments
- Audit logging of credential usage and configuration changes

### Network Security
- TLS certificate validation for all HTTPS connections
- Support for custom CA certificates in enterprise environments
- Proxy authentication support for corporate networks
- Network traffic logging for compliance requirements

### Access Control
- Configuration file permissions must be restricted (600)
- Support for role-based configuration access
- Integration with enterprise identity providers
- Configuration change approval workflows for production environments

## Success Criteria

- Tool can target any major LLM API provider without code changes
- Authentication works seamlessly with environment variable integration
- Multiple targets can be configured and tested in single engagement
- Configuration is self-documenting and easy to troubleshoot
- Migration from current hardcoded approach is seamless
- Professional deployment scenarios are fully supported

## Dependencies

### External Dependencies
- `pyyaml` - Configuration file parsing
- `jsonschema` - Configuration validation
- `requests` - HTTP client (already present)
- `cryptography` - For encrypted configuration file support

### Internal Dependencies
- Existing CLI framework in `ablitafuzzer.py`
- Download manager from previous SRD
- Existing error handling patterns
- Current API calling infrastructure

## Risk Mitigation

### Risk: Configuration complexity overwhelms users
- **Mitigation**: Interactive configuration wizard and comprehensive templates

### Risk: Authentication failures disrupt testing
- **Mitigation**: Pre-flight connectivity and auth testing with clear error messages

### Risk: Migration breaks existing setups
- **Mitigation**: Backwards compatibility mode and comprehensive migration testing

### Risk: Performance impact from configuration overhead
- **Mitigation**: Configuration caching and lazy loading of provider modules

### Risk: Security vulnerabilities in credential handling
- **Mitigation**: Security review of all credential handling code and comprehensive audit logging