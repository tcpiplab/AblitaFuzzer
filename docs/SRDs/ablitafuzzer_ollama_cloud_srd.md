# Software Requirements Document: AblitaFuzzer Ollama Cloud Target Integration

## Document Information
- **Project**: AblitaFuzzer
- **Component**: Ollama Cloud Target Integration
- **Version**: 1.0
- **Date**: 2025-01-09

## Executive Summary

This supplemental SRD defines the requirements for configuring AblitaFuzzer to use Ollama cloud services as the target model while maintaining local Ollama instances for attack generation and response analysis. This focused modification enables professional penetration testing against cloud-hosted LLM services while preserving the security benefits of local attack model operation.

## Current State Analysis

### Current Target Model Configuration
AblitaFuzzer currently uses hardcoded localhost configuration for all three model components:

```python
# configs/config.py - Current target model configuration
TARGET_MODEL_API_URL = "http://localhost:11434/api/chat"
TARGET_MODEL_NAME = "gemma:2b"
```

```python
# during_attack/run_fuzz_attack.py - Current request implementation
payload = {
    "model": config.TARGET_MODEL_NAME,
    "messages": [{"role": "user", "content": wrapped_prompt}],
    "stream": False
}
response = session.post(config.TARGET_MODEL_API_URL, headers=headers, data=json.dumps(payload))
```

### Architecture Clarification
AblitaFuzzer operates with three distinct model roles:

1. **Attack Model** (generates malicious prompts) - **REMAINS LOCAL** at `localhost:8181`
2. **Target Model** (LLM being tested) - **CHANGES TO OLLAMA CLOUD**
3. **Analyzer Model** (judges attack success) - **REMAINS LOCAL** (same as attack model)

## Requirements

### Functional Requirements

#### FR-1: Ollama Cloud Authentication
- **Requirement**: Support Bearer token authentication for Ollama cloud API access
- **Implementation**: Environment variable integration following security best practices
- **Details**:
  - API key must be stored in environment variable `OLLAMA_API_KEY`
  - Authentication header format: `Authorization: Bearer {api_key}`
  - Graceful error handling for missing or invalid API keys
  - No hardcoded credentials in source code or configuration files

#### FR-2: Cloud Endpoint Configuration
- **Requirement**: Configure target model to use Ollama cloud endpoints
- **Implementation**: Modify target model configuration while preserving local model settings
- **Details**:
  - Target API URL: `https://ollama.com/api/chat` (native Ollama format)
  - Target model name: `gpt-oss:120b` (cloud model specification)
  - Maintain existing local attack and analyzer model configurations
  - Support both HTTP and HTTPS with proper TLS validation

#### FR-3: Request Authentication Integration
- **Requirement**: Add authentication headers to target model requests only
- **Implementation**: Modify attack execution logic to include Bearer token
- **Details**:
  - Preserve existing request structure and error handling
  - Add authentication headers only for target model requests
  - Maintain existing unique attack ID headers for Burp Suite correlation
  - Support existing proxy configuration options

#### FR-4: Error Handling and Validation
- **Requirement**: Robust error handling for cloud API failures
- **Implementation**: Explicit exception handling following coding style guidelines
- **Details**:
  - API key validation before attack execution
  - Network connectivity validation to cloud endpoints
  - HTTP status code handling (401 Unauthorized, 429 Rate Limited, etc.)
  - Clear error messages for authentication and network failures
  - Graceful degradation with informative user feedback

### Non-Functional Requirements

#### NFR-1: Security Requirements
- API keys must be managed through environment variables only
- No sensitive credentials in configuration files or source code
- Support for existing proxy configurations for corporate environments
- Maintain audit trail compatibility with existing attack ID system

#### NFR-2: Compatibility Requirements
- Preserve all existing local model functionality
- Maintain compatibility with existing CLI arguments and proxy settings
- No changes to attack generation or analysis pipeline
- Backward compatibility with existing configuration files

#### NFR-3: Performance Requirements
- Cloud API requests must not significantly impact attack execution time
- Proper timeout handling for network requests
- Support for existing rate limiting and delay configurations

## Implementation Specifications

### Environment Variable Configuration

```python
# configs/config.py - Updated configuration
import os

## Target LLM API Settings (Ollama Cloud)
TARGET_MODEL_API_URL = "https://ollama.com/api/chat"
TARGET_MODEL_NAME = "gpt-oss:120b"
TARGET_MODEL_API_KEY = os.getenv('OLLAMA_API_KEY')

## Attack/Analyzer LLM API Settings (Local - Unchanged)
ATTACK_MODEL_API_URL = "http://localhost:8181/v1"
ATTACK_MODEL_API_KEY = "lm-studio"
ATTACK_MODEL_NAME = "TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf"

ANALYZER_MODEL_API_URL = "http://localhost:8181/v1"
ANALYZER_MODEL_API_KEY = "lm-studio"
ANALYZER_MODEL_NAME = "TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf"
```

### Authentication Validation Function

```python
# utilities/auth_utilities.py - New authentication validation
import os
from typing import Optional
from colorama import Fore


def validate_ollama_api_key() -> Optional[str]:
    """
    Validate that Ollama API key is available in environment.
    
    Returns:
        API key string if valid, None if missing or invalid
        
    Raises:
        ValueError: If API key is missing from environment
    """
    api_key = os.getenv('OLLAMA_API_KEY')
    
    if not api_key:
        raise ValueError(
            f"{Fore.RED}[!] OLLAMA_API_KEY environment variable is required for cloud target testing.\n"
            f"[!] Get your API key from https://ollama.com/settings/keys\n"
            f"[!] Set it with: export OLLAMA_API_KEY=sk-your-key-here{Fore.RESET}"
        )
    
    if not api_key.startswith('sk-'):
        raise ValueError(
            f"{Fore.RED}[!] Invalid OLLAMA_API_KEY format. Key should start with 'sk-'{Fore.RESET}"
        )
    
    return api_key


def generate_ollama_auth_headers(api_key: str) -> dict:
    """
    Generate authentication headers for Ollama cloud API.
    
    Args:
        api_key: Valid Ollama API key
        
    Returns:
        Dictionary containing Authorization header
    """
    return {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
```

### Modified Attack Execution

```python
# during_attack/run_fuzz_attack.py - Updated attack_target_model_api function
import json
import time
import requests
from colorama import Fore

from configs import config
from utilities.auth_utilities import validate_ollama_api_key, generate_ollama_auth_headers
from utilities.http_utilities import generate_unique_http_header
from utilities.text_utilities import wrap_prompt_with_delimiters, vprint


def attack_target_model_api(args, session, prompt_styles_config, prompts, model_name):
    """
    Execute attacks against target model with Ollama cloud authentication.
    
    Args:
        args: Command line arguments
        session: Requests session with proxy configuration
        prompt_styles_config: Prompt formatting configuration
        prompts: List of attack prompts to execute
        model_name: Target model style identifier
        
    Returns:
        List of attack results with responses and metadata
    """
    delimiter_start = prompt_styles_config[model_name]['delimiter_start']
    delimiter_end = prompt_styles_config[model_name]['delimiter_end']
    results = []

    # Validate Ollama API key before starting attacks
    try:
        api_key = validate_ollama_api_key()
        base_auth_headers = generate_ollama_auth_headers(api_key)
        print(f"{Fore.GREEN}[+] Ollama cloud authentication validated{Fore.RESET}")
    except ValueError as e:
        print(str(e))
        return []

    try:
        i = 0
        for prompt in prompts:
            try:
                wrapped_prompt = wrap_prompt_with_delimiters(prompt, delimiter_start, delimiter_end)
            except Exception as e:
                print(f"{Fore.YELLOW}[*] Failed to wrap the prompt with delimiters: {e}")
                continue

            try:
                # Construct payload for Ollama cloud API
                payload = {
                    "model": config.TARGET_MODEL_NAME,
                    "messages": [{"role": "user", "content": wrapped_prompt}],
                    "stream": False
                }
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to construct the payload for the attack: {e}")
                return results

            try:
                # Generate unique header for Burp Suite correlation
                new_ablitafuzzer_http_header = generate_unique_http_header()
                
                # Combine authentication and tracking headers
                headers = {
                    **base_auth_headers,
                    new_ablitafuzzer_http_header[0]: new_ablitafuzzer_http_header[1]
                }

                print(f"{Fore.GREEN}[+] Attack payload #{i + 1} unique attack header: "
                      f"{new_ablitafuzzer_http_header[0]}: {new_ablitafuzzer_http_header[1]}")
                print(f"{Fore.GREEN}[+]   {prompt}")

            except Exception as e:
                print(f"{Fore.RED}[!] Error generating unique attack header: {e}")
                return results

            try:
                vprint(args, f"{Fore.YELLOW}[!]   config.TARGET_MODEL_API_URL: {config.TARGET_MODEL_API_URL}")
                vprint(args, f"{Fore.GREEN}[+]   Attack payload #{i + 1} will be sent to target model API: "
                            f"{config.TARGET_MODEL_API_URL}")
                
                # Send request to Ollama cloud
                response = session.post(
                    config.TARGET_MODEL_API_URL, 
                    headers=headers, 
                    data=json.dumps(payload),
                    timeout=60
                )

                print(f"{Fore.GREEN}[+]   Attack payload #{i + 1}. Response: {response.status_code}")
                i += 1

            except requests.exceptions.Timeout:
                print(f"{Fore.RED}[!]   Timeout sending attack payload #{i + 1} to Ollama cloud")
                results.append({
                    "prompt": wrapped_prompt,
                    "error": "Request timeout to Ollama cloud API",
                    "attack_id": new_ablitafuzzer_http_header[1]
                })
                continue
            except requests.exceptions.ConnectionError as e:
                print(f"{Fore.RED}[!]   Connection error sending attack payload #{i + 1}: {e}")
                results.append({
                    "prompt": wrapped_prompt,
                    "error": f"Connection error to Ollama cloud: {str(e)}",
                    "attack_id": new_ablitafuzzer_http_header[1]
                })
                continue
            except Exception as e:
                print(f"{Fore.RED}[!]   Error sending attack payload #{i + 1} to target model API: {e}")
                results.append({
                    "prompt": wrapped_prompt,
                    "error": f"Unexpected error: {str(e)}",
                    "attack_id": new_ablitafuzzer_http_header[1]
                })
                continue

            # Handle response based on status code
            if response.status_code == 200:
                try:
                    response_data = response.json()
                    results.append({
                        "prompt": wrapped_prompt,
                        "response": response_data,
                        "attack_id": new_ablitafuzzer_http_header[1]
                    })
                except json.JSONDecodeError as e:
                    print(f"{Fore.RED}[!] Invalid JSON response from Ollama cloud: {e}")
                    results.append({
                        "prompt": wrapped_prompt,
                        "error": f"Invalid JSON response: {response.text[:200]}",
                        "attack_id": new_ablitafuzzer_http_header[1]
                    })
            elif response.status_code == 401:
                print(f"{Fore.RED}[!] Authentication failed - check OLLAMA_API_KEY")
                results.append({
                    "prompt": wrapped_prompt,
                    "error": "Authentication failed - invalid API key",
                    "attack_id": new_ablitafuzzer_http_header[1]
                })
            elif response.status_code == 429:
                print(f"{Fore.YELLOW}[*] Rate limited by Ollama cloud - implementing backoff")
                time.sleep(5)  # Simple backoff for rate limiting
                results.append({
                    "prompt": wrapped_prompt,
                    "error": "Rate limited by Ollama cloud API",
                    "attack_id": new_ablitafuzzer_http_header[1]
                })
            else:
                error_msg = f"Error returned from Ollama cloud API: {response.status_code} - {response.text[:200]}"
                print(f"{Fore.RED}[!] {error_msg}")
                results.append({
                    "prompt": wrapped_prompt,
                    "error": error_msg,
                    "attack_id": new_ablitafuzzer_http_header[1]
                })

            # Maintain existing delay between requests
            time.sleep(0.5)

    except Exception as e:
        print(f"{Fore.RED}[!] Error preparing to send payloads to target model API: {e}")
        return results

    return results
```

### Updated Test Function

```python
# tests/test_calling_apis.py - Updated target model test
import json
import requests
from colorama import Fore

from configs import config
from utilities.auth_utilities import validate_ollama_api_key, generate_ollama_auth_headers


def test_call_target_model():
    """Test connectivity to Ollama cloud target model."""
    
    try:
        # Validate API key
        api_key = validate_ollama_api_key()
        headers = generate_ollama_auth_headers(api_key)
        
        # Test payload
        payload = {
            "model": config.TARGET_MODEL_NAME,
            "messages": [{"role": "user", "content": "Introduce yourself."}],
            "stream": False
        }

        print(f"{Fore.GREEN}[+] Testing connection to Ollama cloud target model...")
        
        # Send test request
        response = requests.post(
            config.TARGET_MODEL_API_URL, 
            headers=headers, 
            data=json.dumps(payload),
            timeout=30
        )

        if response.status_code == 200:
            try:
                response_data = response.json()
                content = response_data.get("message", {}).get("content", "No content")
                print(f"{Fore.GREEN}[+] Response from Ollama cloud target model:{Fore.RESET}\n  {content}")
            except json.JSONDecodeError as e:
                print(f"{Fore.RED}[!] Invalid JSON response from Ollama cloud: {e}")
        elif response.status_code == 401:
            print(f"{Fore.RED}[!] Authentication failed - check OLLAMA_API_KEY")
        else:
            print(f"{Fore.RED}[!] Error from Ollama cloud: {response.status_code} - {response.text}")

    except ValueError as e:
        print(str(e))
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error connecting to Ollama cloud: {e}")
        print(f"{Fore.RED}[!] Check network connectivity and API endpoint availability")
```

## File Modifications Required

### New Files to Create
1. `utilities/auth_utilities.py` - Authentication validation and header generation functions

### Existing Files to Modify
1. `configs/config.py` - Update target model configuration for Ollama cloud
2. `during_attack/run_fuzz_attack.py` - Modify `attack_target_model_api()` function
3. `tests/test_calling_apis.py` - Update `test_call_target_model()` function
4. `README.md` - Add Ollama cloud setup instructions
5. `.gitignore` - Ensure `.env` files are ignored (if not already present)

### Configuration Changes Required
```python
# Example environment variable setup
OLLAMA_API_KEY=sk-your-actual-api-key-from-ollama-settings
```

## Setup Instructions

### Prerequisites
1. Create Ollama cloud account at `https://ollama.com`
2. Generate API key at `https://ollama.com/settings/keys`
3. Ensure local Ollama is running for attack and analyzer models

### Environment Configuration
```bash
# Set Ollama cloud API key
export OLLAMA_API_KEY=sk-your-actual-api-key-here

# Verify configuration
echo $OLLAMA_API_KEY
```

### Testing Procedure
```bash
# Test all APIs (local attack/analyzer + cloud target)
python3 ablitafuzzer.py test

# Run attack campaign against Ollama cloud target
python3 ablitafuzzer.py fuzz

# Use with proxy for traffic analysis
python3 ablitafuzzer.py fuzz --proxy 127.0.0.1:8080
```

## Error Handling and Troubleshooting

### Common Issues and Solutions

#### Missing API Key
**Error**: `OLLAMA_API_KEY environment variable is required`
**Solution**: Set environment variable with valid API key from Ollama settings

#### Authentication Failure
**Error**: `Authentication failed - check OLLAMA_API_KEY`
**Solution**: Verify API key is correct and active in Ollama cloud settings

#### Network Connectivity
**Error**: `Connection error to Ollama cloud`
**Solution**: Check internet connectivity and corporate firewall/proxy settings

#### Rate Limiting
**Error**: `Rate limited by Ollama cloud API`
**Solution**: Increase delay between requests or implement exponential backoff

## Testing Requirements

### Unit Tests
- API key validation with various input scenarios
- Authentication header generation accuracy
- Error handling for missing credentials
- Network timeout and connection error handling

### Integration Tests
- End-to-end attack execution against Ollama cloud
- Proxy configuration compatibility with cloud endpoints
- Local model functionality preservation
- Error recovery and graceful degradation

### Manual Testing Scenarios
- First-time setup with API key configuration
- Network connectivity issues simulation
- API key rotation and re-authentication
- Mixed local/cloud operation validation

## Success Criteria

- Target model successfully connects to Ollama cloud with authentication
- Attack and analyzer models continue operating locally without changes
- Existing CLI arguments and proxy settings remain functional
- Clear error messages guide users through setup and troubleshooting
- No hardcoded credentials exist in source code
- All tests pass with both local and cloud configurations

## Dependencies

### External Dependencies
- `requests` - HTTP client for cloud API calls (already present)
- `colorama` - Terminal output formatting (already present)

### Internal Dependencies
- Existing configuration system in `configs/config.py`
- Existing HTTP utilities and error handling patterns
- Current CLI framework and proxy support
- Attack execution pipeline in `during_attack/run_fuzz_attack.py`

## Security Considerations

### API Key Management
- API keys must only be stored in environment variables
- No credentials in configuration files or source code
- Clear documentation for secure key rotation procedures
- Audit logging compatibility with existing attack ID system

### Network Security
- TLS validation enforced for HTTPS connections to Ollama cloud
- Support for corporate proxy configurations
- Request timeout implementation to prevent hanging connections
- Clear separation between local and cloud authentication methods

## Risk Mitigation

### Risk: API key exposure in logs or configuration
- **Mitigation**: Environment variable usage and explicit logging exclusions

### Risk: Cloud service unavailability disrupts testing
- **Mitigation**: Clear error messages and graceful failure handling

### Risk: Authentication failures during long test campaigns
- **Mitigation**: Pre-flight validation and mid-campaign error recovery

### Risk: Network issues in corporate environments
- **Mitigation**: Proxy support preservation and timeout configuration