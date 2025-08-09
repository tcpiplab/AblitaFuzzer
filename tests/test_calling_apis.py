import json
import time
import requests
from configs import config as config
from colorama import Fore, init

# Move this statement to main() and test that colors still work
# Initialize colorama and set autoreset to True
init(autoreset=True)


def test_call_ollama_attacker_model():
    """Test calling the local Ollama attacker model using native Ollama API format."""
    
    print(f'{Fore.GREEN}[+] Testing calling the Ollama attacker model at {config.ATTACK_MODEL_API_URL}{Fore.RESET}')

    # Define the payload for Ollama API
    payload = {
        "model": config.ATTACK_MODEL_NAME,
        "messages": [
            {
                "role": "system",
                "content": "Below is an instruction that describes a task. Write a response that appropriately completes the request."
            },
            {
                "role": "user",
                "content": "Introduce yourself."
            }
        ],
        "stream": False,
        "options": {
            "temperature": config.ATTACK_MODEL_TEMPERATURE
        }
    }

    # Set the headers for Ollama API
    headers = {
        "Content-Type": "application/json"
    }

    try:
        # Build the full API URL for native Ollama API
        api_url = config.ATTACK_MODEL_API_URL
        # If URL ends with /v1, replace with /api/chat for native API
        if api_url.endswith('/v1'):
            api_url = api_url.rstrip('/v1') + '/api/chat'
        elif not api_url.endswith('/api/chat'):
            api_url = api_url.rstrip('/') + '/api/chat'
        
        # Send the POST request to Ollama
        response = requests.post(api_url, 
                               headers=headers, 
                               data=json.dumps(payload),
                               timeout=30)

        if response.status_code == 200:
            response_data = response.json()
            message_content = response_data.get("message", {}).get("content", "")
            print(f"{Fore.GREEN}[+] Response from Ollama attacker model:{Fore.RESET}\n  {message_content}")
        else:
            print(f"{Fore.RED}[!] Error from Ollama attacker model:{Fore.RESET}\n  {response.status_code} - {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error calling the Ollama attacker model: {e}{Fore.RESET}")
        print(f"{Fore.RED}[!] This can happen if Ollama is not running on localhost or the model is not loaded.{Fore.RESET}")
        print(f"{Fore.RED}[!] Please ensure Ollama is running and the model '{config.ATTACK_MODEL_NAME}' is available.{Fore.RESET}")

    except json.JSONDecodeError as e:
        print(f"{Fore.RED}[!] Invalid JSON response from Ollama attacker model: {e}{Fore.RESET}")

    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error calling Ollama attacker model: {e}{Fore.RESET}")


def test_call_target_model():
    """Test calling the target model using Ollama API format."""
    
    print(f'{Fore.GREEN}[+] Testing calling the target model at {config.TARGET_MODEL_API_URL}{Fore.RESET}')

    # Define the payload for Ollama API
    payload = {
        "model": config.TARGET_MODEL_NAME,
        "messages": [
            {
                "role": "user",
                "content": "Introduce yourself."
            }
        ],
        "stream": False
    }

    # Set the headers for Ollama API
    headers = {
        "Content-Type": "application/json"
    }
    
    # Add authentication for cloud services if URL is HTTPS
    if config.TARGET_MODEL_API_URL.startswith("https://"):
        import os
        api_key = os.getenv('OLLAMA_TURBO_API_KEY')
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        else:
            print(f"{Fore.YELLOW}[!] Warning: Cloud target URL detected but no OLLAMA_TURBO_API_KEY environment variable set{Fore.RESET}")
            print(f"{Fore.YELLOW}[!] This test may fail without proper authentication{Fore.RESET}")

    try:
        # Build the full API URL (use v1 for cloud, api/chat for local)
        api_url = config.TARGET_MODEL_API_URL
        if config.TARGET_MODEL_API_URL.startswith("https://ollama.com"):
            # Cloud service - use OpenAI-compatible endpoint
            if not api_url.endswith('/v1/chat/completions'):
                api_url = api_url.rstrip('/') + '/v1/chat/completions'
        else:
            # Local service - use native Ollama endpoint
            if not api_url.endswith('/api/chat'):
                api_url = api_url.rstrip('/') + '/api/chat'
        
        # Send the POST request with timeout
        response = requests.post(api_url, 
                               headers=headers, 
                               data=json.dumps(payload),
                               timeout=30)

        if response.status_code == 200:
            response_data = response.json()
            message_content = response_data.get("message", {}).get("content", "")
            print(f"{Fore.GREEN}[+] Response from target model:{Fore.RESET}\n  {message_content}")
        else:
            print(f"{Fore.RED}[!] Error from target model:{Fore.RESET}\n  {response.status_code} - {response.text}")

    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error calling the target model: {e}{Fore.RESET}")
        print(f"{Fore.RED}[!] This can happen if the target model is unreachable or not running.{Fore.RESET}")
        print(f"{Fore.RED}[!] Check that the model '{config.TARGET_MODEL_NAME}' is available at {config.TARGET_MODEL_API_URL}{Fore.RESET}")

    except json.JSONDecodeError as e:
        print(f"{Fore.RED}[!] Invalid JSON response from target model: {e}{Fore.RESET}")

    except Exception as e:
        print(f"{Fore.RED}[!] Unexpected error calling target model: {e}{Fore.RESET}")


def main():
    """Run API connectivity tests sequentially to prevent resource conflicts."""
    
    print(f"{Fore.BLUE}[*] Starting Ollama API connectivity tests{Fore.RESET}")
    print(f"{Fore.BLUE}[*] Running tests sequentially to prevent kernel panics{Fore.RESET}\n")

    # Test the Ollama attacker model first
    test_call_ollama_attacker_model()
    
    # Wait between tests to prevent resource conflicts
    print(f"\n{Fore.BLUE}[*] Waiting 3 seconds before next test...{Fore.RESET}")
    time.sleep(3)
    
    # Test the target model
    test_call_target_model()
    
    print(f"\n{Fore.BLUE}[*] API connectivity tests completed{Fore.RESET}")


# If the script is being executed directly, run the `main` function
if __name__ == '__main__':
    main()
