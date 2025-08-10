import os
import time

from colorama import Fore

from tests.test_calling_apis import test_call_ollama_attacker_model, test_call_target_model


def run_all_test_functions(args):

    if args.proxy:
        print(f'{Fore.GREEN}[+] Testing through proxy at http(s)://{args.proxy}')
        os.environ['http_proxy'] = args.proxy
        os.environ['https_proxy'] = args.proxy
        # Disable SSL verification when using proxy (for Burp Suite, etc.)
        os.environ['REQUESTS_CA_BUNDLE'] = ''
        os.environ['CURL_CA_BUNDLE'] = ''

    print(f"{Fore.BLUE}[*] Starting Ollama API connectivity tests{Fore.RESET}")
    print(f"{Fore.BLUE}[*] Running tests sequentially to prevent kernel panics{Fore.RESET}\n")

    # Test the Ollama attacker model first
    test_call_ollama_attacker_model()
    
    # Wait between tests to prevent resource conflicts
    print(f"\n{Fore.BLUE}[*] Waiting 3 seconds before next test...{Fore.RESET}")
    time.sleep(3)
    
    # Test the target model
    print(f'{Fore.GREEN}[+] Testing calling the target model...{Fore.RESET}')
    test_call_target_model()
    
    print(f"\n{Fore.BLUE}[*] API connectivity tests completed{Fore.RESET}")

    exit()
