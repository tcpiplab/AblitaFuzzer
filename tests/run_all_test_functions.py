import os

from colorama import Fore

from tests.test_calling_apis import test_call_abliterated_model, test_call_target_model


def run_all_test_functions(args):

    if args.proxy:

        print(f'{Fore.GREEN}[+] Testing through proxy at {args.proxy}...')
        os.environ['http_proxy'] = args.proxy
        os.environ['https_proxy'] = args.proxy

    print(f'{Fore.GREEN}[+] Testing calling the abliterated model...')
    test_call_abliterated_model()

    print(f'{Fore.GREEN}[+] Testing calling the target model...')
    test_call_target_model()

    exit()
