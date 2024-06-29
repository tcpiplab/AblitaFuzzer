import argparse

from tests.test_calling_apis import test_call_abliterated_model, test_call_target_model


def main():
    parser = argparse.ArgumentParser(description='AblitaFuzzer')
    parser.add_argument('--version', action='store_true', help='Show version and exit')
    parser.add_argument('--setup', action='store_true', help='Setup the fuzzer')
    parser.add_argument('--test-call-abliterated-model', action='store_true', help='Test calling the abliterated model')
    parser.add_argument('--test-call-target-model', action='store_true', help='Test calling the target model')

    args = parser.parse_args()

    if args.version:
        print('AblitaFuzzer version 1.0')
        exit()
    elif args.setup:
        # Setup the fuzzer
        print('Setting up the fuzzer...')
        # Your setup code here
        exit()
    elif args.test_call_abliterated_model:
        # Test calling the abliterated model
        print('Testing calling the abliterated model...')
        test_call_abliterated_model()
    elif args.test_call_target_model:
        # Test calling the target model
        print('Testing calling the target model...')
        test_call_target_model()
    else:
        # Default action
        print('No action specified. Run with --help for more information.')

if __name__ == '__main__':
    main()
