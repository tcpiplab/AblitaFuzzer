import argparse
from post_attack.analyzers import run_all_analyzers
from during_attack.run_fuzz_attack import run_fuzz_attack
from tests.run_all_test_functions import run_all_test_functions
from colorama import init

# TODO: Move this to main() and test if it still works correctly
# Initialize colorama and set autoreset to True
init(autoreset=True)


def setup_arguments():
    parser = argparse.ArgumentParser(description='AblitaFuzzer')

    subparsers = parser.add_subparsers(title='subcommands', description='valid subcommands', help='additional help')

    parser.add_argument('--version', action='store_true', help='Show version and exit')
    parser.add_argument('--verbose', action='store_true', help='Print more information during runtime')

    parser_analyze = subparsers.add_parser('analyze', help='Analyze results from the most recent fuzzing attack')
    parser_analyze.set_defaults(func=run_all_analyzers)

    parser_fuzz = subparsers.add_parser('fuzz', help='Fuzz the target model')
    parser_fuzz.add_argument('--proxy', metavar='IP:PORT', help='Specify the proxy to use')
    parser_fuzz.set_defaults(func=run_fuzz_attack)

    parser_test = subparsers.add_parser('test', help='Test calling both APIs but do not fuzz')
    parser_test.add_argument('--proxy', metavar='IP:PORT', help='Specify the proxy to use')
    parser_test.set_defaults(func=run_all_test_functions)

    return parser


def main():
    parser = setup_arguments()
    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

    if args.version:
        print(f'AblitaFuzzer version 0.7-alpha')
        exit()

if __name__ == '__main__':
    main()
