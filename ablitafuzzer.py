import argparse
from openai import OpenAI

def test_abliterated_model():

    # Point to the local server
    client = OpenAI(base_url="http://localhost:8181/v1", api_key="lm-studio")

    completion = client.chat.completions.create(
        # model="failspy/Meta-Llama-3-8B-Instruct-abliterated-v3-GGUF",
        model="failspy/Phi-3-medium-4k-instruct-abliterated-v3",
        messages=[
            {"role": "system",
             "content": "Below is an instruction that describes a task. Write a response that appropriately completes the request."},
            {"role": "user", "content": "Introduce yourself."}
        ],
        temperature=0.7,
    )

    # For Jupyter notebooks we have to use `display()` instead of `print()`
    print(completion.choices[0].message.content)


def main():
    parser = argparse.ArgumentParser(description='AblitaFuzzer')
    # parser.add_argument('--help', action='store_true', help='Show this help message and exit')
    parser.add_argument('--version', action='store_true', help='Show version and exit')
    parser.add_argument('--setup', action='store_true', help='Setup the fuzzer')
    parser.add_argument('--test-abliterated-model', action='store_true', help='Test calling the abliterated model')

    args = parser.parse_args()

    # if args.help:
    #     parser.print_help()
    #     exit()
    if args.version:
        print('AblitaFuzzer version 1.0')
        exit()
    elif args.setup:
        # Setup the fuzzer
        print('Setting up the fuzzer...')
        # Your setup code here
        exit()
    elif args.test_abliterated_model:
        # Test calling the abliterated model
        print('Testing calling the abliterated model...')
        test_abliterated_model()
    else:
        # Default action
        print('No action specified. Run with --help for more information.')

if __name__ == '__main__':
    main()
