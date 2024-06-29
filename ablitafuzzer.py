import argparse
from openai import OpenAI
import requests
import json

def test_call_abliterated_model():

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

    print(completion.choices[0].message.content)


def test_call_target_model():

    # Define the URL for the API
    url = "http://localhost:11434/api/chat"

    # Define the payload
    payload = {
        "model": "mistral",
        "messages": [
            {
                "role": "user",
                "content": "why is the sky blue?"
            }
        ],
        "stream": False
    }

    # Set the headers
    headers = {
        "Content-Type": "application/json"
    }

    # Send the POST request
    response = requests.post(url, headers=headers, data=json.dumps(payload))

    # Check if the request was successful
    if response.status_code == 200:
        # Print the response from the server
        print("Response:", response.json())
    else:
        # Print the error
        print(f"Error: {response.status_code} - {response.text}")


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
