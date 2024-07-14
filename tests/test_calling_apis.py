import json
import requests
from openai import OpenAI
from colorama import Fore, init

# Move this statement to main() and test that colors still work
# Initialize colorama and set autoreset to True
init(autoreset=True)


def test_call_abliterated_model():
    # TODO: Move these hardcoded values into a config file

    # Point to the local server
    client = OpenAI(base_url="http://localhost:8181/v1", api_key="lm-studio")

    completion = client.chat.completions.create(
        # model="failspy/Meta-Llama-3-8B-Instruct-abliterated-v3-GGUF",
        # model="failspy/Phi-3-medium-4k-instruct-abliterated-v3",
        model="TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF",
        messages=[
            {"role": "system",
             "content": "Below is an instruction that describes a task. Write a response that appropriately completes the request."},
            {"role": "user", "content": "Introduce yourself."}
        ],
        temperature=0.7,
    )

    print(completion.choices[0].message.content)


def test_call_target_model():
    # TODO: Move these hardcoded values into a config file

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
        print(f"{Fore.GREEN}[+] Response:", response.json())
    else:
        # Print the error
        print(f"{Fore.RED}[!] Error: {response.status_code} - {response.text}")


def main():
    # If this file is called directly by name, run both tests

    # Test the call to the abliterated model
    test_call_abliterated_model()

    # Test the call to the target model
    test_call_target_model()


# If the script is being executed directly, run the `main` function
if __name__ == '__main__':
    main()
