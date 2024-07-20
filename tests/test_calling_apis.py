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

    try:

        print(f"{Fore.GREEN}[+] Response from abliterated model:{Fore.RESET}\n  {completion.choices[0].message.content}")

    except AttributeError as e:

        # This error can happen if the abliterated model is supposed to be running on localhost (e.g., via LM Studio )
        # but its API server is actually not running at all
        print(f"{Fore.RED}[!] Error calling the abliterated model: {e}{Fore.RESET}")
        print(f"{Fore.RED}[!] This can happen if the abliterated model is supposed to be running on "
              f"localhost but its API server is actually not running at all.{Fore.RESET}")
        print(f"{Fore.RED}[!] Please make sure that the abliterated model is running and that "
              f"its API server is reachable, whether on localhost or on a remote server.{Fore.RESET}")


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
                "content": "Introduce yourself."
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

    # Check if the request was successful or if it returned a different HTTP status code
    if response.status_code == 200:

        try:
            # Print the response from the server
            print(f"{Fore.GREEN}[+] Response from target model:{Fore.RESET}\n", response.json().get("message").get("content"))

        except requests.exceptions.RequestException as e:
            # This error can happen if the target model is supposed to be running on localhost but is not actually running
            print(f"{Fore.RED}[!] Error sending request to target model:{Fore.RESET}\n  {e}")
            print(f"{Fore.RED}[!] This error can happen if the target model is unreachable, for example if the target "
                  "model is supposed to be running on localhost but is not actually running at all.")
            print(f"{Fore.RED}[!] Check that the target model is running and accessible at the target URL, "
                  f"whether on localhost or hosted on a remote server URL.{Fore.RESET}")
    else:
        # Print the error
        print(f"{Fore.RED}[!] Error from target model:{Fore.RESET}\n  {response.status_code} - {response.text}")


def main():
    # If this file is called directly by name, run both tests

    # Test the call to the abliterated model
    test_call_abliterated_model()

    # Test the call to the target model
    test_call_target_model()


# If the script is being executed directly, run the `main` function
if __name__ == '__main__':
    main()
