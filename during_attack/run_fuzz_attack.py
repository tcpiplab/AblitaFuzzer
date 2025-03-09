import json
import time

import requests
from colorama import Fore

from pre_attack.pre_attack_functions import generate_malicious_prompts
from configs import config as config
from utilities.http_utilities import generate_unique_http_header
from utilities.text_utilities import wrap_prompt_with_delimiters, vprint


def run_fuzz_attack(args):

    proxies = None

    if args.proxy:
        print(f"{Fore.GREEN}[+] Using proxy: {args.proxy}")
        proxy = args.proxy
        proxies = {
            "http": f"http://{proxy}",
            "https": f"http://{proxy}"
        }
    else:
        print(f"{Fore.RED}[!] No proxy specified")


    # Set up the requests session
    session = requests.Session()
    if proxies is not None:
        session.proxies.update(proxies)

    fuzz_target_model(args, session)

    # # Automatically include all the analysis after fuzzing is completed
    # save_classification_results()
    #
    # # TODO: Decide if these get saved to disk, or just displayed to the user.
    # # TODO: Does this need to be renamed as something like "NLP analysis"?
    # create_agreement_refusal_confused_charts()
    #
    # # This must be run last, as it depends on the classifications to have been saved to a file.
    # llm_results_analyzer.main()


def fuzz_target_model(args, session):

    prompt_styles_file_path = config.PROMPT_STYLES_FILE_PATH
    seed_prompt_input_file_path = config.SEED_PROMPT_INPUT_FILE_PATH
    num_prompts_to_generate = config.NUM_PROMPTS_TO_GENERATE

    try:
        with open(prompt_styles_file_path) as prompt_styles_file:

            prompt_styles_config = json.load(prompt_styles_file)

    except FileNotFoundError:

        print(f"{Fore.RED}[!] The prompt styles configuration file was not found at: {prompt_styles_file_path}")

        return

    except Exception as e:

        print(f"{Fore.RED}[!] An error occurred when trying to load the prompt styles configuration file: {str(e)}")

        return

    target_prompt_style = config.TARGET_PROMPT_STYLE

    try:
        with open(seed_prompt_input_file_path) as seed_prompt_input_file_handle:

            # TODO: This never gets used
            seed_prompts = seed_prompt_input_file_handle.readlines()

    except FileNotFoundError:

        print(f"{Fore.RED}[!] The seed prompt input file was not found at: {seed_prompt_input_file_path}")

        return

    except Exception as e:

        print(f"{Fore.RED}[!] An error occurred when trying to load the seed prompt input file: {str(e)}")

        return

    # Generate malicious prompts
    # try:
    print(f"{Fore.GREEN}[+] Generating malicious prompts...")

    # try:
    malicious_prompts = generate_malicious_prompts(
        num_prompts=num_prompts_to_generate,
        prompt_styles_config=prompt_styles_config,
        seed_prompt_csv_file_path=seed_prompt_input_file_path,
        target_prompt_style=target_prompt_style
    )

    print(f"{Fore.GREEN}[+] Success generating {len(malicious_prompts)} malicious prompts.")

    try:
        print(f"{Fore.GREEN}[+] Attacking target model with malicious prompts...")
        results = attack_target_model_api(args, session, prompt_styles_config, malicious_prompts, target_prompt_style)
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred while attacking the target model: {str(e)}")
        return

    try:
        with open(config.TEMP_RESULTS_FILE_PATH, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"{Fore.GREEN}[+] Fuzzing completed. Results saved to '{config.TEMP_RESULTS_FILE_PATH}'.")
    except Exception as e:
        print(f"{Fore.RED}[!] An error occurred while outputting results: {str(e)}")
        return


def attack_target_model_api(args, session, prompt_styles_config, prompts, model_name):
    delimiter_start = prompt_styles_config[model_name]['delimiter_start']
    delimiter_end = prompt_styles_config[model_name]['delimiter_end']

    results = []

    try:
        i = 0
        for prompt in prompts:

            try:
                wrapped_prompt = wrap_prompt_with_delimiters(prompt, delimiter_start, delimiter_end)
            except Exception as e:
                print(f"{Fore.YELLOW}[*] Failed to wrap the prompt with delimiters: {e}")
                continue

            try:
                # Construct the payload
                payload = {
                    "model": config.TARGET_MODEL_NAME,  # Replace with the actual model name if different
                    "messages": [
                        {
                            "role": "user",
                            "content": wrapped_prompt
                        }
                    ],
                    "stream": False
                }
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to construct the payload for the attack: {e}")
                exit(1)

            try:
                # TODO: Add an option to not send the unique header if wanting to be stealthy
                # Send a unique header for each attack so that it can be searched and found in Burp
                new_ablitafuzzer_http_header = generate_unique_http_header()

                # Add the unique header to the payload
                headers = {
                    "Content-Type": "application/json",
                    new_ablitafuzzer_http_header[0]: new_ablitafuzzer_http_header[1]
                }

                print(f"{Fore.GREEN}[+] Attack payload #{i + 1} unique attack header: {new_ablitafuzzer_http_header[0]}: {new_ablitafuzzer_http_header[1]}")

                # Print the prompt
                print(f"{Fore.GREEN}[+]   {prompt}")


            except Exception as e:
                print(f"{Fore.RED}[!] Error generating unique attack header: {e}")
                exit(1)

            try:
                vprint(args, f"{Fore.YELLOW}[!]   config.TARGET_MODEL_API_URL: {config.TARGET_MODEL_API_URL}")
                vprint(args, f"{Fore.GREEN}[+]   Attack payload #{i + 1} will be sent to target model API: {config.TARGET_MODEL_API_URL}")
                # Send the payload to the target API
                response = session.post(config.TARGET_MODEL_API_URL, headers=headers, data=json.dumps(payload))

                print(f"{Fore.GREEN}[+]   Attack payload #{i + 1}. Response: {response.status_code}")
                i += 1

            except Exception as e:
                print(f"{Fore.RED}[!]   Error sending attack payload #{i + 1} to target model API: {e}")
                exit(1)

            if response.status_code == 200:
                results.append({
                    "prompt": wrapped_prompt,
                    "response": response.json(),
                    "attack_id": new_ablitafuzzer_http_header[1]
                })
            else:
                results.append({
                    "prompt": wrapped_prompt,
                    "error": f"Error returned from target model API: {response.status_code} - {response.text}"
                })
                # Also print the target API response error to the console
                print(f"{Fore.RED}[!] Error returned from target model API: {response.status_code} - {response.text}")


            # TODO: Add a configurable delay between requests to avoid overwhelming the target API
            time.sleep(0.5)  # To avoid overwhelming the target API

    except Exception as e:
        print(f"{Fore.RED}[!] Error preparing to send payloads to target model API: {e}")
        exit(1)

    return results
