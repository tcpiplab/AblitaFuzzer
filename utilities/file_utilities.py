import csv
from colorama import Fore


def read_seed_prompts_from_csv(path_to_seed_prompts_csv_file):
    """
    Reads malicious seed prompts and responses from a CSV file.

    Args:
        path_to_seed_prompts_csv_file (str): The path to the CSV file containing seed prompts and responses.

    Returns:
        list: A list of tuples where each tuple contains a prompt and its corresponding response.
    """

    seed_prompt_response_tuples = []

    print(f"{Fore.GREEN}[+] Will try reading seed prompts/responses from {path_to_seed_prompts_csv_file}...")

    try:
        with open(path_to_seed_prompts_csv_file, 'r') as file:
            reader = csv.reader(file)
            num_rows = sum(1 for _ in reader)

            file.seek(0)  # Reset file pointer

            print(f"{Fore.GREEN}[+] Reading seed prompts/responses from {path_to_seed_prompts_csv_file}...")

            print(f"{Fore.GREEN}[+] Appending {num_rows} seed prompts/responses to seed_prompt_response_tuples list", end='')

            line_num = 0  # Track line number manually

            for row in reader:
                line_num += 1

                if not row:
                    print(f"{Fore.RED}[!] Error: Seed prompts CSV file contains empty rows.")
                    continue

                if len(row) < 1:
                    print(f"{Fore.RED}[!] Error: Seed prompts CSV file contains rows with no columns.")
                    continue

                if line_num == 1:
                    continue

                # TODO: Append and propagate the response also. It will require pairs of prompts and responses.
                # Put prompt and response pairs into a tuple
                seed_prompt_response_tuples.append((row[0], row[1]))  # First column is prompt and second column is response


                # Append seed attack prompt to list, not the response though
                # TODO: This is an experimental bugfix, need to add support for response propagation
                # seed_prompt_response_tuples.append(row[0])

                # Print progress with dots
                print(f"{Fore.GREEN}.", end="")

            print(f'{Fore.GREEN}\n[+] Finished creating seed attack prompt/response list.')

            if len(seed_prompt_response_tuples) > 0:
                print(f"{Fore.GREEN}[+] Seed attack prompt/response list successfully created with {len(seed_prompt_response_tuples)} prompts.")
            else:
                print(f"{Fore.RED}[!] Seed attack prompt/response list is empty, please check the CSV file and try again.")

    except FileNotFoundError:
        print(f"{Fore.RED}[!] Error: Seed attack prompt/response CSV file '{path_to_seed_prompts_csv_file}' not found.")
    except Exception as e:
        print(f"{Fore.RED}[!] Error reading seed attack prompts/responses from CSV file: {e}")

    # Return the seed prompts
    return seed_prompt_response_tuples
