import csv
import os
import requests
from colorama import Fore


# URL of the input CSV file
url = 'https://github.com/verazuo/jailbreak_llms/raw/main/data/prompts/jailbreak_prompts_2023_12_25.csv'
input_file = 'jailbreak_prompts_2023_12_25.csv'
output_file = 'jailbreaks_only.csv'

try:
    response = requests.get(url)
    response.raise_for_status()
except requests.exceptions.HTTPError as err:
    print(f"{Fore.RED} HTTP error occurred: {err}")
except requests.exceptions.RequestException as e:
    print(f"{Fore.RED}Request exception occurred: {e}")

try:
    # Change the cwd to be the same as the directory of this script
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Now change to the directory at '../inputs/seed-prompts/jailbreaks/'
    os.chdir('../inputs/seed-prompts/jailbreaks/')
except Exception as e:
    print(f"{Fore.RED}An error occurred while changing the current working directory: {e}")


try:
    # Write the downloaded content to a local file
    with open(input_file, 'wb') as f:
        f.write(response.content)
except Exception as e:
    print(f"{Fore.RED}An error occurred while writing the downloaded content to a file: {e}")


try:
    # Process the downloaded CSV file
    with open(input_file, 'r', newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)

        # Create a list to store the filtered prompts
        filtered_prompts = []

        # Header of the downloaded file is:
        # platform,source,prompt,jailbreak,created_at,date,community,community_id,previous_community_id

        # Iterate through the rows in the input file
        for row in reader:
            # Check if the jailbreak column is True (assuming the CSV stores booleans as strings 'True' or 'False')
            if row['jailbreak'].strip().lower() == 'true':
                # Append the prompt to the filtered list
                filtered_prompts.append(row['prompt'])
except Exception as e:
    print(f"{Fore.RED}An error occurred while processing the input file: {e}")


try:
    # Open the output CSV file
    with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile, quoting=csv.QUOTE_NONNUMERIC)

        # Write the header for the new CSV
        writer.writerow(['prompt'])

        # Write the filtered prompts
        for prompt in filtered_prompts:
            writer.writerow([prompt])
except Exception as e:
    print(f"{Fore.RED}An error occurred while writing to the output CSV file: {e}")


# Print a confirmation message with the full path to the output CSV
output_file = os.path.abspath(output_file)

# If the output file is not empty, print a confirmation message
if os.path.getsize(output_file) > 0:
    print(f"{Fore.GREEN}Filtered prompts have been written to {output_file}")
else:
    print(f"{Fore.RED}The output CSV file is empty. Please check your input parameters and try again.")