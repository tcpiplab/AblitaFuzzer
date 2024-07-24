import os

## Target LLM API Settings
TARGET_MODEL_API_URL = "http://localhost:11434/api/chat"
TARGET_MODEL_NAME = "llama3.1"

## Prompt Generation Settings
TARGET_PROMPT_STYLE = "openai_chatgpt"
PROMPT_STYLES_FILE_PATH = 'inputs/prompt-styles/prompt-styles.json'
SEED_PROMPT_INPUT_FILE_PATH = 'inputs/seed-prompts/harmful-behaviors/harmful_behaviors.csv'
NUM_PROMPTS_TO_GENERATE = 10

## Abliterated/Uncensored Attack LLM API Settings
ATTACK_MODEL_API_URL = "http://localhost:8181/v1"
ATTACK_MODEL_API_KEY = "lm-studio"
ATTACK_MODEL_NAME = "TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf"
ATTACK_MODEL_TEMPERATURE = 0.7

## Analyzer LLM API Settings
# Yes, for now we are using the same model for both attack and analysis
ANALYZER_MODEL_API_URL = "http://localhost:8181/v1"
ANALYZER_MODEL_API_KEY = "lm-studio"
ANALYZER_MODEL_NAME = "TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf"

## Analysis and Reporting Settings
# These TEMP files will get overwritten each time an attack and analysis is run, respectively
TEMP_RESULTS_FILE_PATH = "results/results.json"
TEMP_CLASSIFIED_RESULTS_FILE_PATH = "results/classified_results.json"
# Path and name for the final report in Markdown format
FINAL_REPORT_FILENAME_PREFIX = "results/Ablitafuzzer_Results_"
FINAL_REPORT_FILENAME_TIMESTAMP_FORMAT = "%Y-%m-%d-%H-%M"
# Set the CWD to the root directory of the repo so that analysis and reporting doesn't fail
# For example, "${HOME}/Tools/AblitaFuzzer"
ABLITAFUZZER_REPO_ROOT_DIR = os.path.join(os.environ["HOME"], "Tools", "AblitaFuzzer")