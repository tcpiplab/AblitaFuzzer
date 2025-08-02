import os

## Target LLM API Settings
TARGET_MODEL_API_URL = "http://api.target.local:11434/api/chat"
TARGET_MODEL_NAME = "gemma:2b"

## Prompt Generation Settings
TARGET_PROMPT_STYLE = "openai_chatgpt"
PROMPT_STYLES_FILE_PATH = 'inputs/prompt-styles/prompt-styles.json'

# Dataset Configuration - supports both local files and dataset registry IDs
# For backwards compatibility, local file paths are still supported
# To use dataset registry, set to a dataset ID like "advbench_harmful"
SEED_PROMPT_DATASET = "advbench_harmful"  # Default to AdvBench dataset
SEED_PROMPT_INPUT_FILE_PATH = 'inputs/seed-prompts/harmful-behaviors/harmful_behaviors.csv'  # Fallback for backwards compatibility

NUM_PROMPTS_TO_GENERATE = 10
MINIMUM_TOXICITY_SCORE_THRESHOLD = 0.001

## Dataset Download Settings
DATASET_CACHE_DIR = None  # None uses default ~/.ablitafuzzer/cache
DATASET_DOWNLOAD_TIMEOUT = 30  # seconds
DATASET_CACHE_MAX_AGE_DAYS = 7
FORCE_DATASET_DOWNLOAD = False  # Set to True to always download fresh datasets
SHOW_DOWNLOAD_PROGRESS = True

## Abliterated/Uncensored Attack LLM API Settings
ATTACK_MODEL_API_URL = "http://api.promptmaker.local:8181/v1"
ATTACK_MODEL_API_KEY = "lm-studio"
ATTACK_MODEL_NAME = "TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf"
ATTACK_MODEL_TEMPERATURE = 10

## Analyzer LLM API Settings
# Yes, for now we are using the same model for both attack and analysis
ANALYZER_MODEL_API_URL = "http://api.analyzer.local:8181/v1"
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