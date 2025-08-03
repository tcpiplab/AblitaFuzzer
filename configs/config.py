#!/usr/bin/env python3

import os
import warnings
from .config_loader import load_configuration, get_target_configuration, get_attack_model_configuration
from .migration import get_migration_status

# Global configuration cache
_config_cache = None
_environment = None

def _load_config():
    """Load configuration with caching."""
    global _config_cache, _environment
    
    if _config_cache is None:
        try:
            _environment = os.getenv('ABLITAFUZZER_ENV', 'development')
            _config_cache = load_configuration(environment=_environment)
        except (FileNotFoundError, ValueError):
            # Fall back to legacy configuration if new config not available
            migration_status = get_migration_status()
            if migration_status['status'] in ['needed', 'no_config']:
                warnings.warn(
                    "New configuration system not found. Using legacy hardcoded values. "
                    "Run 'ablitafuzzer config migrate' to upgrade to the new system.",
                    DeprecationWarning
                )
                _config_cache = _get_legacy_config()
            else:
                raise
    
    return _config_cache

def _get_legacy_config():
    """Provide legacy hardcoded configuration as fallback."""
    return {
        'version': '1.0-legacy',
        'providers': {
            'legacy_target': {
                'type': 'ollama',
                'base_url': 'http://api.target.local:11434/api/chat',
                'auth': {'type': 'api_key', 'header': 'Authorization', 'format': 'Bearer ollama'},
                'models': ['gemma:2b']
            },
            'legacy_attacker': {
                'type': 'openai',
                'base_url': 'http://api.promptmaker.local:8181/v1/chat/completions',
                'auth': {'type': 'api_key', 'header': 'Authorization', 'format': 'Bearer lm-studio'},
                'models': ['TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf']
            }
        },
        'targets': {
            'legacy_target': {
                'provider': 'legacy_target',
                'model': 'gemma:2b',
                'description': 'Legacy target configuration'
            }
        },
        'attack': {
            'attacker_model': {
                'provider': 'legacy_attacker',
                'model': 'TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf',
                'temperature': 10
            },
            'analyzer_model': {
                'provider': 'legacy_attacker',
                'model': 'TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf',
                'temperature': 0.7
            }
        }
    }

def get_config():
    """Get the current configuration."""
    return _load_config()

def reload_config():
    """Reload configuration from disk."""
    global _config_cache
    _config_cache = None
    return _load_config()

# Legacy configuration variables for backwards compatibility
def get_target_model_api_url():
    config = _load_config()
    try:
        target_config = get_target_configuration(config, 'legacy_target')
        return target_config['base_url']
    except:
        return "http://api.target.local:11434/api/chat"

def get_target_model_name():
    config = _load_config()
    try:
        target_config = get_target_configuration(config, 'legacy_target')
        return target_config['model']
    except:
        return "gemma:2b"

def get_attack_model_api_url():
    config = _load_config()
    try:
        attack_config = get_attack_model_configuration(config, 'attacker_model')
        return attack_config['base_url']
    except:
        return "http://api.promptmaker.local:8181/v1"

def get_attack_model_api_key():
    config = _load_config()
    try:
        attack_config = get_attack_model_configuration(config, 'attacker_model')
        # Extract key from auth format
        auth_format = attack_config['auth']['format']
        if 'Bearer ' in auth_format:
            return auth_format.replace('Bearer ', '')
        return auth_format
    except:
        return "lm-studio"

def get_attack_model_name():
    config = _load_config()
    try:
        attack_config = get_attack_model_configuration(config, 'attacker_model')
        return attack_config['model']
    except:
        return "TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf"

def get_attack_model_temperature():
    config = _load_config()
    try:
        attack_config = get_attack_model_configuration(config, 'attacker_model')
        return attack_config.get('temperature', 0.7)
    except:
        return 10

def get_analyzer_model_api_url():
    config = _load_config()
    try:
        analyzer_config = get_attack_model_configuration(config, 'analyzer_model')
        return analyzer_config['base_url']
    except:
        return "http://api.analyzer.local:8181/v1"

def get_analyzer_model_api_key():
    config = _load_config()
    try:
        analyzer_config = get_attack_model_configuration(config, 'analyzer_model')
        # Extract key from auth format
        auth_format = analyzer_config['auth']['format']
        if 'Bearer ' in auth_format:
            return auth_format.replace('Bearer ', '')
        return auth_format
    except:
        return "lm-studio"

def get_analyzer_model_name():
    config = _load_config()
    try:
        analyzer_config = get_attack_model_configuration(config, 'analyzer_model')
        return analyzer_config['model']
    except:
        return "TheBloke/Wizard-Vicuna-13B-Uncensored-GGUF/Wizard-Vicuna-13B-Uncensored.Q8_0.gguf"

# Legacy configuration variables as module-level constants for backwards compatibility
TARGET_MODEL_API_URL = get_target_model_api_url()
TARGET_MODEL_NAME = get_target_model_name()
ATTACK_MODEL_API_URL = get_attack_model_api_url()
ATTACK_MODEL_API_KEY = get_attack_model_api_key()
ATTACK_MODEL_NAME = get_attack_model_name()
ATTACK_MODEL_TEMPERATURE = get_attack_model_temperature()
ANALYZER_MODEL_API_URL = get_analyzer_model_api_url()
ANALYZER_MODEL_API_KEY = get_analyzer_model_api_key()
ANALYZER_MODEL_NAME = get_analyzer_model_name()

# Attack Engine Configuration
ATTACK_ENGINE_CONFIG = {
    'max_workers': 5,
    'default_rate_limit': 10.0,  # requests per second
    'retry_attempts': 3,
    'retry_base_delay': 1.0,
    'retry_max_delay': 60.0,
    'circuit_breaker_threshold': 5,
    'circuit_breaker_recovery_timeout': 60.0,
    'progress_update_interval': 1.0,
    'session_auto_cleanup_days': 30,
    'max_concurrent_targets': 3,
    'default_request_timeout': 30.0,
    'response_time_samples': 100
}

# Static configuration values
TARGET_PROMPT_STYLE = "openai_chatgpt"
PROMPT_STYLES_FILE_PATH = 'inputs/prompt-styles/prompt-styles.json'
SEED_PROMPT_DATASET = "advbench_harmful"
SEED_PROMPT_INPUT_FILE_PATH = 'inputs/seed-prompts/harmful-behaviors/harmful_behaviors.csv'
NUM_PROMPTS_TO_GENERATE = 10
MINIMUM_TOXICITY_SCORE_THRESHOLD = 0.001
DATASET_CACHE_DIR = None
DATASET_DOWNLOAD_TIMEOUT = 30
DATASET_CACHE_MAX_AGE_DAYS = 7
FORCE_DATASET_DOWNLOAD = False
SHOW_DOWNLOAD_PROGRESS = True
TEMP_RESULTS_FILE_PATH = "results/results.json"
TEMP_CLASSIFIED_RESULTS_FILE_PATH = "results/classified_results.json"
FINAL_REPORT_FILENAME_PREFIX = "results/Ablitafuzzer_Results_"
FINAL_REPORT_FILENAME_TIMESTAMP_FORMAT = "%Y-%m-%d-%H-%M"
ABLITAFUZZER_REPO_ROOT_DIR = os.path.join(os.environ.get("HOME", "."), "Tools", "AblitaFuzzer")