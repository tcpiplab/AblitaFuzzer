#!/usr/bin/env python3

import os
import yaml
from pathlib import Path
from .config_loader import get_default_config_path, save_configuration


def migrate_legacy_config():
    """
    Migrate from legacy hardcoded configuration to new YAML-based system.
    
    Returns:
        dict: Migration results with status and details
    """
    try:
        # Import old config to get current values
        import configs.config as old_config
        
        # Create new configuration structure based on old values
        new_config = {
            'version': '1.0',
            'global': {
                'timeout': {
                    'connection': 30,
                    'read': 60,
                    'total': 120
                },
                'retry': {
                    'attempts': 3,
                    'backoff': 'exponential',
                    'max_delay': 30
                }
            },
            'environments': {
                'development': {
                    'log_level': 'DEBUG',
                    'rate_limit': 1
                },
                'production': {
                    'log_level': 'INFO',
                    'rate_limit': 10,
                    'require_confirmation': True
                }
            },
            'providers': {},
            'targets': {},
            'attack': {
                'attacker_model': {
                    'provider': 'legacy_attacker',
                    'model': getattr(old_config, 'ATTACK_MODEL_NAME', 'unknown'),
                    'temperature': getattr(old_config, 'ATTACK_MODEL_TEMPERATURE', 0.7)
                }
            }
        }
        
        # Migrate target model configuration
        target_url = getattr(old_config, 'TARGET_MODEL_API_URL', 'http://localhost:11434/api/chat')
        target_model = getattr(old_config, 'TARGET_MODEL_NAME', 'unknown')
        
        if 'localhost:11434' in target_url:
            # Ollama configuration
            new_config['providers']['legacy_target'] = {
                'type': 'ollama',
                'base_url': target_url,
                'auth': {
                    'type': 'api_key',
                    'header': 'Authorization',
                    'format': 'Bearer ollama'
                },
                'models': [target_model]
            }
        else:
            # Generic OpenAI-compatible configuration
            new_config['providers']['legacy_target'] = {
                'type': 'openai',
                'base_url': target_url,
                'auth': {
                    'type': 'api_key',
                    'header': 'Authorization',
                    'format': 'Bearer ${TARGET_API_KEY}'
                },
                'models': [target_model]
            }
        
        new_config['targets']['legacy_target'] = {
            'provider': 'legacy_target',
            'model': target_model,
            'description': 'Migrated from legacy configuration'
        }
        
        # Migrate attacker model configuration
        attacker_url = getattr(old_config, 'ATTACK_MODEL_API_URL', 'http://localhost:8181/v1')
        attacker_key = getattr(old_config, 'ATTACK_MODEL_API_KEY', 'lm-studio')
        attacker_model = getattr(old_config, 'ATTACK_MODEL_NAME', 'unknown')
        
        if 'localhost:8181' in attacker_url or 'lm-studio' in attacker_key:
            # LM Studio configuration
            new_config['providers']['legacy_attacker'] = {
                'type': 'openai',
                'base_url': attacker_url + '/chat/completions' if not attacker_url.endswith('/chat/completions') else attacker_url,
                'auth': {
                    'type': 'api_key',
                    'header': 'Authorization',
                    'format': f'Bearer {attacker_key}'
                },
                'models': [attacker_model]
            }
        else:
            # Generic OpenAI-compatible configuration
            new_config['providers']['legacy_attacker'] = {
                'type': 'openai',
                'base_url': attacker_url + '/chat/completions' if not attacker_url.endswith('/chat/completions') else attacker_url,
                'auth': {
                    'type': 'api_key',
                    'header': 'Authorization',
                    'format': '${ATTACK_MODEL_API_KEY}'
                },
                'models': [attacker_model]
            }
        
        # Create default campaign
        new_config['campaigns'] = {
            'legacy_migration': {
                'targets': ['legacy_target'],
                'datasets': ['advbench_harmful'],
                'concurrent_targets': 1
            }
        }
        
        # Save new configuration
        config_path = get_default_config_path()
        save_configuration(new_config, config_path)
        
        # Generate environment variables template
        env_vars = []
        if 'TARGET_API_KEY' in str(new_config):
            env_vars.append('TARGET_API_KEY=your_target_api_key_here')
        if 'ATTACK_MODEL_API_KEY' in str(new_config):
            env_vars.append('ATTACK_MODEL_API_KEY=your_attack_model_api_key_here')
        
        env_template_path = Path(config_path).parent / 'env_template.txt'
        if env_vars:
            with open(env_template_path, 'w') as f:
                f.write("# Environment Variables Template\n")
                f.write("# Copy these to your shell environment or .env file\n\n")
                f.write('\n'.join(env_vars))
        
        return {
            'success': True,
            'config_path': config_path,
            'env_template_path': str(env_template_path) if env_vars else None,
            'message': 'Migration completed successfully',
            'recommendations': [
                'Review the generated configuration file and adjust as needed',
                'Set required environment variables' + (f' (template saved to {env_template_path})' if env_vars else ''),
                'Test connectivity to your targets using: ablitafuzzer config validate',
                'Consider updating to use cloud API providers for production use'
            ]
        }
        
    except ImportError:
        return {
            'success': False,
            'message': 'Legacy configuration not found - migration not needed',
            'recommendations': [
                'Use configuration templates to create a new configuration',
                'Run: ablitafuzzer config init'
            ]
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Migration failed: {e}',
            'recommendations': [
                'Check that the legacy configuration is valid',
                'Create configuration manually using templates',
                'Contact support if the issue persists'
            ]
        }


def backup_legacy_config():
    """
    Create a backup of the legacy configuration file.
    
    Returns:
        str: Path to backup file, or None if no backup needed
    """
    legacy_config_path = Path('configs/config.py')
    
    if not legacy_config_path.exists():
        return None
    
    backup_path = legacy_config_path.parent / 'config_legacy_backup.py'
    
    # Copy file content
    with open(legacy_config_path, 'r') as src:
        with open(backup_path, 'w') as dst:
            dst.write(f"# Legacy configuration backup created during migration\n")
            dst.write(f"# Original file: {legacy_config_path}\n\n")
            dst.write(src.read())
    
    return str(backup_path)


def create_default_config_from_template(template_name='openai'):
    """
    Create a default configuration from a template.
    
    Args:
        template_name (str): Name of template to use
        
    Returns:
        dict: Creation results
    """
    template_path = Path(__file__).parent / 'templates' / f'{template_name}.yaml'
    
    if not template_path.exists():
        available_templates = [
            f.stem for f in (Path(__file__).parent / 'templates').glob('*.yaml')
        ]
        return {
            'success': False,
            'message': f'Template {template_name} not found',
            'available_templates': available_templates
        }
    
    # Load template
    with open(template_path, 'r') as f:
        template_config = yaml.safe_load(f)
    
    # Save to default location
    config_path = get_default_config_path()
    
    # Ensure directory exists
    Path(config_path).parent.mkdir(parents=True, exist_ok=True)
    
    save_configuration(template_config, config_path)
    
    return {
        'success': True,
        'config_path': config_path,
        'template_used': template_name,
        'message': f'Configuration created from {template_name} template',
        'recommendations': [
            'Set required environment variables for your chosen providers',
            'Validate configuration using: ablitafuzzer config validate',
            'Test connectivity using: ablitafuzzer config test-target <target_name>'
        ]
    }


def get_migration_status():
    """
    Check if migration is needed and provide status.
    
    Returns:
        dict: Migration status information
    """
    # Check if new config exists
    new_config_path = get_default_config_path()
    has_new_config = os.path.exists(new_config_path)
    
    # Check if legacy config exists
    legacy_config_path = Path('configs/config.py')
    has_legacy_config = legacy_config_path.exists()
    
    # Check if legacy config is being used
    legacy_in_use = False
    if has_legacy_config:
        try:
            import configs.config as old_config
            # Check if it has the old hardcoded values
            if hasattr(old_config, 'TARGET_MODEL_API_URL') and hasattr(old_config, 'ATTACK_MODEL_API_URL'):
                legacy_in_use = True
        except ImportError:
            pass
    
    if has_new_config and not legacy_in_use:
        status = 'completed'
        message = 'Using new configuration system'
        recommendations = []
    elif has_new_config and legacy_in_use:
        status = 'partial'
        message = 'New configuration exists but legacy config still in use'
        recommendations = [
            'Update imports to use new configuration system',
            'Remove or rename legacy config file after testing'
        ]
    elif not has_new_config and legacy_in_use:
        status = 'needed'
        message = 'Migration needed - using legacy configuration'
        recommendations = [
            'Run: ablitafuzzer config migrate',
            'Or create new configuration: ablitafuzzer config init'
        ]
    else:
        status = 'no_config'
        message = 'No configuration found'
        recommendations = [
            'Create configuration: ablitafuzzer config init',
            'Or migrate if you have legacy config: ablitafuzzer config migrate'
        ]
    
    return {
        'status': status,
        'message': message,
        'has_new_config': has_new_config,
        'has_legacy_config': has_legacy_config,
        'legacy_in_use': legacy_in_use,
        'new_config_path': new_config_path,
        'legacy_config_path': str(legacy_config_path),
        'recommendations': recommendations
    }