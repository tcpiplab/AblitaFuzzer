#!/usr/bin/env python3

"""
Configuration-specific exception classes for AblitaFuzzer.

Provides structured error handling for configuration loading and validation.
"""


class ConfigurationError(Exception):
    """Base exception for configuration-related errors."""
    pass


class EnvironmentVariableError(ConfigurationError):
    """Exception for missing or invalid environment variables."""
    
    def __init__(self, variable_name: str, suggestion: str = ""):
        self.variable_name = variable_name
        message = f"Required environment variable '{variable_name}' is not set"
        if suggestion:
            message += f"\n{suggestion}"
        super().__init__(message)


class ConfigurationMigrationError(ConfigurationError):
    """Exception for configuration migration issues."""
    pass