



import os
from pathlib import Path
import sys
from typing import Any, Literal, Optional
import logging
from unittest.mock import MagicMock, AsyncMock

import duckdb
from pydantic import (
    BaseModel, 
    computed_field, 
    DirectoryPath, 
    FilePath,
    Field, 
    SecretStr, 
    ValidationError
)
import yaml


_ROOT_DIR = Path(__file__).parent.parent
_HOME_DIR = Path(__file__).parent

# Insert this file's directory to the system path
sys.path.insert(0, str(_ROOT_DIR))
try:
    sys.path.insert(0, str(_HOME_DIR))
except ImportError:
    # If the import fails, it means the directory is not a package
    pass


def get_unittest_mock_attributes() -> list[str]:
    """Get a list of attributes from unittest.mock objects to exclude from config validation."""

    unittest_mock_attributes = []
    for obj in [MagicMock, AsyncMock]:
        mock_attributes = [attr for attr in dir(obj)]
        unittest_mock_attributes.extend(mock_attributes)
    return unittest_mock_attributes


class Configs(BaseModel):
    """
    Configuration class for the American Law Search application.

    This pydantic class defines all the necessary configurations for the project,
    including API keys, file paths, model specifications, and other settings.
    It loads settings from a `configs.yaml` file and environment variables.

    Attributes:
        OPENAI_API_KEY (SecretStr): Authentication key for OpenAI API.
        HUGGING_FACE_USER_ACCESS_TOKEN (SecretStr): Authentication token for Hugging Face.
        ADMIN_EMAIL (SecretStr): Administrator's email address.
        EMAIL_SERVER (SecretStr): SMTP server for sending emails.
        EMAIL_USERNAME (SecretStr): Username for the email server.
        EMAIL_PASSWORD (SecretStr): Password for the email server.
        EMAIL_PORT (int): Port for the email server.
        ROOT_DIR (DirectoryPath): Root directory of the project.
        APP_DIR (DirectoryPath): Application directory of the project.
        FRONTEND_DIR (DirectoryPath): Directory for frontend source files.
        AMERICAN_LAW_DATA_DIR (DirectoryPath): Directory containing the American Law data.
        PARQUET_FILES_DIR (DirectoryPath): Directory containing parquet files.
        DB_PATH (DirectoryPath): Path to the American Law database file.
        SEARCH_HISTORY_DB_PATH (DirectoryPath): Path to the search history database file.
        PROMPTS_DIR (DirectoryPath): Directory containing LLM prompt templates.
        HUGGING_FACE_REPO_ID (str): Repository ID on Hugging Face.
        OPENAI_MODEL (str): Main OpenAI model to use for processing.
        OPENAI_SMALL_MODEL (str): Smaller, faster OpenAI model for specific tasks.
        OPENAI_EMBEDDING_MODEL (str): OpenAI model to use for text embeddings.
        LOG_LEVEL (int): Logging level for the application (e.g., logging.DEBUG).
        SIMILARITY_SCORE_THRESHOLD (float): Threshold for cosine similarity scoring.
        SEARCH_EMBEDDING_BATCH_SIZE (int): Batch size for embedding searches.
        DATABASE_CONNECTION_POOL_SIZE (int): Max number of database connections in the pool.
        DATABASE_CONNECTION_TIMEOUT (int): Timeout in seconds for database connections.
        DATABASE_CONNECTION_MAX_OVERFLOW (int): Max connections beyond pool size.
        DATABASE_CONNECTION_MAX_AGE (int): Max age in seconds for a database connection.
        TOP_K (int): Number of top results to return in searches.
        USE_GPU_FOR_COSINE_SIMILARITY (str): Computed property, "cuda" or "cpu".
    """
    ROOT_DIR:                         DirectoryPath = _ROOT_DIR
    APP_DIR:                          DirectoryPath = _HOME_DIR
    FRONTEND_DIR:                     DirectoryPath = _HOME_DIR / "src"
    AMERICAN_LAW_DATA_DIR:            DirectoryPath = _ROOT_DIR / "data"
    PARQUET_FILES_DIR:                DirectoryPath = _ROOT_DIR / "data" / "parquet_files"
    DB_PATH:                          FilePath = _ROOT_DIR / "data" / "meta_tester.db"
    LOG_LEVEL:                        Literal[10, 20, 30, 40, 50] = logging.DEBUG
    SIMILARITY_SCORE_THRESHOLD:       float = 0.4
    SEARCH_EMBEDDING_BATCH_SIZE:      int = 10000
    DATABASE_CONNECTION_POOL_SIZE:    int = 10
    DATABASE_CONNECTION_TIMEOUT:      int = 30
    DATABASE_CONNECTION_MAX_OVERFLOW: int = 20
    DATABASE_CONNECTION_MAX_AGE:      int = 300



    def __getitem__(self, key: str) -> str:
        """
        Allows dictionary-like access to the configuration attributes.

        Args:
            key (str): The name of the configuration attribute.

        Returns:
            str: The value of the requested configuration attribute.
        """
        try:
            return getattr(self, key)
        except AttributeError as e:
            raise KeyError(f"Configuration key '{key}' not found.") from e

    def __setitem__(self, key: str, value: str) -> None:
        """
        Allows dictionary-like setting of the configuration attributes.

        Args:
            key (str): The name of the configuration attribute.
            value (str): The value to set for the configuration attribute.

        Raises:
            AttributeError: If the attribute does not exist.
        """
        try:
            setattr(self, key, value)
            # Re-validate the new value
            self.model_validate()
        except ValidationError as e:
            raise ValidationError(f"Validation error setting '{key}' to '{value}': {e.errors()}")
        except AttributeError as e:
            raise KeyError(f"Configuration key '{key}' not found.") from e

    def get(self, key: str, default: Optional[str] = None) -> Any:
        """Retrieves the value of a configuration attribute.

        Args:
            key (str): The name of the configuration attribute.
            default (str): The default value to return if the key is not found. Defaults to None.

        Returns:
            Any: The value of the requested configuration attribute or the default value.
        """
        return getattr(self, key, default)


def set_mock_configs(configs: Configs, mock_configs: dict[str, Any]) -> None:
    """
    Sets multiple configuration attributes on a Configs instance.

    This function updates the attributes of a Configs object based on the
    provided dictionary of configuration overrides. It validates each attribute
    after setting it.

    Args:
        configs (Configs): The Configs instance to update.
        mock_configs (dict[str, Any]): A dictionary of configuration overrides.

    Raises:
        AttributeError: If an attribute in mock_configs does not exist in Configs.
        ValidationError: If setting an attribute fails validation.
    """
    unittest_mock_attributes = get_unittest_mock_attributes()
    for attr, value in mock_configs.items():
        if (
            not attr.startswith('_') and 
            attr not in unittest_mock_attributes and
            hasattr(configs, attr)
        ):
            try:
                setattr(configs, attr, value)
                # Re-validate the new value
                configs.model_validate()
            except ValidationError as e:
                raise ValidationError(f"Validation error setting '{attr}' to '{value}': {e.errors()}")
            except AttributeError as e:
                raise KeyError(f"Configuration key '{attr}' not found.") from e
        else:
            raise AttributeError(f"Unexpected config attribute in mock_configs: {attr}")
    return configs


def make_configs(mock_configs: Optional[dict[str, Any]] = None) -> Configs:
    """
    Factory function to create a Configs instance.

    This function initializes a Configs object with the provided dictionary
    of configuration overrides. It is intended to be used for creating
    configuration instances as needed.

    Args:
        mock_configs (dict[str, Any], optional): A dictionary of configuration overrides. Defaults to None.
    
    Returns:
        Configs: A new instance of the Configs pydantic model.
    """
    # Load the configs from the yaml and create an instance of the Configs class
    config_path = _HOME_DIR / "configs.yaml"
    try:
        with open(config_path, "r") as config_file:
            config_dict = yaml.safe_load(config_file)
    except FileNotFoundError as e:
        raise FileNotFoundError(f"Configuration file '{config_path}' not found.") from e
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing the config file '{config_path}'.") from e
    except Exception as e: # Stop everything if we get bad configs
        raise RuntimeError(f"Unexpected error loading config file: {e}") from e

    try:
        configs = Configs.model_validate(config_dict)
    except ValueError as e:
        raise ValueError(
            f"Validation error in configs: {e.errors()}"
        ) from e
    except Exception as e: # Stop everything if we get bad configs
        raise RuntimeError(f"Unexpected error validating configs: {e}") from e

    if mock_configs is not None:
        configs = set_mock_configs(configs, mock_configs)
    return configs

try:
    configs = CONFIGS = make_configs()
except Exception as e:
    raise AssertionError(f"Failed to initialize configs: {e}") from e
