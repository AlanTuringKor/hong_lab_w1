import os
import yaml

def load_config(config_path='config.yaml'):
    """Load the configuration file."""
    full_path = os.path.join(os.path.dirname(__file__), config_path)
    with open(full_path, 'r') as file:
        return yaml.safe_load(file)

__all__ = ['load_config']