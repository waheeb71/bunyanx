import os
import yaml

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "settings.yaml")

def get_log_settings() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f) or {}

def save_log_settings(config_dict: dict) -> None:
    with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
        yaml.safe_dump(config_dict, f, default_flow_style=False, sort_keys=False)
