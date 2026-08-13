from config.config_loader import load_config


def get_resources():
    config = load_config()
    return config["services"]