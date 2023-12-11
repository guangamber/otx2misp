# utils.py

import configparser
from datetime import datetime, timedelta
from typing import Optional
import logging
from logging.handlers import TimedRotatingFileHandler

def setup_global_logger(config_data:dict):
    logger = logging.getLogger('otx2misp')
    log_level_str = config_data['general'].get('logging_level', 'INFO')
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    log_file = config_data['general'].get('log_file')
    if log_file is None:
        log_file = 'misp_default.log'
    logger.setLevel(log_level)
    handler = TimedRotatingFileHandler(log_file, when="W0", interval=1, backupCount=4)
    handler.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def load_config(file_path) -> dict:
    config = configparser.ConfigParser()
    config.read(file_path)
    config_data = {
        'otx': {
            'api_key': config.get('otx', 'api_key'),
            'last_days': config.getint('otx', 'last_days', fallback=7)
        },
        'misp': {
            'api_key': config.get('misp', 'api_key'),
            'url': config.get('misp', 'url')
        },
        'general':{
            'log_file': config.get('general', 'log_file'),
            'logging_level': config.get('general', 'logging_level')
        }
    }
    return config_data

def convert_string_to_datetime(date_string: str) -> Optional[datetime]:
    # Define a list of formats to try
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",  # format with microseconds
        "%Y-%m-%dT%H:%M:%S",     # format without microseconds
        "%Y-%m-%dT%H:%M:%S%z"    # format with timezone offset
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_string, fmt)
        except ValueError:
            continue
    return None

def get_start_date(last_days):
    current_time = datetime.now()
    current_time = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
    start_date = current_time - timedelta(days=last_days)
    return start_date.isoformat()

def check_if_empty_att(att):
    return att == [] or att is None or att in [" ", '']
