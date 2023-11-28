import configparser
import argparse
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime,timedelta
from dateutil import parser as date_parser
from typing import Optional
import requests
from OTXv2 import OTXv2
from pymisp import PyMISP, MISPEvent, MISPAttribute

logger = logging.getLogger(__name__)
config_data = {}

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

def setup_logger():
    global logger
    log_level_str = config_data['general'].get('logging_level', 'INFO')
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    log_file = config_data['general'].get('log_file')
    if log_file is None:
        log_file = 'default_log.log'
    logger.setLevel(log_level)
    handler = TimedRotatingFileHandler(log_file, when="midnight", interval=1, backupCount=7)
    handler.setLevel(log_level)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def load_config(file_path):
    config = configparser.ConfigParser()
    config.read(file_path)
    global config_data
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

def get_pulses(otx: OTXv2, from_timestamp=None):
    if from_timestamp is None:
        logger.debug("Retrieving all Pulses (no timestamp)")
        pulses = otx.getall()
    else:
        logger.debug("Retrieving pulses since " + from_timestamp)
        pulses = otx.getsince(from_timestamp)

    return pulses

def initialize_misp() -> PyMISP:
    try:
        return PyMISP(config_data['misp'].get('url'), config_data['misp'].get('api_key'), ssl=False)
    except Exception as ex:
        raise Exception("Cannot connect to MISP instance. Check server url and api key.")

def initialize_otx() -> OTXv2:
    try:
        return OTXv2(api_key=config_data['otx'].get('api_key'),verify=False)
    except Exception as e:
        raise Exception(f"Cannot connect to OTX instance. Check api key. Details: {e}")

def add_tags_to_event(misp: PyMISP, event: MISPEvent, pulse: dict):
    misp.tag(event, "Threat Source:OSINT")
    if 'tlp' in pulse:
        tag = f"tlp:{pulse['tlp']}"
        misp.tag(event, tag)

    if 'tags' in pulse:
        for pulse_tag in pulse['tags'] and not pulse_tag.startswith('#'):
            misp_tags = misp.search_tags(tagname=pulse_tag.lower())
            if misp_tags:
                misp.tag(misp_entity=event, tag=misp_tags[0]['Tag'])
            else:
                misp.tag(misp_entity=event, tag=pulse_tag)
                logger.info("Tag does not exist. Added new tag:" + pulse_tag)

def check_if_empty_att(att):
    return att == [] or att is None or att in [" ", '']

def add_iocs_to_event(event: MISPEvent, pulse: dict):
    ioc_type_mapping = {
        'IPv4': 'ip-src',
        'IPv6': 'ip-src',
        'domain': 'domain',
        'YARA': 'yara',
        'hostname': 'hostname',
        'email': 'email',
        'URL': 'url',
        'MUTEX': 'mutex',
        'CVE': 'other',
        'FileHash-MD5': 'md5',
        'FileHash-SHA1': 'sha1',
        'FileHash-SHA256': 'sha256',
        'FileHash-PEHASH': 'pehash',
        'FileHash-IMPHASH': 'imphash'
    }
    for key, value in pulse.items():
        if key in ['id','name','author_name','modified','tlp','created','revision','public','tags']:
            continue
        elif key == 'indicators':
            for ioc in value:
                ioc_type = ioc['type']
                attr_type = ioc_type_mapping.get(ioc_type, None)
                if attr_type:
                    attr_value = ioc['indicator'] if ioc_type != 'YARA' else ioc['content']
                    if ioc_type == 'CVE':
                        attr_value = "CVE: " + attr_value
                    event.add_attribute(attr_type, attr_value)
        elif key in ['malware_families', 'targeted_countries', 'adversary','attack_ids']:
            if not check_if_empty_att(value):
                prefix = key.replace('_', ' ').capitalize() + ': '
                event.add_attribute("other", prefix + str(value))
        elif key == 'references':
            if not check_if_empty_att(value):
                for r in value:
                    att_kwargs = {'category': 'External analysis'}
                    event.add_attribute("link", r, **att_kwargs)
        elif key == 'description':
            if not check_if_empty_att(value):
                att_kwargs = {'category': 'External analysis'}
                event.add_attribute("comment", value, **att_kwargs)
        else:
            logger.warning("Unsupported IOC type:" + key)

def create_event(misp: PyMISP, pulse: dict):
    new_event = MISPEvent()
    new_event.distribution = 0
    new_event.analysis = 2
    new_event.info = pulse['name']
    try:
        dt = convert_string_to_datetime(pulse['created'])
    except ValueError:
        logger.error("Cannot parse Pulse 'created' date.")
        dt = datetime.utcnow()
    new_event.date = dt.strftime('%Y-%m-%d')
    new_event.timestamp = dt
    add_iocs_to_event(new_event,pulse)
    result = misp.add_event(new_event)
    add_tags_to_event(misp,result,pulse)
    logger.debug("Pulse addedt MISP, ID:" +result['Event']['id'] + ", name: " + pulse['name'])


def update_event(misp: PyMISP, pulse: dict):
    logger.debug("not yet implemented")

def main():
    parser = argparse.ArgumentParser(description="Provide the absolute path of config file. Refer to sample-misp.ini for sample.")
    parser.add_argument('file_path', help="The path to the misp.ini file.")
    args = parser.parse_args()
    try:
        load_config(args.file_path)
        setup_logger()
        logger.info("config file loaded.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    
    misp = initialize_misp()
    logger.debug("MISP connection is verified.")

    otx = initialize_otx()
    if otx.get_user("AlienVault"):
        logger.debug("OTX connection is verified.")
    
    pulses = get_pulses(otx, get_start_date(config_data['otx']['last_days']))
    if len(pulses) == 0:
        logger.info("No new pulses retrirved. Ending.")
    else:
        for pulse in pulses:
            pulse_name = pulse['name']
            result = misp.search_index(eventinfo=pulse_name)
            if len(result)==0:
                create_event(misp, pulse)
                logger.info("Importing pulse done:" + pulse_name)
            else:
                logger.info("Pulse already imported. Going to update this pulse:" + pulse_name)
                update_event(misp, pulse)
    logger.info("Done with importing.")
if __name__ == "__main__":
    main()