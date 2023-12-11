# core.py
import requests
from pymisp import PyMISP, MISPEvent
from OTXv2 import OTXv2
from datetime import datetime
import logging
from .utils import convert_string_to_datetime, check_if_empty_att

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

logger = logging.getLogger("otx2misp")

def initialize_misp(config_data:dict) -> PyMISP:
    try:
        return PyMISP(config_data['misp'].get('url'), config_data['misp'].get('api_key'), ssl=False)
    except Exception as ex:
        raise Exception("Cannot connect to MISP instance. Check server url and api key.")

def initialize_otx(config_data:dict) -> OTXv2:
    try:
        return OTXv2(api_key=config_data['otx'].get('api_key'),verify=False)
    except Exception as e:
        raise Exception(f"Cannot connect to OTX instance. Check api key. Details: {e}")
    
def get_pulses(logger, otx: OTXv2, from_timestamp=None):
    if from_timestamp is None:
        logger.debug("Retrieving all Pulses (no timestamp)")
        pulses = otx.getall()
    else:
        logger.debug("Retrieving pulses since " + from_timestamp)
        pulses = otx.getsince(from_timestamp)

    return pulses

def add_tags_to_event(misp: PyMISP, event: MISPEvent, pulse: dict):
    misp.tag(event, "Threat Source:OSINT")
    if 'tlp' in pulse:
        tag = f"tlp:{pulse['tlp']}"
        misp.tag(event, tag)

    if 'tags' in pulse:
        for pulse_tag in pulse['tags']:
            if not pulse_tag.startswith('#'):
                misp_tags = misp.search_tags(tagname=pulse_tag.lower())
                if misp_tags:
                    misp.tag(misp_entity=event, tag=misp_tags[0]['Tag'])
                else:
                    misp.tag(misp_entity=event, tag=pulse_tag)
                    logger.info("Tag does not exist. Added new tag:" + pulse_tag)

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