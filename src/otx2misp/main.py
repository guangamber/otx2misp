import argparse
import logging
from .utils import setup_global_logger,load_config, get_start_date
from .core import initialize_misp,initialize_otx,get_pulses,create_event,update_event

def main():
    parser = argparse.ArgumentParser(description="Provide the absolute path of config file. Refer to sample-misp.ini for sample.")
    parser.add_argument('file_path', help="The path to the misp.ini file.")
    args = parser.parse_args()
    logger = logging.getLogger('otx2misp')
    config_data = {}
    try:
        config_data = load_config(args.file_path)
        setup_global_logger(config_data)
        logger.debug("Config file loaded: " + args.file_path)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
    
    misp = initialize_misp(config_data)
    logger.debug("MISP connection is verified.")

    otx = initialize_otx(config_data)
    if otx.get_user("AlienVault"):
        logger.debug("OTX connection is verified.")
    
    pulses = get_pulses(otx, get_start_date(config_data['otx']['last_days']))
    if len(pulses) == 0:
        logger.info("No new pulses retrieved. Ending.")
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
