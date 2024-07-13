import requests
import logging
import argparse
import configparser
from datetime import datetime, timedelta
from dateutil import parser
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load configuration
config = configparser.ConfigParser()

# Function to get pulses from OTX (subscribed pulses)
def get_pulses(api_key):
    headers = {
        'X-OTX-API-KEY': api_key,
    }
    url = 'https://otx.alienvault.com/api/v1/pulses/subscribed'
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        pulses = response.json()
        return pulses
    except requests.RequestException as e:
        logging.error(f'Error fetching pulses: {e}')
        return None

# Function to filter pulses from the past week
def filter_recent_pulses(pulses):
    one_week_ago = datetime.now() - timedelta(days=7)
    recent_pulses = [
        pulse for pulse in pulses['results']
        if parser.parse(pulse['modified']) > one_week_ago
    ]
    return recent_pulses

# Function to create a Snort rule from an indicator
def create_rule(indicator, pulse_name, pulse_id, sid_counter):
    reference_link = f"https://otx.alienvault.com/pulse/{pulse_id}"
    if indicator['type'] == 'IPv4':
        return f"alert ip any any -> {indicator['indicator']} any (msg: \"OTX Pulse: {pulse_name}\"; reference:url,{reference_link}; sid:{sid_counter}; rev:1;)"
    elif indicator['type'] in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
        hash_content = indicator['indicator']
        return f"alert tcp any any -> any any (msg: \"OTX Pulse: {pulse_name}\"; content:\"{hash_content}\"; reference:url,{reference_link}; sid:{sid_counter}; rev:1;)"
    elif indicator['type'] == 'Domain':
        domain = indicator['indicator']
        return [
            f"alert udp any any -> any any (msg: \"OTX Pulse: {pulse_name} - Domain\"; content:\"{domain}\"; reference:url,{reference_link}; sid:{sid_counter}; rev:1;)",
            f"alert tcp any any -> any any (msg: \"OTX Pulse: {pulse_name} - Domain\"; content:\"{domain}\"; reference:url,{reference_link}; sid:{sid_counter + 1}; rev:1;)"
        ]
    elif indicator['type'] == 'URL':
        url_content = indicator['indicator']
        return f"alert tcp any any -> any any (msg: \"OTX Pulse: {pulse_name} - URL\"; content:\"{url_content}\"; reference:url,{reference_link}; sid:{sid_counter}; rev:1;)"
    elif indicator['type'] == 'IPv6':
        return f"alert ip any any -> {indicator['indicator']} any (msg: \"OTX Pulse: {pulse_name} - IPv6\"; reference:url,{reference_link}; sid:{sid_counter}; rev:1;)"
    elif indicator['type'] == 'CIDR':
        return f"alert ip any any -> {indicator['indicator']} any (msg: \"OTX Pulse: {pulse_name} - CIDR\"; reference:url,{reference_link}; sid:{sid_counter}; rev:1;)"
    elif indicator['type'] == 'Hostname':
        hostname = indicator['indicator']
        return [
            f"alert udp any any -> any any (msg: \"OTX Pulse: {pulse_name} - Hostname\"; content:\"{hostname}\"; reference:url,{reference_link}; sid:{sid_counter}; rev:1;)",
            f"alert tcp any any -> any any (msg: \"OTX Pulse: {pulse_name} - Hostname\"; content:\"{hostname}\"; reference:url,{reference_link}; sid:{sid_counter + 1}; rev:1;)"
        ]
    elif indicator['type'] == 'Email':
        email = indicator['indicator']
        return f"alert tcp any any -> any any (msg: \"OTX Pulse: {pulse_name} - Email\"; content:\"{email}\"; reference:url,{reference_link}; sid:{sid_counter}; rev:1;)"
    else:
        return None

# Function to create Snort rules from pulses
def create_snort_rules(pulses, sid_start):
    rules = []
    sid_counter = sid_start
    with ThreadPoolExecutor() as executor:
        for pulse in pulses:
            for indicator in pulse['indicators']:
                future = executor.submit(create_rule, indicator, pulse['name'], pulse['id'], sid_counter)
                result = future.result()
                if result:
                    if isinstance(result, list):
                        rules.extend(result)
                    else:
                        rules.append(result)
                sid_counter += 2
    return rules

# Function to save Snort rules to a file
def save_rules_to_file(rules, filename):
    with open(filename, 'w') as file:
        for rule in rules:
            file.write(rule + '\n')
    logging.info(f'Snort rules saved to {filename}')

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Generate Snort rules from OTX pulses.',
        epilog='This script generates Snort rules from OTX pulses based on various indicators such as IPs, domains, URLs, and file hashes.'
    )
    parser.add_argument('--config', type=str, default='config.ini', help='Path to configuration file')
    parser.add_argument('-k', '--api_key', type=str, help='OTX API key')
    parser.add_argument('-s', '--sid_start', type=int, help='Starting SID for rules')
    parser.add_argument('-o', '--output', type=str, help='Output file for Snort rules')
    args = parser.parse_args()

    # Load configuration
    config.read(args.config)

    api_key = args.api_key or config.get('OTX', 'API_KEY')
    output_filename = args.output or config.get('OUTPUT', 'FILENAME')
    sid_start = args.sid_start or config.getint('OUTPUT', 'SID_START')

    pulses = get_pulses(api_key)
    if pulses:
        recent_pulses = filter_recent_pulses(pulses)
        rules = create_snort_rules(recent_pulses, sid_start)
        rules = list(set(rules))  # Remove duplicates
        save_rules_to_file(rules, output_filename)

if __name__ == '__main__':
    main()
