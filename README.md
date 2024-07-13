# OTX2Snort
Python script created to generate Snort rules from IOCs observed in AlienVault OTX pulses during the past week that are subscribed to by a user.

# Usage Options:
  - --config CONFIG       (Path to configuration file)
    
  - -h, --help            (show this help message and exit)
  - -k API_KEY, --api_key API_KEY
                        (OTX API key)
  - -s SID_START, --sid_start SID_START
                        (Starting SID for rules)
  - -o OUTPUT, --output OUTPUT
                        (Output file for Snort rules)
