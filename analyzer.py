# coding: utf-8
"""_summary_
V1, July 23, based on the example of Sooty
Principal scan functions
"""


import json
import os
import requests
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from bs4 import BeautifulSoup as bs
import urllib.request
from utils import *


# Analysis functions:
class Functions:
    @staticmethod
    def whois():
        """_summary_
        Check ip2location and return the results in a dedicated file in the reports directory.
            whois cmd sup:
                or
                os.system("whois " + IP + " | grep -A15 netname | grep -E 'NetName|Organization|Country|RegDate' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u > " + f"analyzer_reports/{DOMAIN_NAME_TO_IP}_whois.txt")
        """
        try:
            print(Color.GREEN + "[+] ip 2 location report: " + Color.END)
            global WHOIS

            configFile = Config_file(KEY_FILE)
            result = configFile.getIP2Location(DOMAIN_NAME_TO_IP)

            print('\t- Country code:', result['country_code'],
                    '\n\t- Country name:', result['country_name'],
                    '\n\t- Time zone:', result['time_zone'],
                    '\n\t- Categorized as public proxy:', result['is_proxy'])
            
            isProxy = str(result['is_proxy'])
            WHOIS = [result['country_name'], isProxy]
        
        except Exception as err:
            print(Color.RED + "[!] Error with IP 2 Location: " + str(err) + Color.END)


    @staticmethod
    def virusTotal():
        """_summary_
        Check VT and return the results in a dedicated file in the reports directory.
        """
        try:
            print(Color.GREEN + "[+] VirusTotal report:" + Color.END)
            global VT_COUNT
            
            configFile = Config_file(KEY_FILE)
            result = configFile.virusTotalReport(DOMAIN_NAME_TO_IP)
            count = 0

            if 'Resource does not exist in the dataset' in str(result):
                print(Color.ORANGE + '[!] Message:' + result['verbose_msg'] + Color.END)
                VT_COUNT = [0, 0]

            elif result.get('response_code') == 1:
                if result['positives'] == 0:
                    print("[!] No positives results found in " + str(result['total']) + " AV scanned")
                    VT_COUNT = [count, result['total']]

                if result['positives'] != 0:
                    print('[+] Positives results found: ' )
                    for key in result['scans']:
                        if result['scans'][key]['detected'] == True:
                            count += 1
                            charToRemove = ["{detected: ", "}"]
                            stringToDisplay = str(result['scans'][key]).replace("'", '')
                            for char in charToRemove:
                                stringToDisplay = stringToDisplay.replace(char, "")
                            print("\t- ", key, ":", stringToDisplay)

                    print(Color.GREEN + "[+] Number of detections: ", str(count) + Color.END)
                    VT_COUNT = [count, result['total']]

        except Exception as err:
            print(Color.RED + "[!] Error with Virus Total: " + str(err) + Color.END)