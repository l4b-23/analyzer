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


# Returns the variable "DOMAIN_NAME_TO_IP", which can be used in the following functions
print(Color.ORANGE + "[+] Check whether the input is a domain or an IP address" + Color.END)
print("--------------------------------------------------------------------------------------------------------")
DOMAIN_NAME_TO_IP = Check_INPUT.checkInput()
print("--------------------------------------------------------------------------------------------------------")


# Analysis functions:
class Functions:
    # [+] Checking public Whois sources
    @staticmethod
    def ip2Location():
        """_summary_
        Check ip2location and return the responses in a dedicated file in the reports directory.
            whois cmd sup:
                or
                os.system("whois " + IP + " | grep -A15 netname | grep -E 'NetName|Organization|Country|RegDate' | sed 's/^\ *//g' | tr '[A-Z]' '[a-z]' | sort -u > " + f"analyzer_reports/{DOMAIN_NAME_TO_IP}_whois.txt")
        """
        try:
            print(Color.GREEN + "[+] ip 2 location report: " + Color.END)
            global WHOIS

            configFile = Config_file(KEY_FILE)
            response = configFile.getIP2Location(DOMAIN_NAME_TO_IP)

            print('\t- Country code:', response['country_code'],
                    '\n\t- Country name:', response['country_name'],
                    '\n\t- Time zone:', response['time_zone'],
                    '\n\t- Categorized as public proxy:', response['is_proxy'])
            
            isProxy = str(response['is_proxy'])
            WHOIS = [response['country_name'], isProxy]
        
        except Exception as err:
            print(Color.RED + "[!] Error with IP 2 Location: " + str(err) + Color.END)


    # [+] Checking public CTI sources
    @staticmethod
    def virusTotal():
        """_summary_
        Check VT and return the responses in a dedicated file in the reports directory.
        """
        try:
            print(Color.GREEN + "[+] VirusTotal report:" + Color.END)
            global VT_COUNT
            
            configFile = Config_file(KEY_FILE)
            response = configFile.getVirusTotal(DOMAIN_NAME_TO_IP)
            count = 0

            if 'Resource does not exist in the dataset' in str(response):
                print(Color.ORANGE + '[!] Message: ' + response['verbose_msg'] + Color.END)
                VT_COUNT = [0, 0]

            elif response.get('response_code') == 1:
                if response['positives'] == 0:
                    print("[!] No positives responses found in " + str(response['total']) + " AV scanned")
                    VT_COUNT = [count, response['total']]

                if response['positives'] != 0:
                    print('[+] Positives responses found: ' )
                    for key in response['scans']:
                        if response['scans'][key]['detected'] == True:
                            count += 1
                            charToRemove = ["{detected: ", "}"]
                            stringToDisplay = str(response['scans'][key]).replace("'", '')
                            for char in charToRemove:
                                stringToDisplay = stringToDisplay.replace(char, "")
                            print("\t- ", key, ":", stringToDisplay)

                    print(Color.GREEN + "[+] Number of detections: ", str(count) + Color.END)
                    VT_COUNT = [count, response['total']]

        except Exception as err:
            print(Color.RED + "[!] Error with Virus Total: " + str(err) + Color.END)


    @staticmethod
    def criminalIP():
        try:
            print(Color.GREEN + "[+] Criminal IP report:" + Color.END)
            global CRIMINALIP_COUNTS

            configFile = Config_file(KEY_FILE)
            response = configFile.getCtiminalIP(DOMAIN_NAME_TO_IP)
            count = 0

            if response['is_malicious'] == True:
                count += 1
                print("[+] Malicious IP:", response['is_malicious'],
                        '\n[+] VPN:',response['is_vpn'],
                        '\n[+] Remote access:', response['can_remote_access'],
                        '\n[+] Remote port:', response['remote_port'],
                        '\n[+] IDS:', response['ids'])

                if response['current_opened_port']['count'] != 0:
                    print('[+] Count of opened ports:', response['current_opened_port']['count'])
                    portsCount = 0

                    for key in range(len(response['current_opened_port']['data'])):
                        if (response['current_opened_port']['count'] <= 10 or response['current_opened_port']['count'] > 10):
                            if response['current_opened_port']['data'][key]['has_vulnerability'] == True:
                                print('\t-',
                                    response['current_opened_port']['data'][key]['socket_type'],
                                    response['current_opened_port']['data'][key]['port'],
                                    response['current_opened_port']['data'][key]['protocol'],
                                    response['current_opened_port']['data'][key]['product_name'],
                                    response['current_opened_port']['data'][key]['product_version'],
                                    response['current_opened_port']['data'][key]['has_vulnerability'])
                                portsCount = portsCount + 1
                                if portsCount == 10:
                                    break

                if response['vulnerability']['count'] != 0:
                    print('[+] Count of vulnerabilities founded:',response['vulnerability']['count'])
                    charToRemove = ["{", "}", "[", "]"]
                    vulCount = 0

                    for key in range(len(response['vulnerability']['data'])):
                        stringToDisplay = str(response['vulnerability']['data'][key]['ports']).replace("'", '')
                        if (response['vulnerability']['count'] <= 10 or response['vulnerability']['count'] > 10):
                            for char in charToRemove:
                                stringToDisplay = stringToDisplay.replace(char, "")
                            print('\t-',
                                response['vulnerability']['data'][key]['cve_id'],
                                response['vulnerability']['data'][key]['cvssv2_score'],
                                response['vulnerability']['data'][key]['cvssv3_score'],
                                response['vulnerability']['data'][key]['product_version'],
                                response['vulnerability']['data'][key]['product_vendor'])
                            vulCount = vulCount + 1
                            if vulCount == 10:
                                break

                if response['ip_category']['count'] != 0:
                    print('[+] count of IP category: ', response['ip_category']['count'],
                            '\n[+] IP category:')
                    for key in range(len(response['ip_category']['data'])):
                        print('\t-', response['ip_category']['data'][key]['type'])

            else:
                count == count
                print(DOMAIN_NAME_TO_IP, 'Not found in CriminalIP.io')
            
            CRIMINALIP_COUNTS = [count, response['current_opened_port']['count'], response['vulnerability']['count'], response['ip_category']['count']]
        
        except KeyError as err:
            print(Color.RED + "[!] KeyError occured: ", str(err) + Color.END)
        except TypeError as err:
            print(Color.RED + "[!] TypeError occurred:", str(err) + Color.END)
        except Exception as err:
            print(Color.RED + "[!] Error with CriminalIP: " + err + Color.END)


    @staticmethod
    def abuseIPDB():
        try:
            print(Color.GREEN + "[+] AbuseIPDB report:" + Color.END)
            global ABUSEIPDB_CONFIDENCE

            configFile = Config_file(KEY_FILE)
            response = configFile.getAbuseIPDB(DOMAIN_NAME_TO_IP)

            print('[+] Count of reports:', response['data']['totalReports'])
            print(
                '\t- Whiteliested:', response['data']["isWhitelisted"],
                '\n\t- Confidence in %:', response['data']["abuseConfidenceScore"],
                '\n\t- Country code:', response['data']["countryCode"], 
                '\n\t- ISP:', response['data']["isp"], 
                '\n\t- Domain:', response['data']["domain"], 
                '\n\t- Is TOR node:', response['data']["isTor"], 
                '\n\t- Distinct users:', response['data']["numDistinctUsers"], 
                '\n\t- Last report date:', response['data']["lastReportedAt"])
            
            ABUSEIPDB_CONFIDENCE = [response['data']['totalReports'], response['data']["abuseConfidenceScore"]]
                
        except KeyError as err:
            print(Color.RED + "[!] KeyError occured: ", str(err) + Color.END)
        except TypeError as err:
            print(Color.RED + "[!] TypeError occurred:", str(err) + Color.END)
        except Exception as err:
            print(Color.RED + "[!] Error with AbuseIPDB:" + err + Color.END)

    @staticmethod
    def alienVault():
        try:
            print(Color.GREEN + "[+] OTX report:" + Color.END)
            global OTX_COUNT

            configFile = Config_file(KEY_FILE)
            alienVaultKey = configFile.getAlienVault()

            otx = OTXv2(alienVaultKey)
            response = otx.get_indicator_details_full(IndicatorTypes.IPv4, Check_INPUT.checkInput())

            print("[+] Reputation:", response['general']['reputation'],
                    "\n[+] Count of pulses reported:", response['general']['pulse_info']['count'])
            
            OTX_COUNT = response['general']['pulse_info']['count']
            
            if response['general']['pulse_info']['count'] != 0:
                print("[+] Last puple containing tags: ")
                tagCount = 0

                for key in range(len(response['general']['pulse_info']['pulses'])):
                    tags = str(response['general']['pulse_info']['pulses'][key]['tags'])
                    charToRemove = ["[", "]", "'"]
                    if response['general']['pulse_info']['pulses'][key]['tags'] != []:
                        for char in charToRemove:
                            tags = tags.replace(char, '')
                        print(
                            '\t- Description:', response['general']['pulse_info']['pulses'][key]['description'],
                            '\n\t- Last update:', response['general']['pulse_info']['pulses'][key]['modified'],
                            '\n\t- Tags:',tags,
                            '\n')
                        if tagCount == 1:
                            break
                        tagCount = tagCount + 1
        
        except KeyError as err:
            print(Color.RED + "[!] KeyError occured: ", str(err) + Color.END)
            OTX_COUNT = 0
        except TypeError as err:
            print(Color.RED + "[!] TypeError occurred:", str(err) + Color.END)
            OTX_COUNT = 0
        except Exception:
            print(Color.RED + "[!] Error with OTX: probably a wrong input value" + Color.END)
            OTX_COUNT = 0

    # [+] Checking public Blacklists
    @staticmethod
    def duggyTuxy():
        """
        These are the IP addresses of the most active Botnets/Zombies/Scanners in European Cyber Space
        """
        try:
            print(Color.GREEN + "[+] Duggy Tuxy report:" + Color.END)
            global DUGGY_COUNT

            configURL = Config_urls()
            url = configURL.getDuggyTuxy()
            count = 0

            page = urllib.request.urlopen(url,timeout=5).read()
            soup = bs(page, 'html.parser')  # or 'lxml'
            text = soup.get_text()

            if DOMAIN_NAME_TO_IP in str(text):
                count += 1
                print('[!]', DOMAIN_NAME_TO_IP, 'Found in the list. Possible active Botnets/Zombies/Scanners in European Cyber Space')
            else:
                count == count
                print('[+]', DOMAIN_NAME_TO_IP, "Not found in the Duggy Tuxy's list")
            
            DUGGY_COUNT = count

        except KeyError as err:
            print(Color.RED + "[!] KeyError occured: ", str(err) + Color.END)
        except TypeError as err:
            print(Color.RED + "[!] TypeError occurred:", str(err) + Color.END)
        except Exception as err:
            print(Color.RED + "[!] Error with Duggy Tuxy's list: " + err + Color.END)

    @staticmethod
    def ipsum():
        """
        IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses like:
            abuseipdb, alienvault, atmos, badips, bitcoinnodes, blocklist, botscout, cobaltstrike, malwaredomains, proxylists, ransomwaretrackerurl, talosintelligence, torproject, etc.
        """
        try:
            print(Color.GREEN + "[+] IPsum report:" + Color.END)
            global IPSUM_COUNT

            configURL = Config_urls()
            url = configURL.getIpsum()
            count = 0
            blacklists = 0
        
            page = urllib.request.urlopen(url,timeout=5).read()
            soup = bs(page, 'html.parser')
            text = soup.get_text()

            if DOMAIN_NAME_TO_IP in str(text):
                count += 1
                print('[!]', DOMAIN_NAME_TO_IP, 'Found in the list.')
                os.system(f'curl --compressed https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt 2>/dev/null | grep -v "#" | grep {DOMAIN_NAME_TO_IP} | cut -f 2 > out.txt')

                with open('out.txt', 'r') as blacklisted:
                    blacklists = blacklisted.read()
                    if int(blacklists) != 0:
                        print(f'[!] {DOMAIN_NAME_TO_IP} founded in:', int(blacklists),'blacklists')
                        blacklisted.close()
                        os.system('rm -rf out.txt')

            else:
                count == count
                blacklists = blacklists
                print('[+]', DOMAIN_NAME_TO_IP, "Not found in the IPsum's blacklists")
            
            IPSUM_COUNT = [count, int(blacklists)]

        except KeyError as err:
            print(Color.RED + "[!] KeyError occured: ", str(err) + Color.END)
        except TypeError as err:
            print(Color.RED + "[!] TypeError occurred:", str(err) + Color.END)
        except Exception as err:
            print(Color.RED + "[!] Error with IPsum's blacklists: "+ err + Color.END)


class Count:
    """_summary_
    Sends constants to summary class
    """
    @staticmethod
    def count():
        try:
            return [WHOIS, VT_COUNT, DUGGY_COUNT, IPSUM_COUNT,CRIMINALIP_COUNTS, ABUSEIPDB_CONFIDENCE, OTX_COUNT]
        except Exception:
            print(Color.RED + "[!] Counting error" + Color.END)
            exit()