# coding: utf-8
"""_summary_
V1, July 23, based on the example of Sooty
V2, April 24
Principal scan functions
"""


import os
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from bs4 import BeautifulSoup as bs
import urllib.request
import ipinfo
import csv
from datetime import datetime, timezone
from utils import *
# import pprint
# import json
# import requests
# import netlas


# Returns the variable "DOMAIN_NAME_TO_IP", which can be used in the following functions
print(Color.ORANGE + "[+] Check whether the input is a domain or an IP address" + Color.END)
print("--------------------------------------------------------------------------------------------------------")
DOMAIN_NAME_TO_IP = Check_INPUT.checkInput()


# Analysis functions:
class Functions:
    # [+] Checking public Whois sources
    @staticmethod
    def ip2Location():
        """_summary_
        Check ip2location and return the responses in a dedicated file in the reports directory.
        """
        try:
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
            print('IP2Location error: ', err)


    @staticmethod
    def ipInfo():
        """_summary_
        Check ipinfo and return the responses in a dedicated file in the reports directory.
        """
        try:
            global WHOIS_IPINFO

            configFile = Config_file(KEY_FILE)
            ipInfoKey = configFile.getIPInfo()

            handler = ipinfo.getHandler(access_token=ipInfoKey)
            response = handler.getDetails(DOMAIN_NAME_TO_IP)

            if DOMAIN_NAME_TO_IP:
                print('\t- Organisation/ASN:', response.org,
                        '\n\t- City:', response.city,
                        '\n\t- Region:', response.region,
                        '\n\t- Continent:', response.continent['name'],
                        '\n\t- Continent code:', response.continent['code'],
                        '\n\t- Is European:', response.isEU,
                        '\n\t- GPS coordinates:', response.loc,
                        '\n\t- Time zone:', response.timezone)

                WHOIS_IPINFO = [response.country, response.org, response.continent['name'], response.region]
            else:
                print(Color.RED + "[!] no valid IP address found" + Color.END)
                pass
        
        except Exception as err:
            print('IPInfo error: ', err)   


    # @staticmethod
    # def netlas():
    #     """_summary_
    #     Check netlas and return the responses in a dedicated file in the reports directory.
    #     Whois is more complete, but has certain restrictions on API use https://app.netlas.io/.
    #     Use of the Netlas library must be confirmed.
    #     """
    #     try:
    #         global NETLAS

    #         configFile = Config_file(KEY_FILE)
    #         response = configFile.getNetlas(DOMAIN_NAME_TO_IP)

    #         pprint.pprint(response)

    #         NETLAS = []

    #     except Exception as err:
    #         print('Netlas', err)


    # [+] Checking public CTI sources
    @staticmethod
    def virusTotal():
        """_summary_
        Check VT and return the responses in a dedicated file in the reports directory.
        """
        try:
            global VT_COUNT
            
            configFile = Config_file(KEY_FILE)
            response = configFile.getVirusTotal(DOMAIN_NAME_TO_IP)
            count = 0

            if 'Resource does not exist in the dataset' in str(response):
                print(Color.ORANGE + '[!] Message: ' + response['verbose_msg'] + Color.END)
                VT_COUNT = [0, 0, 0]

            elif response.get('response_code') == 1:
                if response['positives'] == 0:
                    print("[!] No positives responses found in " + str(response['total']) + " AV scanned")
                    VT_COUNT = [count, response['total'], response['permalink']]

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

                    print(Color.BLUE + "[+] Number of detections: ", str(count) + Color.END)
                    VT_COUNT = [count, response['total'], response['permalink']]
        except Exception as err:
            print('VT error: ', err)
            VT_COUNT = [0, 0, 0]


    @staticmethod
    def criminalIP():
        """_summary_
        Check CriminalIP and return the responses in a dedicated file in the reports directory.
        """
        try:
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

                    print('\t- Ports with vulnerabilities:')
                    for key in range(len(response['current_opened_port']['data'])):
                        if (response['current_opened_port']['count'] <= 10 or response['current_opened_port']['count'] > 10):
                            if response['current_opened_port']['data'][key]['has_vulnerability'] == True:
                                print('\t\t-',
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
            
            CRIMINALIP_COUNTS = [count, response['current_opened_port']['count'], response['vulnerability']['count'], 
                                 response['ip_category']['count']]
        
        except Exception as err:
            print('CriminalIP error: ', err)


    @staticmethod
    def abuseIPDB():
        """_summary_
        Check AbuseIPDB and return the responses in a dedicated file in the reports directory.
        """
        try:
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

        except Exception as err:
            print('AbuseIPDB error: ', err)        


    @staticmethod
    def alienVault():
        """_summary_
        Check AlienVault and return the responses in a dedicated file in the reports directory.
        """
        try:
            global OTX_COUNT

            configFile = Config_file(KEY_FILE)
            alienVaultKey = configFile.getAlienVault()

            handler = OTXv2(alienVaultKey)
            response = handler.get_indicator_details_full(IndicatorTypes.IPv4, Check_INPUT.checkInput())

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
        
        except Exception as err:
            print('AlienVault error: ', err)
            OTX_COUNT = 0


    @staticmethod
    def threatBook():
        """_summary_
        Check Threatbook and return the responses in a dedicated file in the reports directory.
        """
        try:
            global THREATBOOK
            
            configFile = Config_file(KEY_FILE)
            response = configFile.getThreatBook(DOMAIN_NAME_TO_IP)
            count = 0
            CHAR = string.ascii_lowercase
            executed = False
            if any(char in DOMAIN for char in CHAR):
                executed = True
                print('\t- ASN number:', response['data']['asn']['number'],
                        '\n\t- ASN rank:', response['data']['asn']['rank'],
                        '\n\t- Ports:', response['data']['ports'],
                        '\n\t- Judgment:', response['data']['summary']['judgments'],
                        '\n\t- Is whitelisted:', response['data']['summary']['whitelist'],
                        f'\n\t- Link: https://threatbook.io/domain/{DOMAIN}')
                tbLink = f'https://threatbook.io/domain/{DOMAIN}'
            else:
                executed = False
                print('\t- ASN number:', response['data']['asn']['number'],
                        '\n\t- ASN rank:', response['data']['asn']['rank'],
                        '\n\t- Ports:', response['data']['ports'],
                        '\n\t- Judgment:', response['data']['summary']['judgments'],
                        '\n\t- Is whitelisted:', response['data']['summary']['whitelist'],
                        f'\n\t- Link: https://threatbook.io/ip/{DOMAIN_NAME_TO_IP}')
                tbLink = f'https://threatbook.io/ip/{DOMAIN_NAME_TO_IP}'
            
            if response['data']['summary']['judgments']:
                THREATBOOK = [count+1, str(response['data']['summary']['judgments']), response['data']['ports'], tbLink]
            else:
                THREATBOOK = [count, str(response['data']['summary']['judgments']), response['data']['ports'], tbLink]
        
        except Exception as err:
            print('ThreatBook error: ', err)
            count = 0
            response['data']['summary']['judgments'] = []
            response['data']['ports'] = []
            THREATBOOK = [count, str(response['data']['summary']['judgments']), response['data']['ports'], tbLink]

    
    @staticmethod
    def greyNoise():
        """_summary_
        Check Greynoise and return the responses in a dedicated file in the reports directory.
        """
        try:
            global GREYNOISE
            
            configFile = Config_file(KEY_FILE)
            response = configFile.getGreyNoise(DOMAIN_NAME_TO_IP)
            count = 0
            riot = False  
            message = "IP not observed scanning the internet or contained in RIOT data set."
            
            if message in response['message']:
                print('IP not observed scanning the internet or contained in RIOT data set',
                      '\n\t- Present in RIOT DB:', response['riot'],
                      '\n\t- Scanning internet in the last 90 days:', response['noise'])

                GREYNOISE = [count, riot]

            else:
                print('\t- Classification:', response['classification'],
                            '\n\t- Scanning internet in the last 90 days:', response['noise'],
                            '\n\t- Present in RIOT DB:', response['riot'],
                            '\n\t- Last seen:', response['last_seen'],
                            '\n\t- Link:',response['link'])
            
                if 'benign' in response['classification']:
                        count = count+1
                
                if 'malicious' in response['classification']:
                        count = count+2

                if response['riot'] != True:
                        riot = riot
                else:
                    riot = True

            GREYNOISE = [count, riot]

        except Exception as err:
            print('Greynoise error: ', err)
            count = 0
            riot = False
            GREYNOISE = [count, riot]
            

    @staticmethod
    def urlScan():
        """_summary_
        Check URL Scan and return the responses in a dedicated file in the reports directory.
        Improvement needed
        """
        try:
            global URLSCAN
            
            configFile = Config_file(KEY_FILE)
            response = configFile.getURLScan(DOMAIN_NAME_TO_IP)
            count = 0
            URL_SCAN_REPORT = f'/home/{USERNAME}/Documents/url_scan_report.json'

            with open(URL_SCAN_REPORT, 'r') as url_scan_report:
                data = json.load(url_scan_report)
                if 'data' in data and 'requests' in data['data']:
                    requests_data = data['data']['requests']
                    if requests_data:
                        key = 0  # Use index 0 to access the first (and only) entry
                        print('[+] Header:')
                        if data['data']['requests'][0]['response']['failed']:
                            keys = data['data']['requests'][0]['response']['failed']
                            for key, value in keys.items():
                                print(f'\t- {key}: {value}')
                            print(Color.RED + '[!] Response failed' + Color.END)
                            count = count
                        else:
                            headers = requests_data[key]['response']['response']['headers']
                            for header, value in headers.items():  # Loop in Headers
                                print(f'\t- {header}: {value}')
                            print('[+] Response:')
                            print('\t- RemotePort:', requests_data[key]['response']['response']['remotePort'],
                                '\n\t- Protocol:', requests_data[key]['response']['response']['protocol'])
                    else:
                        print('No data in requests')
                else:
                    print('No key "data" or "requests"')

                print('[+] Cookies and links found:')
                if 'data' in data:
                    if 'links' in data['data']:
                        print('\t- Links:')
                        for link in data['data']['links']:
                            for key, value in link.items():
                                print(f'\t\t- {key}: {value}')
                    else:
                        print('No links found')
                        
                    if 'cookies' in data['data']:
                        print('\t- Cookies:')
                        for i, cookie in enumerate(data['data']['cookies']):  
                            if i == 0:
                                print('', end=' ')  # improve indentation
                            else:
                                print('\t\t-', end=' ')
                            for key, value in cookie.items():
                                print(f'\t\t- {key}: {value}')
                    else:
                        print('No cookies found')
                else:
                    print('no key data')

                print('[+] Domain Infos:')
                if 'lists' in data:
                    for key, value in data['lists'].items():
                        if key != 'certificates':
                            print('\t- {}: {}'.format(key.capitalize(), ', '.join(map(str, value))))
                else:
                    print('no key in first loop')

                if 'certificates' in data['lists']:
                    print('[+] Certificates:')
                    for certificates in data['lists']['certificates']:
                        print('\t- Certificate:')
                        for key in ['subjectName', 'issuer', 'validFrom', 'validTo']:
                            if key in certificates:
                                if key.startswith('valid'):
                                    value = datetime.fromtimestamp(certificates[key], timezone.utc)
                                else:
                                    value = certificates[key]
                                print(f'\t\t- {key.capitalize()}: {value}')

                else:
                    print('no key lists')
                
                if 'verdicts' in data:
                    print('[+] URL Scan Verdict: ')
                    verdicts = data['verdicts']['urlscan']
                    for key in ['hasVerdicts', 'malicious']:
                        if key in verdicts:
                            print(f'\t- {key.capitalize()}: {verdicts[key]}')

            url_scan_report.close()
            os.system(f'rm -rf {URL_SCAN_REPORT}')
          
            URLSCAN = [count]

        except Exception as err:
            print('URL Scan error: ', err)
            URLSCAN = [count]


    # [+] Checking public Blacklists
    @staticmethod
    def duggyTuxy():
        """_summary_
        These are the IP addresses of the most active Botnets/Zombies/Scanners in European Cyber Space
        """
        try:
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

        except Exception as err:
            print('DuggyTuxy error: ', err)


    @staticmethod
    def ipsum():
        """_summary_
        IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses like:
            abuseipdb, alienvault, atmos, badips, bitcoinnodes, blocklist, botscout, cobaltstrike, malwaredomains, proxylists, 
            ransomwaretrackerurl, talosintelligence, torproject, etc.
        """
        try:
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

        except Exception as err:
            print('IPSum error: ', err)
    

    @staticmethod
    def redflagDomains():
        """_summary_
        Redflag Domains are lists of very recently registered probably malicious domain names in french TLDs
        """
        try:
            global REDFLAGDOMAINS_COUNT

            configURL = Config_urls()
            url = configURL.getRedflagDomains()
            count = 0

            CHAR = string.ascii_lowercase
            executed = False
            if any(char in DOMAIN for char in CHAR):
                executed = True
                os.system(f'wget {url} 2>/dev/null')
                with open('red.flag.domains.txt', 'r') as redflag:
                        redflag_domains = redflag.read()
                        if DOMAIN in redflag_domains:
                            print(f'[!] {DOMAIN} founded in Redflag Domains')
                            os.system('rm -rf red.flag.domains.txt')
                            count += 1
                            redflag.close()
                        else:
                            print('[+]', DOMAIN, "Not found in Redflag Domains")
                            os.system('rm -rf red.flag.domains.txt')
                            count == count
                            redflag.close()
            else:
                print('[+] No domain name provided')    
            REDFLAGDOMAINS_COUNT = count

        except Exception as err:
            print('RedFlag error: ', err)


    # [+] Checking internal IOCs
    @staticmethod
    def tlpAmberCheck(ioc, tlp_url):
        """_summary_
        IP address or domain present in internal IOCs
        """
        try:
            USERNAME = os.getenv("USER")
            tlp_url = f"/home/{USERNAME}/Downloads/tlp.csv"  # Use for tests
            # configURL = Config_urls()
            # url = configURL.getTLP()

            # os.system(f'wget {url} 2>/dev/null')
            with open(tlp_url, newline='') as tlp_file:
                reader = csv.DictReader(tlp_file)
                for row in reader:
                    if row['domain'] == DOMAIN or row['domain'] == DOMAIN_NAME_TO_IP:
                        return {
                            'domain': row['domain'],
                            'entry_date': row['entry date'],
                            'expired': row['expired'],
                            'category': row['category']
                        }
                tlp_file.close()
                return None
        
        except Exception as err:
            print('CheckTLP error: ', err)


    @staticmethod
    def tlpAmber():
        """_summary_
        IP address or domain present in internal IOCs, Use tlpAmberCheck()
        """
        try:
            global TLP_COUNT
            CHAR = string.ascii_lowercase
            count = 0
            if any(char in DOMAIN for char in CHAR):
                ioc = DOMAIN
            else:
                ioc = DOMAIN_NAME_TO_IP
            USERNAME = os.getenv("USER")
            csv_file_path = f"/home/{USERNAME}/Downloads/tlp.csv"

            result = Functions.tlpAmberCheck(ioc, csv_file_path)
            if result:
                print('\t- IOC :', result['domain'],
                            '\n\t- First seen :', result['entry_date'],
                            '\n\t- Expired :', result['expired'],
                            '\n\t- Category :', result['category'])
                count += 1
            else:
                print(ioc, "not found")
                count = count

            TLP_COUNT = count

        except Exception as err:
            print('TLPAmber error: ', err)


class Count:
    """_summary_
    Sends constants to summary class
    """
    @staticmethod
    def count():
        try:
            return [WHOIS, VT_COUNT, DUGGY_COUNT, IPSUM_COUNT,CRIMINALIP_COUNTS, ABUSEIPDB_CONFIDENCE, 
                    OTX_COUNT, THREATBOOK, GREYNOISE, REDFLAGDOMAINS_COUNT, TLP_COUNT, WHOIS_IPINFO]
        
        except Exception as err:
            print('Counting error: ', err)
            exit()