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
import urllib3
import ipinfo
import csv
from datetime import datetime, timezone
from utils import *

# import netlas


# Returns the variable "DOMAIN_NAME_TO_IP", which can be used in the following functions
print(Color.ORANGE + "[+] Check whether the input is a domain or an IP address" + Color.END)
print("--------------------------------------------------------------------------------------------------------")
DOMAIN_NAME_TO_IP = Check_INPUT.checkInput()


# Analysis functions:
class Functions:
    # Checking public Whois sources
    @staticmethod
    def ip2Location():
        """_summary_
        Check ip2location and return the responses in a dedicated file in the reports directory.
        """
        try:
            global WHOIS

            config_file = Config_file(KEY_FILE)
            response = config_file.getIP2Location(DOMAIN_NAME_TO_IP)

            print('\t- Country code:', response['country_code'],
                '\n\t- Country name:', response['country_name'],
                '\n\t- Time zone:', response['time_zone'],
                '\n\t- Categorized as public proxy:', response['is_proxy'])
            
            is_proxy = str(response['is_proxy'])

            WHOIS = [response['country_name'], is_proxy]
        
        except Exception as err:
            print('IP 2 Location error: ', err)
            WHOIS = [0, 0]


    @staticmethod
    def ipInfo():
        """_summary_
        Check ipinfo and return the responses in a dedicated file in the reports directory.
        """
        try:
            global WHOIS_IPINFO

            config_file = Config_file(KEY_FILE)
            ip_info_key = config_file.getIPInfo()

            handler = ipinfo.getHandler(access_token=ip_info_key)
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
            print('IP Info error: ', err)   
            WHOIS_IPINFO = [0, 0, 0, 0]


    # @staticmethod
    # def netlas():
    #     """_summary_
    #     Check netlas and return the responses in a dedicated file in the reports directory.
    #     Whois is more complete, but has certain restrictions on API use https://app.netlas.io/.
    #     Use of the Netlas library must be confirmed.
    #     """
    #     try:
    #         global NETLAS

    #         config_file = Config_file(KEY_FILE)
    #         response = config_file.getNetlas(DOMAIN_NAME_TO_IP)

    #         pprint.pprint(response)

    #         NETLAS = []

    #     except Exception as err:
    #         print('Netlas', err)


    # Checking public CTI sources
    @staticmethod
    def virusTotal():
        """_summary_
        Check VT and return the responses in a dedicated file in the reports directory.
        """
        try:
            global VT_COUNT
            
            config_file = Config_file(KEY_FILE)
            response = config_file.getVirusTotal(DOMAIN_NAME_TO_IP)
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
                    for key, value in response['scans'].items():
                        if value['detected'] or (value['result'] != 'clean site' and value['result'] != 'unrated site'):
                            count += 1
                            result = value['result']
                            print(f"\t- {key}: {result}")
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

            config_file = Config_file(KEY_FILE)
            response = config_file.getCtiminalIP(DOMAIN_NAME_TO_IP)
            count = 0

            if response['is_malicious'] == True:
                count += 1
                print("[+] Malicious IP:", response['is_malicious'],
                    '\n[+] VPN:',response['is_vpn'],
                    '\n[+] Remote access:', response['can_remote_access'])
                print("[+] Remote port:",
                    "\n\t- count:", len(response['remote_port']['data']),
                    "\n\t- data:")

                # Display remote port(s) info
                for port_info in response['remote_port']['data']:
                    print("\t\t- socket_type:", port_info['socket_type'],
                        "\n\t\t- port:", port_info['port'],
                        "\n\t\t- protocol:", port_info['protocol'],
                        "\n\t\t- product_name:", port_info['product_name'],
                        "\n\t\t- product_version:", port_info['product_version'],
                        "\n\t\t- has_vulnerability:", port_info['has_vulnerability'],
                        "\n\t\t- confirmed_time:", port_info['confirmed_time'], '\n')
                
                # Display IDS info
                print("[+] IDS:"
                    "\n\t- count:", len(response['ids']['data']),
                    "\n\t- data:")
                for id_info in response['ids']['data']:
                    print("\t\t- classification:", id_info['classification'],
                        "\n\t\t- url:", id_info['url'],
                        "\n\t\t- message:", id_info['message'],
                        "\n\t\t- source_system:", id_info['source_system'],
                        "\n\t\t- confirmed_time:", id_info['confirmed_time'], '\n')

                if response['current_opened_port']['count'] != 0:
                    print('[+] Count of opened ports:', response['current_opened_port']['count'])
                    ports_count = response['current_opened_port']['count']

                    print('\t- Top 10 Ports with vulnerabilities:')
                    for port_info in response['current_opened_port']['data']:
                        if port_info['has_vulnerability']:
                            print('\t\t-',
                                port_info['socket_type'],
                                port_info['port'],
                                port_info['protocol'] if port_info['protocol'] else "None",
                                port_info['product_name'],
                                port_info['product_version'],
                                'Vulnerable: ', port_info['has_vulnerability'])
                            ports_count = ports_count + 1
                            if ports_count == 10:
                                break

                # Display vuln info
                if response['vulnerability']['count'] != 0:
                    print('[+] Count of vulnerabilities founded:',response['vulnerability']['count'],
                        '\n[+] Here are the top 10:')
                    vuln_count = 0

                    for vuln in response['vulnerability']['data']:
                        print('\t-',
                            vuln['cve_id'],
                            vuln['cvssv2_score'],
                            vuln['cvssv3_score'],
                            vuln['product_version'],
                            vuln['product_vendor'])
                        vuln_count = vuln_count + 1
                        if vuln_count == 10:
                            break

                if response['ip_category']['count'] != 0:
                    print('[+] Count of IP category: ', response['ip_category']['count'],
                            '\n[+] IP category:')
                    for key in range(len(response['ip_category']['data'])):
                        print('\t-', response['ip_category']['data'][key]['type'])

            else:
                count == count
                print('[+]', DOMAIN_NAME_TO_IP, 'Not found in Criminal IP')
            
            CRIMINALIP_COUNTS = [count, response['current_opened_port']['count'], response['vulnerability']['count'], response['ip_category']['count']]
        
        except Exception as err:
            print('Criminal IP error:', err)
            CRIMINALIP_COUNTS = [0, 0, 0, 0]


    @staticmethod
    def abuseIPDB():
        """_summary_
        Check AbuseIPDB and return the responses in a dedicated file in the reports directory.
        """
        try:
            global ABUSEIPDB_CONFIDENCE

            config_file = Config_file(KEY_FILE)
            response = config_file.getAbuseIPDB(DOMAIN_NAME_TO_IP)

            print('[+] Count of reports:', response['data']['totalReports'],
                '\n\t- Whiteliested:', response['data']["isWhitelisted"],
                '\n\t- Confidence in %:', response['data']["abuseConfidenceScore"],
                '\n\t- Country code:', response['data']["countryCode"], 
                '\n\t- ISP:', response['data']["isp"], 
                '\n\t- Domain:', response['data']["domain"], 
                '\n\t- Is TOR node:', response['data']["isTor"], 
                '\n\t- Distinct users:', response['data']["numDistinctUsers"], 
                '\n\t- Last report date:', response['data']["lastReportedAt"])
            
            ABUSEIPDB_CONFIDENCE = [response['data']['totalReports'], response['data']["abuseConfidenceScore"]]

        except Exception as err:
            print('Abuse IP DB error: ', err)
            ABUSEIPDB_CONFIDENCE = [0, 0]      


    @staticmethod
    def alienVault():
        """_summary_
        Check AlienVault and return the responses in a dedicated file in the reports directory.
        """
        try:
            global OTX_COUNT

            config_file = Config_file(KEY_FILE)
            alien_vault_key = config_file.getAlienVault()

            handler = OTXv2(alien_vault_key)
            response = handler.get_indicator_details_full(IndicatorTypes.IPv4, Check_INPUT.checkInput())

            print("[+] Reputation:", response['general']['reputation'],
                "\n[+] Count of pulses reported:", response['general']['pulse_info']['count'])
            
            OTX_COUNT = response['general']['pulse_info']['count']
            
            if response['general']['pulse_info']['count'] != 0:
                print("[+] Last puple containing tags: ")
                tag_count = 0

            for pulse in response['general']['pulse_info']['pulses']:
                tags = ", ".join(pulse.get('tags', []))
                print('\t- Description:', pulse['description'],
                    '\n\t- Last update:', pulse['modified'],
                    '\n\t- Tags:', tags,'\n')
                
                if tag_count == 1:
                    break
                tag_count += 1
        
        except Exception as err:
            print('Alien Vault error: ', err)
            OTX_COUNT = 0


    @staticmethod
    def threatBook():
        """_summary_
        Check Threatbook and return the responses in a dedicated file in the reports directory.
        """
        try:
            global THREATBOOK
            CHAR = string.ascii_lowercase
            
            config_file = Config_file(KEY_FILE)
            response = config_file.getThreatBook(DOMAIN_NAME_TO_IP)
            count = 0
            executed = False

            if any(char in DOMAIN for char in CHAR):
                executed = True
                print('\t- ASN number:', response['data']['asn']['number'],
                    '\n\t- ASN rank:', response['data']['asn']['rank'],
                    '\n\t- Judgment:', response['data']['summary']['judgments'],
                    '\n\t- Is whitelisted:', response['data']['summary']['whitelist'],
                    f'\n\t- Link: https://threatbook.io/domain/{DOMAIN}',
                    '\n\t- Top 10 ports:')
                
                if isinstance(response['data']['ports'], list):
                    max_ports = 10
                    ports_displayed = 0
                    for port in response['data']['ports']:
                        if ports_displayed < max_ports:
                            port_str = ', '.join([f"{key}: {value}" for key, value in port.items()])
                            print(f'\t\t- {port_str}')
                            ports_displayed += 1
                        else:
                            break
                tb_link = f'https://threatbook.io/domain/{DOMAIN}'
            else:
                executed = False
                print('\t- ASN number:', response['data']['asn']['number'],
                    '\n\t- ASN rank:', response['data']['asn']['rank'],
                    '\n\t- Judgment:', response['data']['summary']['judgments'],
                    '\n\t- Is whitelisted:', response['data']['summary']['whitelist'],
                    f'\n\t- Link: https://threatbook.io/ip/{DOMAIN_NAME_TO_IP}',
                    '\n\t- Top 10 ports:')
                
                if isinstance(response['data']['ports'], list):
                    max_ports = 10
                    ports_displayed = 0
                    for port in response['data']['ports']:
                        if ports_displayed < max_ports:
                            port_str = ', '.join([f"{key}: {value}" for key, value in port.items()])
                            print(f'\t\t- {port_str}')
                            ports_displayed += 1
                        else:
                            break
                tb_link = f'https://threatbook.io/ip/{DOMAIN_NAME_TO_IP}'
            
            if response['data']['summary']['judgments']:
                THREATBOOK = [count+1, str(response['data']['summary']['judgments']), response['data']['ports'], tb_link]
            else:
                THREATBOOK = [count, str(response['data']['summary']['judgments']), response['data']['ports'], tb_link]
        
        except Exception as err:
            print('Threat Book error: ', err)
            THREATBOOK = [0, 0, 0]
    

    @staticmethod
    def threatFox():
        """_summary_
        ThreatFox is a free platform from abuse.ch with the goal of sharing indicators of compromise (IOCs) associated with malware with the infosec community, 
        AV vendors and threat intelligence providers.
        """
        try:
            global THREATFOX
            CHAR = string.ascii_lowercase

            connect = urllib3.HTTPSConnectionPool('threatfox-api.abuse.ch', port=443, maxsize=50)
            count = 0

            if any(char in DOMAIN for char in CHAR):
                ioc = DOMAIN
            else:
                ioc = DOMAIN_NAME_TO_IP

            data = {'query': 'search_ioc', 'search_term': ioc}
            data_json = json.dumps(data)
            request = connect.request("POST", "/api/v1", body=data_json)
            response = request.data.decode("utf-8", "ignore")
            response_dict = json.loads(response)
            status = response_dict.get('query_status')

            if 'no_result' in status:
                print('[+] Not found on ThreatFox')
                count = count
                THREATFOX = [0, 0]
            else:
                print(Color.ORANGE + '[!] Reported on ThreatFox' + Color.END)
                keys = response_dict['data'][0]
                for key, value in keys.items():
                    print(f'\t- {key.capitalize()}: {value}')
                count += 1

                THREATFOX = [count, response_dict['data'][0]['malware_malpedia']]
        
        except Exception as err:
            print('Threat Fox error', err)
            THREATFOX = [0, 0]

    
    @staticmethod
    def greyNoise():
        """_summary_
        Check Greynoise and return the responses in a dedicated file in the reports directory.
        """
        try:
            global GREYNOISE
            
            config_file = Config_file(KEY_FILE)
            response = config_file.getGreyNoise(DOMAIN_NAME_TO_IP)
            message = "IP not observed scanning the internet or contained in RIOT data set."
            count = 0
            riot = False  
            
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
            GREYNOISE = [0, 0]
            

    @staticmethod
    def urlScan():
        """_summary_
        Check URL Scan and return the responses in a dedicated file in the reports directory.
        Needs improvement
        """
        try:
            global URLSCAN
            URL_SCAN_REPORT = f'/home/{USERNAME}/Documents/url_scan_report.json'
            
            config_file = Config_file(KEY_FILE)
            config_file.getURLScan(DOMAIN_NAME_TO_IP)
            count = 0

            if os.path.exists(URL_SCAN_REPORT):
                with open(URL_SCAN_REPORT, 'r') as url_scan_report:
                    data = json.load(url_scan_report)
                    if 'message' in data and data['message'] == 'Scan is not finished yet':
                        print(Color.ORANGE + '[!] Scan is not finished yet' + Color.END)
                        URLSCAN = count
                        os.system(f'rm -rf {URL_SCAN_REPORT}')
                        return
                        
                    elif 'data' in data and 'requests' in data['data']:
                        requests_data = data['data']['requests']
                        if requests_data:
                            key = 0  # Use index 0 to access the first (and only) entry
                            print('[+] Header:')
                            if 'response' in requests_data[key] and 'failed' in requests_data[key]['response']:
                                if requests_data[key]['response']['failed']:
                                    failed_keys = requests_data[key]['response']['failed']
                                    for failed_key, failed_value in failed_keys.items():
                                        print(f'\t- {failed_key}: {failed_value}')
                                    print(Color.RED + '[!] Response failed' + Color.END)
                                    count = count
                            else:
                                headers = requests_data[key]['response']['response']['headers']
                                for header, value in headers.items():  # Loop in Headers
                                    print(f'\t- {header}: {value}')
                                print('[+] Response:',
                                    '\n\t- RemotePort:', requests_data[key]['response']['response']['remotePort'],
                                    '\n\t- Protocol:', requests_data[key]['response']['response']['protocol'])
                        else:
                            print('[!] No data in requests')
                    else:
                        print('[!] No key "data" or "requests"')

                    print('[+] Cookies and links found:')
                    if 'data' in data:
                        if 'links' in data['data']:
                            print('\t- Links:')
                            for link in data['data']['links']:
                                for key, value in link.items():
                                    print(f'\t\t- {key}: {value}')
                        else:
                            print('[!] No links')
                            
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
                            print('[!] No cookies')
                    else:
                        print('[!] No data')

                    print('[+] Domain Infos:')
                    if 'lists' in data:
                        for key, value in data['lists'].items():
                            if key != 'certificates':
                                print('\t- {}: {}'.format(key.capitalize(), ', '.join(map(str, value))))
                    else:
                        print('[!] No lists')

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
                        print('[!] No certificates in lists')
                    
                    if 'verdicts' in data:
                        print('[+] URL Scan Verdict: ')
                        verdicts = data['verdicts']['urlscan']
                        for key in ['hasVerdicts', 'malicious']:
                            if key in verdicts:
                                print(f'\t- {key.capitalize()}: {verdicts[key]}')

                        if data['verdicts']['urlscan']['malicious'] == True:
                            count += 1

                url_scan_report.close()
                os.system(f'rm -rf {URL_SCAN_REPORT}')

            else:
                print(f'[!] {URL_SCAN_REPORT} does not exist')

            URLSCAN = count

        except Exception as err:
            print('URL Scan error: ', err)
            URLSCAN = 0
    

    @staticmethod
    def checkPhish():
        """_summary_
        Check Phish scan suspicious URLs and monitor for typosquats and lookalikes variants of a domain
        The os.popen() function executes a shell command specified as a string and returns a file object that can be used to read or write data in this process
        json.loads() is used to load a JSON string, while json.load() is used to load a JSON file
        """
        try:
            global CHECKPHISH_COUNT
            CHAR = string.ascii_lowercase

            config_file = Config_file(KEY_FILE)
            key = config_file.getCheckPhish()
            url_scan = "https://developers.bolster.ai/api/neo/scan"
            url_response = "https://developers.bolster.ai/api/neo/scan/status"
            count = 0
            executed = False

            if any(char in DOMAIN for char in CHAR):
                executed = True
                url = DOMAIN
            else:
                url = DOMAIN_NAME_TO_IP

            scan = os.popen(f"curl -X POST --header 'Content-Type: application/json' -d '{{\"apiKey\": \"{key}\", \"urlInfo\": {{\"url\": \"{url}\"}}, \"scanType\": \"full\"}}' {url_scan} 2> /dev/null")  
            
            # Variables after the first curl command
            response_json = json.load(scan)
            job_id = response_json['jobID']

            if job_id == 'none':
                message = response_json['errorMessage']
                print(Color.RED + '[!]', message + Color.END)
                CHECKPHISH_COUNT = [0, 0, 0]
            else:
                data = {"apiKey": key, "jobID": job_id, "insights": True}
                json_data = json.dumps(data)
                print('[+] Data:')
                while True:
                    response_scan = os.popen(f"curl -X POST --header 'Content-Type: application/json' -d '{json_data}' {url_response} 2> /dev/null").read()
                    response_scan_json = json.loads(response_scan)
                    status = response_scan_json['status']

                    if status == 'DONE':
                        json.loads(response_scan)
                        print("\t- Disposition:", response_scan_json["disposition"],
                            "\n\t- Brand:", response_scan_json["brand"],
                            "\n\t- Insights:", response_scan_json["insights"],
                            "\n\t- Resolved:", response_scan_json["resolved"],
                            "\n\t- Error:", response_scan_json["error"])
                        break
                    time.sleep(5)

                if response_scan_json['disposition'] == 'clean':
                    count = count
                else:
                    print('[!] Not clean on Check Phish:', response_scan_json["disposition"])
                    count += 1

                CHECKPHISH_COUNT = [count, response_scan_json['insights'], response_scan_json['disposition']]

        except Exception as err:
            print('Check Phish error', err)
            CHECKPHISH_COUNT = [0, 0, 0]


    # Checking public Blacklists
    @staticmethod
    def duggyTuxy():
        """_summary_
        These are the IP addresses of the most active Botnets/Zombies/Scanners in European Cyber Space
        """
        try:
            global DUGGY_COUNT

            config_url = Config_urls()
            url = config_url.getDuggyTuxy()
            
            page = urllib.request.urlopen(url,timeout=5).read()
            soup = bs(page, 'html.parser')  # or 'lxml'
            text = soup.get_text()
            count = 0

            if DOMAIN_NAME_TO_IP in str(text):
                count += 1
                print('[!]', DOMAIN_NAME_TO_IP, 'Found in the list. Possible active Botnets/Zombies/Scanners in European Cyber Space')
            else:
                count == count
                print('[+]', DOMAIN_NAME_TO_IP, "Not found in the Duggy Tuxy's list")
            
            DUGGY_COUNT = count

        except Exception as err:
            print('Duggy Tuxy error: ', err)
            DUGGY_COUNT = 0


    @staticmethod
    def ipsum():
        """_summary_
        IPsum is a threat intelligence feed based on 30+ different publicly available lists of suspicious and/or malicious IP addresses like:
            abuseipdb, alienvault, atmos, badips, bitcoinnodes, blocklist, botscout, cobaltstrike, malwaredomains, proxylists, 
            ransomwaretrackerurl, talosintelligence, torproject, etc.
        """
        try:
            global IPSUM_COUNT

            config_url = Config_urls()
            url = config_url.getIpsum()
        
            page = urllib.request.urlopen(url,timeout=5).read()
            soup = bs(page, 'html.parser')
            text = soup.get_text()
            count = 0
            blacklists_count = 0

            if DOMAIN_NAME_TO_IP in str(text):
                count += 1
                print('[!]', DOMAIN_NAME_TO_IP, 'Found in the list.')
                os.system(f'curl --compressed {url} 2>/dev/null | grep -v "#" | grep {DOMAIN_NAME_TO_IP} | cut -f 2 > IPSum.txt')

                with open('IPSum.txt', 'r') as blacklisted:
                    blacklists_count = blacklisted.read()
                    if int(blacklists_count) != 0:
                        print(f'[!] {DOMAIN_NAME_TO_IP} founded in:', int(blacklists_count),'blacklists')
                        blacklisted.close()
                        os.system('rm -rf IPSum.txt')

            else:
                count == count
                blacklists_count = blacklists_count
                print('[+]', DOMAIN_NAME_TO_IP, "Not found in the IPsum's blacklists")
            
            IPSUM_COUNT = [count, int(blacklists_count)]

        except Exception as err:
            print('IPSum error: ', err)
            IPSUM_COUNT [0, 0]
    

    @staticmethod
    def redflagDomains():
        """_summary_
        Redflag Domains are lists of very recently registered probably malicious domain names in french TLDs
        """
        try:
            global REDFLAGDOMAINS_COUNT
            CHAR = string.ascii_lowercase

            config_url = Config_urls()
            url = config_url.getRedflagDomains()
            count = 0
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
            print('Red Flag error: ', err)
            REDFLAGDOMAINS_COUNT = 0


    @staticmethod
    def c2Tracker():
        """_summary_
        IP address or domain present in internal C2 Tracker
        Domains often return the error "[Errno -3] Temporary failure in name resolution".
        """
        try:
            global C2_COUNT
            CHAR = string.ascii_lowercase

            tracker_file = f"/home/{USERNAME}/Documents/dump.csv"
            count = 0
            results = []

            if any(char in DOMAIN for char in CHAR):
                ioc = DOMAIN
            else:
                ioc = DOMAIN_NAME_TO_IP

            os.system(f'curl https://tracker.viriback.com/dump.php -o /home/{USERNAME}/Documents/dump.csv 2>/dev/null')

            with open(tracker_file, newline='') as c2_file:
                    reader = csv.DictReader(c2_file)
                    for row in reader:
                        if row['URL'] == DOMAIN or row['URL'] == DOMAIN_NAME_TO_IP or row['IP'] == DOMAIN_NAME_TO_IP:  
                            results.append(row)
    
                    if results:
                        for result in results:
                            print(Color.RED + '[!]', ioc, 'found in C2 Tracker list' + Color.ORANGE)
                            print('\t- Family :', result['Family'],
                                    '\n\t- URL :', result['URL'],
                                    '\n\t- IP :', result['IP'],
                                    '\n\t- First Seen :', result['FirstSeen'])
                            count += 1
                            C2_COUNT = [count, result['Family']]
                        
                    else:
                        print('[+]', ioc , "Not found in C2 Tracker list")
                        count = count
                        C2_COUNT = [0, 0]
                        
                    c2_file.close()
    
            os.system(f'rm -rf /home/{USERNAME}/Documents/dump.csv')
        
        except Exception as err:
            print('C2 tracker error:', err)
            C2_COUNT = [0, 0]


    # Checking internal IOCs
    @staticmethod
    def tlpAmberCheck(ioc, tlp_url):
        """_summary_
        IP address or domain present in internal IOCs
        """
        try:
            tlp_file_name = f"/home/{USERNAME}/Downloads/tlp.csv"  # Use for tests
            # config_url = Config_urls()
            # url = config_url.getTLP()

            # os.system(f'wget {url} 2>/dev/null')
            with open(tlp_file_name, newline='') as tlp_file:
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
            print('Check TLP error: ', err)


    @staticmethod
    def tlpAmber():
        """_summary_
        IP address or domain present in internal IOCs, Use tlpAmberCheck()
        """
        try:
            global TLP_COUNT
            CHAR = string.ascii_lowercase

            csv_file_path = f"/home/{USERNAME}/Downloads/tlp.csv"
            count = 0

            if any(char in DOMAIN for char in CHAR):
                ioc = DOMAIN
            else:
                ioc = DOMAIN_NAME_TO_IP

            result = Functions.tlpAmberCheck(ioc, csv_file_path)

            if result:
                print(Color.RED + '[!] Reported in internal IOCs' + Color.END)
                print('\t- IOC :', result['domain'],
                            '\n\t- First seen :', result['entry_date'],
                            '\n\t- Expired :', result['expired'],
                            '\n\t- Category :', result['category'])
                count += 1

            else:
                print('[+]', ioc, "not found in intenal IOC")
                count = count

            TLP_COUNT = count

        except Exception as err:
            print('TLP Amber error: ', err)
            TLP_COUNT = 0


class Count:
    """_summary_
    Sends constants to summary class
    """
    @staticmethod
    def count():
        try:
            return [WHOIS, VT_COUNT, DUGGY_COUNT, IPSUM_COUNT, CRIMINALIP_COUNTS, ABUSEIPDB_CONFIDENCE, OTX_COUNT, THREATBOOK, 
                    GREYNOISE, REDFLAGDOMAINS_COUNT, TLP_COUNT, WHOIS_IPINFO, URLSCAN, CHECKPHISH_COUNT, C2_COUNT, THREATFOX]
        
        except Exception as err:
            print('Counting error: ', err)
            exit()