# coding: utf-8
"""_summary_
V1, July 23, based on the example of Sooty
V2, April 24
work utilities
"""

import time
import socket
import os
from os.path import exists
import re
import string
import requests
import json
import PyPDF2


# Colors:
class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    ORANGE = '\033[93m'
    BLUE = "\033[94m"
    END = '\033[0m'


# Constants:
try:
    USERNAME = os.getenv("USER")
    KEY_FILE = f"/home/{USERNAME}/keys_file.json"
    CONFIG_FILE = open(KEY_FILE, "r")
    TODAY = time.strftime("%m-%d-%Y")
    INPUT = input("Enter IP Address or Domain name: ").split()
    DOMAIN = str(INPUT[0])

except Exception:
    print(Color.RED + "[!] Domain not found" + Color.END)


# Classes:
class Api:
    @staticmethod
    def apiConfig():
        """_summary_
        Check API keys config file
        """
        try:
            with CONFIG_FILE as file:
                configFile = json.load(file)
                if "api" in configFile:
                    keyNames = configFile['api']
                    print("[+] Config file found and there is APIs available for: ")
                    for key,value in keyNames.items():
                        if value not in key:
                            print("\t- " + key)
                CONFIG_FILE.close()
        except FileNotFoundError:
            print(Color.RED + '[!] keys_file.json not found, create it!' + Color.END)


class Directory:
    @staticmethod
    def getReportDierectory():
        """_summary_
        Create a folder in the current directory to store results 
        """
        try:
            if not os.path.exists('analyzer_reports/' + TODAY):
                os.makedirs('analyzer_reports/' + TODAY)
        except Exception:
            print(Color.GREEN + "[+] Existing directory" + Color.END)


class Check_INPUT:
    @staticmethod
    def checkInput():
        """_summary_
        Check whether the input is a domain or an IP address.
        Returns the IP address of the domain or retains the IP address entered in "input".
        """
        global IP
        CHAR = string.ascii_lowercase
        IP_STRUCT = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"

        for match in re.findall(IP_STRUCT,INPUT[0]):
            print("[+] IP used: " + INPUT[0])
            IP = INPUT[0]
            return IP
        
        else:
            for CHAR in INPUT:
                if CHAR in INPUT:
                    try:
                        global DOMAIN_NAME_TO_IP
                        DOMAIN_NAME_TO_IP = socket.gethostbyname(DOMAIN)
                        print("[+] Domain used: " + DOMAIN)
                        if DOMAIN_NAME_TO_IP:
                            print("[+] IP associated with the domain and used: " + DOMAIN_NAME_TO_IP)
                            # DOMAIN_NAME_TO_IP = DOMAIN_NAME_TO_IP
                            return DOMAIN_NAME_TO_IP
                        else:
                            print("[+] Domain used: " + DOMAIN +" but couldn't be associated with an IP")
                    except Exception :
                            print(Color.RED + "[!] Domain couldn't be associated with an IP" + Color.END)
                            print(Color.RED + "[!] Invalid input: " + INPUT[0] + Color.END)


# API keys builder 
class Config_file:
    def __init__(self, key_file):
        with open(key_file, "r") as file:
            configFile = json.load(file)
            self.ip2location_key = configFile['api'].get('ip 2 location')
            self.ipinfo_key = configFile['api'].get('ip info')
            self.netlas_key = configFile['api'].get('netlas')
            self.virus_total_key = {'apikey': configFile['api']['virus total'], 'resource': DOMAIN}
            self.criminal_ip_key = configFile['api'].get('criminal ip')
            self.abuse_ip_db_key = configFile['api'].get('abuse ip db')
            self.alien_vault_key = configFile['api'].get('alien vault')
            self.threatbook_key = configFile['api'].get('threatbook')
            self.greynoise_key = configFile['api'].get('greynoise')


    def getIP2Location(self, domain_name_to_ip):
        url = (f"https://api.ip2location.io/?key={self.ip2location_key}&ip={domain_name_to_ip}&format=json")
        response = requests.request("GET", url)
        return response.json()
    

    def getIPInfo(self):
        return self.ipinfo_key
    

    # def getNetlas(self, domain_name_to_ip):
    #     url = f"https://app.netlas.io/api/host/{domain_name_to_ip}/?fields=&source_type=include"
    #     headers = {'accept': 'application/json', 'X-API-Key': self.netlas_key}
    #     response = requests.get(url, headers=headers)
    #     return response.json()
    

    def getVirusTotal(self, domain_name_to_ip):
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        key = {'resource': domain_name_to_ip}  # Initialise the key with only the resource parameter
        
        if self.virus_total_key:
            key.update(self.virus_total_key)  # Update the key with the other parameters if the API key for VirusTotal is defined
        else:
            print(Color.RED + "[!] Error: VirusTotal API key not found" + Color.END)
            return None

        response = requests.get(url, params=key)
        return response.json()
    

    def getCtiminalIP(self, domain_name_to_ip):
        url = (f"https://api.criminalip.io/v1/feature/ip/malicious-info?ip={domain_name_to_ip}")
        payload = {}
        key = {'x-api-key': self.criminal_ip_key}  # Utilisez self.criminal_ip_key pour accéder à la clé API
        response = requests.request("GET", url, headers=key, data=payload)
        return response.json()
    

    def getAbuseIPDB(self, domain_name_to_ip):
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {'ipAddress': domain_name_to_ip, 'maxAgeInDays': '90'}
        key = {'Accept': 'applications/json', 'key': self.abuse_ip_db_key}
        response = requests.request(method='GET', url=url, headers=key, params=querystring)
        if response.status_code == 200:
            return response.json()
    

    def getAlienVault(self):
        return self.alien_vault_key
    

    def getThreatBook(self, domain_name_to_ip):
        url = (f"https://api.threatbook.io/v1/community/ip?apikey={self.threatbook_key}&resource={domain_name_to_ip}")
        key = {"accept": "application/json"}
        response = requests.get(url, headers=key)
        return response.json()
    

    def getGreyNoise(self, domain_name_to_ip):
        url = f"https://api.greynoise.io/v3/community/{domain_name_to_ip}"
        key = {"accept": "application/json","key": self.greynoise_key}
        response = requests.get(url, headers=key)
        return response.json()
            

# URLs builder
class Config_urls:
    def __init__(self):
        self.duggy_tuxy_url = "https://raw.githubusercontent.com/duggytuxy/malicious_ip_addresses/main/botnets_zombies_scanner_spam_ips.txt"
        self.ipsum_url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
        self.redflagDomains_url = "https://dl.red.flag.domains/red.flag.domains.txt"
        self.tlp_url = ""

    def getDuggyTuxy(self):
        return self.duggy_tuxy_url
    

    def getIpsum(self):
        return self.ipsum_url
    

    def getRedflagDomains(self):
        return self.redflagDomains_url
    

    def getTLP(self):
        return self.tlp_url
