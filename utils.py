# coding: utf-8
"""_summary_
V1, July 23, based on the example of Sooty
work utilities
"""

import time
import socket
import os
from os.path import exists
import re
import string
import requests
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
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
    #print(f"The value of the $USER environment variable is : {USERNAME}")
    KEY_FILE = f"/home/{USERNAME}/keys_file.json"
    CONFIG_FILE = open(KEY_FILE, "r")
    TODAY = time.strftime("%m-%d-%Y")
    INPUT = input("Enter IP Address or Domain name: ").split()
    DOMAIN = str(INPUT[0])
    DOMAIN_NAME_TO_IP = socket.gethostbyname(DOMAIN)
    CTI_SOURCES = ["ip 2 location",
                   "virus total",
                   "criminal ip",
                   "abuse ip db",
                   "alien vault",
                   ]
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
        """
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
        """
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
                            DOMAIN_NAME_TO_IP = DOMAIN_NAME_TO_IP
                            return DOMAIN_NAME_TO_IP
                        else:
                            print("[+] Domain used: " + DOMAIN +" but couldn't be associated with an IP")
                    except Exception :
                            print(Color.RED + "[!] Domain couldn't be associated with an IP" + Color.END)
                            print(Color.RED + "[!] Invalid input: " + INPUT[0] + Color.END)



class Config_file:
    def __init__(self, key_file):
        with open(key_file, "r") as file:
            configFile = json.load(file)
            self.ip2location_key = configFile['api'].get('ip 2 location')
            self.virus_total_key = {'apikey': configFile['api']['virus total'], 'resource': INPUT[0]}
            self.criminal_ip_key = configFile['api'].get('criminal ip')
            self.abuse_ip_db_key = configFile['api'].get('abuse ip db')
            self.alien_vault_key = configFile['api'].get('alien vault')

    def getIP2Location(self, domain_name_to_ip):
        url = (f"https://api.ip2location.io/?key={self.ip2location_key}&ip={domain_name_to_ip}&format=json")
        response = requests.request("GET", url)
        return response.json()
    

    def virusTotalReport(self, domain_name_to_ip):
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        key = {'resource': domain_name_to_ip}  # Initialise the key with only the resource parameter
        
        if self.virus_total_key:
            key.update(self.virus_total_key)  # Update the key with the other parameters if the API key for VirusTotal is defined
        else:
            print(Color.RED + "[!] Error: VirusTotal API key not found" + Color.END)
            return None

        response = requests.get(url, params=key)
        return response.json()
