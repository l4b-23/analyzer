# Readme


> ## **Discovers an IP and/or domain from the following web applications and returns a reputation score.**
> ### **V1, Started in July 23 / based on the example of [Sooty](https://github.com/TheresAFewConors/Sooty/blob/master/Sooty.py)**
> ### **Here is the V2, Started in April 24**


## In run:
- [ip 2 location](https://www.ip2location.io/)
- [ip Info](https://ipinfo.io/)
- [Virus Total](https://www.virustotal.com/gui/home/search)
- [Criminal IP](https://www.criminalip.io/en)
- [Abuse IP DB](https://www.abuseipdb.com/)
- [OTX / AlienVault](https://otx.alienvault.com/)
- [ThreatBook](https://threatbook.io/)
- [GreyNoise](https://www.greynoise.io/)
- [URL Scan](https://urlscan.io/)
- [Check Phish](https://checkphish.bolster.ai/)
- [Duggy Tuxy blacklist](https://github.com/duggytuxy/malicious_ip_addresses)
- [IPsum blacklists](https://github.com/stamparm/ipsum)
- [Redflag Domains](https://red.flag.domains/)
- [C2 Tracker](https://tracker.viriback.com/)
- **checks internal IOC in a csv file**

### CSV file format tested
```csv
domain,entry date,expired,category
146.196.38.50,02/04/2024,TRUE,malicious
216.151.191.12,05/04/2024,FALSE,unknown
lemespaceclent.fr,08/04/2024,FALSE,benign
```

### URL Scan
> ### **[!] The scan performed here is a public scan, please pay attention to the private content**


## Setup
### Requirements:
- beautifulsoup4, requests, OTXv2, PyPDF2, ipinfo, netlas:
```bash
pip3 install -r requirements.txt
```

### Adjust utils.py:
- Create the key_file.json file. 
- Set the correct path for the key_file.json file in the `KEY_FILE` constant of `utils.py`.
    - Default: `/home/{USERNAME}/keys_file.json`

```json
{
    "api": {
        "ip 2 location": "your API key",
        "ip info": "your API key",
        "virus total": "your API key", 
        "criminal ip": "your API key",
        "abuse ip db": "your API key",
        "alien vault": "your API key",
        "threatbook": "your API key",
		"greynoise": "your API key",
		"url scan": "your API key",
		"check phish": "your API key"
    }
}     
```

### Create an alias:
- edit your `.bashrc` or `.zshrc`
```bash
alias analyzer='python3 <absolute path of main.py directory>'
source .zshrc
```

### Run analyzer:
```bash
# You can launch "analyzer" from anywhere, but the "analyzer_reports" directory will be created in it.
cd $HOME/Documents
analyzer
```



## Output example
> ### **Report generated and stored in a text file**

```
 ---------------------------------------------------------------------------------------------------------------
 Report for: 43.128.141.106, associated with IP address 43.128.141.106
 ---------------------------------------------------------------------------------------------------------------
[+] WHOIS Report:
	- Organisation/ASN: AS132203 Tencent Building, Kejizhongyi Avenue
	- Country: Korea (the Republic of)
	- Country code: KR
	- Continent: Asia
	- Region: Seoul
 ---------------------------------------------------------------------------------------------------------------
[+] General note: 8.67
	[!] Critical IP
 ---------------------------------------------------------------------------------------------------------------
[+] Internal IOCs status
	[+] Not reported in internal IOCs
 ---------------------------------------------------------------------------------------------------------------
[+] Present in RIOT DB (Greynoise): False
	RIOT informs about IPs used by business services who certainly won't attack you.
 ---------------------------------------------------------------------------------------------------------------
[+] Additional infos
[!] Detected on Virus Total
	- Count of detections: 15
 --------------------------------------------------------------------------------------------------------
[!] Reported malicious on Criminal IP
	- Count of opened ports: 1
 --------------------------------------------------------------------------------------------------------
[!] Reported on Abuse IP DB
	- Count of reports: 3165
 --------------------------------------------------------------------------------------------------------
[!] Count of pulses reported on OTX: 23
 --------------------------------------------------------------------------------------------------------
[!] Judgment reported on Threatbook: ['IDC', 'Scanner', 'Zombie', 'Spam']
	- Ports (ThreatBook):
		- {'port': 123, 'module': 'ntp', 'product': 'NTP', 'version': 'v4', 'detail': ''}
		- {'port': 22, 'module': 'ssh', 'product': 'OpenSSH', 'version': '7.4', 'detail': ''}
		- {'port': 8990, 'module': 'socks5', 'product': '', 'version': '', 'detail': ''}
		- {'port': 49669, 'module': 'msrpc', 'product': '', 'version': '', 'detail': ''}
		- {'port': 49665, 'module': 'msrpc', 'product': '', 'version': '', 'detail': ''}
		- {'port': 49667, 'module': 'msrpc', 'product': '', 'version': '', 'detail': ''}
		- {'port': 49664, 'module': 'msrpc', 'product': '', 'version': '', 'detail': ''}
		- {'port': 3389, 'module': 'ms-wbt-server', 'product': 'Microsoft Terminal Services', 'version': '', 'detail': ''}
		- {'port': 139, 'module': 'netbios-ssn', 'product': '', 'version': '', 'detail': ''}
		- {'port': 5985, 'module': 'http', 'product': 'Microsoft-HTTPAPI/2.0', 'version': '', 'detail': ''}
		- {'port': 47001, 'module': 'http', 'product': 'Microsoft-HTTPAPI/2.0', 'version': '', 'detail': ''}
		- {'port': 135, 'module': 'msrpc', 'product': '', 'version': '', 'detail': ''}
		- {'port': 445, 'module': 'unknown', 'product': '', 'version': '', 'detail': ''}
		- {'port': 53, 'module': 'domain', 'product': '', 'version': '', 'detail': ''}
		- {'port': 443, 'module': 'https', 'product': '', 'version': '', 'detail': ''}
 --------------------------------------------------------------------------------------------------------
[!] Reported malicious on Greynoise
 --------------------------------------------------------------------------------------------------------
[!] Found in Duggy Tuxy blacklist
 --------------------------------------------------------------------------------------------------------
[!] Found in IPsum's blacklists
 --------------------------------------------------------------------------------------------------------
[+] Not in Redflag Domains
 ---------------------------------------------------------------------------------------------------------------
[+] Links:
	- Virus Total: https://www.virustotal.com/gui/url/01f1047fec72906e4f24bc32a2c039d74cf8c41dd49955337d0039fd7bfa8ea2/detection/u-01f1047fec72906e4f24bc32a2c039d74cf8c41dd49955337d0039fd7bfa8ea2-1712263164
	- TreatBook: https://threatbook.io/ip/43.128.141.106
```

## Coming soon:
