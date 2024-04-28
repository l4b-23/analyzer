# Readme


> ## **Discovers an IP and/or domain from the following web applications and returns a reputation score.**
> ### **V1, Started in July 23 / based on the example of [Sooty](https://github.com/TheresAFewConors/Sooty/blob/master/Sooty.py)**
> ### **Here is the V2, Started in April 24**


## In run:
- [IP 2 location](https://www.ip2location.io/)
- [IP Info](https://ipinfo.io/)
- [Virus Total](https://www.virustotal.com/gui/home/search)
- [Criminal IP](https://www.criminalip.io/en)
- [Abuse IP DB](https://www.abuseipdb.com/)
- [OTX / AlienVault](https://otx.alienvault.com/)
- [ThreatBook](https://threatbook.io/)
- [ThreatFox](https://threatfox.abuse.ch/)
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
- beautifulsoup4, requests, OTXv2, PyPDF2, ipinfo, netlas, urllib3:
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
-----------------------------------------------------------------------------------------------------------------
 Report for: lemespaceclent.fr, associated with IP address 62.4.16.153
 ----------------------------------------------------------------------------------------------------------------
[+] WHOIS Report:
	- Organisation/ASN: AS12876 SCALEWAY S.A.S.
	- Country: France
	- Country code: FR
	- Continent: Europe
	- Region: Île-de-France
 ----------------------------------------------------------------------------------------------------------------
[+] General note: 6.67
	[!] High IP
 ----------------------------------------------------------------------------------------------------------------
[+] Internal IOCs status
	[!] Reported in internal IOCs
 ----------------------------------------------------------------------------------------------------------------
[+] Present in RIOT DB (Greynoise): False
	RIOT informs about IPs used by business services who certainly won't attack you.
 ----------------------------------------------------------------------------------------------------------------
[+] Additional infos
[+] Clean on Virus Total
 --------------------------------------------------------------------------------------------------------
[!] Reported malicious on Criminal IP
	- Count of opened ports: 10
 --------------------------------------------------------------------------------------------------------
[+] Not found on Abuse IP DB
 --------------------------------------------------------------------------------------------------------
[!] Count of pulses reported on OTX: 1
 --------------------------------------------------------------------------------------------------------
[+] No judgment reported on Threatbook
 ---------------------------------------------------------------------
[!] Top 10 ports listed on Threatbook, see link below for full list
	- port: 993, module: imaps, product: Dovecot imapd, version: , detail: 
	- port: 443, module: https, product: nginx, version: , detail: 
	- port: 25, module: smtp, product: Exim smtpd, version: 4.97.1, detail: 
	- port: 2525, module: smtp, product: Exim smtpd, version: 4.97.1, detail: 
	- port: 80, module: http, product: nginx, version: , detail: 
	- port: 53, module: domain, product: , version: , detail: 
	- port: 22, module: ssh, product: OpenSSH, version: 7.4, detail: 
	- port: 21, module: ftp, product: vsftpd, version: 3.0.2, detail: 
	- port: 3306, module: mysql, product: MySQL, version: 5.5.68, detail: 
	- port: 995, module: pop3s, product: Dovecot pop3d, version: , detail: 
 --------------------------------------------------------------------------------------------------------
[+] Not reported on ThreatFox
 --------------------------------------------------------------------------------------------------------
[+] Not reporteded by Greynoise
 --------------------------------------------------------------------------------------------------------
[+] Not reporteded as malicious by URL Scan report
 --------------------------------------------------------------------------------------------------------
[+] Clean on Check Phish or Scan was unsuccessful
 ---------------------------------------------------------------------------------------------------------------
 [+] Checking Blacklists
[+] Not in the Duggy Tuxy blacklist.
 --------------------------------------------------------------------------------------------------------
[+] Not in IPsum's blacklists
 --------------------------------------------------------------------------------------------------------
[!] Found in Redflag Domains
 --------------------------------------------------------------------------------------------------------
[+] Not in C2 Tracker
 ----------------------------------------------------------------------------------------------------------------
[+] Links:
	- Virus Total: https://www.virustotal.com/gui/url/2df7158270c72edab5f36cf08d648d3459e995e9d419367d8b1b6492b3295ef7/detection/u-2df7158270c72edab5f36cf08d648d3459e995e9d419367d8b1b6492b3295ef7-1713807192
	- TreatBook: https://threatbook.io/domain/lemespaceclent.fr
	- ThreatFox (To Malpedia): 0
	- Check Phisk: https://checkphish.ai/insights/url/1714203210337/2df7158270c72edab5f36cf08d648d3459e995e9d419367d8b1b6492b3295ef7
```

## Coming soon:
- [IP quality score](https://www.ipqualityscore.com/)
- [ShadowWhisperer / BlockLists](https://github.com/ShadowWhisperer/BlockLists)
- [Firehol / blocklist-ipsets](https://github.com/firehol/blocklist-ipsets?tab=readme-ov-file)
- [Botvrij](https://botvrij.eu/)
- Private scans performed on URLSCAN