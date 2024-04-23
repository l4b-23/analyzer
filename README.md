# Readme


> ## **Discovers an IP and/or domain from the following web applications and returns a reputation score.**
> #### **V1, Started in July 23 / based on the example of [Sooty](https://github.com/TheresAFewConors/Sooty/blob/master/Sooty.py)**
> #### **Here is the V2, Started in April 24**


## In run:
- [ip 2 location](https://www.ip2location.io/)
- [ip Info](https://ipinfo.io/)
- [Virus Total](https://www.virustotal.com/gui/home/search)
- [Criminal IP](https://www.criminalip.io/en)
- [Abuse IP DB](https://www.abuseipdb.com/)
- [OTX / AlienVault](https://otx.alienvault.com/)
- [ThreatBook](https://threatbook.io/)
- [GreyNoise](https://www.greynoise.io/)
- [Duggy Tuxy blacklist](https://github.com/duggytuxy/malicious_ip_addresses)
- [IPsum blacklists](https://github.com/stamparm/ipsum)
- [Redflag Domains](https://red.flag.domains/)
- **checks internal IOC in a csv file**

### CSV file format tested
```csv
domain,entry date,expired,category
146.196.38.50,02/04/2024,TRUE,malicious
216.151.191.12,05/04/2024,FALSE,unknown
lemespaceclent.fr,08/04/2024,FALSE,benign
```


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
        "greynoise": "your API key"
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

## Coming soon: