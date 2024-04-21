# Readme


> ## **Discovers an IP and/or domain from the following web applications and returns a reputation score.**
> #### **V1, Started in July 23 / based on the example of [Sooty](https://github.com/TheresAFewConors/Sooty/blob/master/Sooty.py)**


## In run:
- [ip2location](https://www.ip2location.io/)
- [VirusTotal](https://www.virustotal.com/gui/home/search)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [OTX/AlienVault](https://otx.alienvault.com/)
- [CriminalIP](https://www.criminalip.io/en)
- [Duggy Tuxy blacklist](https://github.com/duggytuxy/malicious_ip_addresses)
- [IPsum](https://github.com/stamparm/ipsum)


## Setup
### Requirements:
- OTXv2 and PyPDF2:
```bash
pip3 install OTXv2 && pip3 install PyPDF2
```

### Adjust utils.py:
- Create the key_file.json file. 
- Set the correct path for the key_file.json file in the `KEY_FILE` constant of `utils.py`.
    - Default: `/home/keys_file.json`

```json
{
    "api": {
        "ip2location": "your API key",
        "virus total": "your API key", 
        "abuseipdb": "your API key",
        "otx": "your API key",
        "criminal ip": "your API key"
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
cd $HOME/Documents
analyzer
```

## Coming soon: