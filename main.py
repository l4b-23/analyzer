# coding: utf-8
"""_summary_
V1, July 23, based on the example of Sooty
main
"""


from analyzer import *
from summary import *


if __name__ == '__main__':
    """_summary_
    """
    try:
        print(Color.ORANGE + "[+] Check API config file" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Api.apiConfig()
        
        print(Color.ORANGE + "[+] Create a directory to store reports" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Directory.getReportDierectory()
        print("[+] Directory create, report link is stored in: " + str(os.getcwd()) + '/analyzer_reports')
        
        print(Color.ORANGE + "[+] Checking public Whois sources" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Check ip 2 Location" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.ip2Location()
            
        print(Color.ORANGE + "[+] Checking public CTI sources" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Virus Total" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.virusTotal()

        print(Color.BLUE + "[+] Criminal IP" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.criminalIP()
        
        print(Color.BLUE + "[+] Abuse IP DB" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.abuseIPDB()
        
        print(Color.BLUE + "[+] Alien Vault / OTX" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.alienVault()
        
        print(Color.ORANGE + "[+] Checking public Blacklists" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Duggy Tuxy's list" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.duggyTuxy()

        print(Color.BLUE + "[+] IPsum's blacklists" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.ipsum()

        print(Color.ORANGE + "[+] Report stored, here is the summary: " + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Summary.summary()
        print("--------------------------------------------------------------------------------------------------------")
    
    except Exception as err:
        print(err)
    except KeyboardInterrupt:
        print(Color.ORANGE + '[!] Exit' + Color.END)