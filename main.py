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

        print(Color.ORANGE + "[+] Check whether the input is a domain or an IP address" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Check_INPUT.checkInput()
        print("--------------------------------------------------------------------------------------------------------")
        
        print(Color.BLUE + "[+] Check Whois.io" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.whois()
            
        # print(Color.GREEN + "[+] Checking Blacklists" + Color.END)
        # print("--------------------------------------------------------------------------------------------------------")
        # print(Color.BLUE + "[+] Duggy Tuxy's list" + Color.END)
        # print("--------------------------------------------------------------------------------------------------------")
        # Functions.scrapDuggyTuxyRepo()

        # print(Color.BLUE + "[+] IPsum's blacklists" + Color.END)
        # print("--------------------------------------------------------------------------------------------------------")
        # Functions.ipsum()

        print(Color.ORANGE + "[+] Checking CTI sources" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Virus Total" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Functions.virusTotal()

        # print(Color.BLUE + "[+] Criminal IP" + Color.END)
        # print("--------------------------------------------------------------------------------------------------------")
        # Functions.criminalIP()
        
        # print(Color.BLUE + "[+] Abuse IP DB" + Color.END)
        # print("--------------------------------------------------------------------------------------------------------")
        # Functions.abuseIPDB()
        
        # print(Color.BLUE + "[+] Alien Vault" + Color.END)
        # print("--------------------------------------------------------------------------------------------------------")
        # Functions.otx()
        
        print(Color.GREEN + "[+] Report stored, here is the summary: " + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Summary.summary()
        print("--------------------------------------------------------------------------------------------------------")
    
    except Exception as err:
        print(err)
    except KeyboardInterrupt:
        print(Color.ORANGE + '[!] Exit' + Color.END)