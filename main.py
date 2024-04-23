# coding: utf-8
"""_summary_
V1, July 23, based on the example of Sooty
V2, April 24
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
        Functions.ip2Location()

        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Check ip info" + Color.END)
        Functions.ipInfo()

        # print("--------------------------------------------------------------------------------------------------------")
        # print(Color.BLUE + "[+] Netlas" + Color.END)
        # Functions.netlas()

            
        print(Color.ORANGE + "[+] Checking public CTI sources" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Virus Total" + Color.END)
        Functions.virusTotal()

        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Criminal IP" + Color.END)
        Functions.criminalIP()
        
        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Abuse IP DB" + Color.END)
        Functions.abuseIPDB()
        
        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Alien Vault / OTX" + Color.END)
        Functions.alienVault()

        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Treatbook" + Color.END)
        print(Color.ORANGE + "[!] Treatbook with the free API = 50 requests per day" + Color.END)
        Functions.threatBook()

        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Greynoise" + Color.END)
        print(Color.ORANGE + "[!] Greynoise with the free API = 50 requests per day" + Color.END)
        Functions.greyNoise()

        
        print(Color.ORANGE + "[+] Checking public Blacklists" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Duggy Tuxy's list" + Color.END)
        Functions.duggyTuxy()

        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] IPsum's blacklists" + Color.END)
        Functions.ipsum()

        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] RedFlag domains's blacklists" + Color.END)
        Functions.redflagDomains()


        print(Color.ORANGE + "[+] Checking intern IOC lists" + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        print(Color.BLUE + "[+] Limited disclosure, restricted to participants' organization and clients" + Color.END)
        Functions.tlpAmber()


        print(Color.ORANGE + "[+] Report stored, here is the summary: " + Color.END)
        print("--------------------------------------------------------------------------------------------------------")
        Summary.summary()
        print("--------------------------------------------------------------------------------------------------------")
    
    except Exception as err:
        print(err)
    except KeyboardInterrupt:
        print(Color.ORANGE + '[!] Exit' + Color.END)