# coding: utf-8
"""_summary_
V1, July 23, based on the example of Sooty
V2, April 24
Summary function
"""


from analyzer import *
from utils import *


class Summary:
    """_summary_
    Calculates scores and returns results
    """
    @staticmethod
    def summary():
        try:
            country = Count.count()[0][0]
            prx = Count.count()[0][1]
            vt = Count.count()[1][0]
            vtTotalScanners = Count.count()[1][1]
            ciCount = Count.count()[4][0]
            ciPortCount = Count.count()[4][1]
            ciVulCount = Count.count()[4][2]
            ciCatCount = Count.count()[4][3]
            abReports = Count.count()[5][0]
            abCnfidence = Count.count()[5][1]
            otx = Count.count()[6]
            tb = Count.count()[7][0]
            tbJudgment = Count.count()[7][1]
            gn = Count.count()[8][0]
            gnRiot = Count.count()[8][1]
            dt = Count.count()[2]
            ipsum = Count.count()[3][0]
            ipsumCount = Count.count()[3][1]
            rfd = Count.count()[9]
            tlp = Count.count()[10]
            
            agressivity = 0
            malicious = 0
            reported = 0

            print('[+] Country:',str(country),
                  '\n[+] Categorized as public proxy (IP 2 Location):',str(prx),
                  '\n[+] Present in RIOT DB (Greynoise):',gnRiot,
                  '\n\t[+] RIOT is a new feature that informs users about IPs used by common business services that are almost certainly not attacking you.')
            print("--------------------------------------------------------------------------------------------------------")
            
            if (vt == 0):
                print('[+] Clean on Virus Total')
            else:
                print("[!] Detected on Virus Total",
                      '\n\t- Count of detections:', vt,
                      '\n\t- Count of Antivirus scanned:', vtTotalScanners)
            print("--------------------------------------------------------------------------------------------------------")
            
            if (dt == 0):  # integrate other blacklists to adjust the result
                print("[+] Not in Duggy Tuxy's list")
                agressivity = 2
            if (ipsum == 0):
                print("[+] Not in IPsum's blacklists")
                agressivity = 2
            if (rfd == 0):
                print("[+] Not in Redflag Domains")
                agressivity = 2
            else:
                if dt == 1:
                    print("[!] Found in Duggy Tuxy and/or IPsum lists")
                if ipsum == 1:
                    print("[!] Found in  IPsum lists")
                if rfd == 1:
                    print("[!] Found in Redflag Domains")
                if (dt == 1 and vt <= 8):
                    agressivity = 4
                if (dt == 1 and vt >= 8 and vt <= 15):
                    agressivity = 6
                if (dt == 1 and vt >= 16 and vt <= 25):
                    agressivity = 8
                if (dt == 1 and vt >= 26):
                    agressivity = 10
                if (ipsum == 1 and ipsumCount <= 3):
                    agressivity = 4
                if (ipsum == 1 and vt >= 8 and ipsumCount > 3 and  ipsumCount < 5):
                    agressivity = 6
                if (ipsum == 1 and vt >= 16 and ipsumCount > 5 and  ipsumCount < 7):
                    agressivity = 8
                if (ipsum == 1 and ipsumCount > 7):
                    agressivity = 10
                if (dt == 1 and ipsum == 1 and vt <= 3 and ipsumCount < 2):
                    agressivity = 4
                if (dt == 1 and ipsum == 1 and vt > 4 and ipsumCount > 2 and ipsumCount < 4):
                    agressivity = 6
                if (dt == 1 and ipsum == 1 and vt > 6 and ipsumCount > 4 and ipsumCount < 8):
                    agressivity = 8
                if (dt == 1 and ipsum == 1 and vt > 6 and ipsumCount >= 8):
                    agressivity = 10
                print('[!] Agressivity:', agressivity)
            print("--------------------------------------------------------------------------------------------------------")
            
            if ciCount == 0:
                print('[+] Not reporteded by Criminal IP')
            if gn == 0:
                print('[+] Not reporteded by Greynoise')
            else:
                if ciCount == 1:
                    print("[!] Reported malicious on Criminal IP",
                        "\n\t- Count of opened ports:",ciPortCount,
                        "\n\t- Count of vulnerability founded:",ciVulCount,
                        "\n\t- Count of IP category:",ciCatCount)
                elif gn == 1:
                    print("[!] Reported malicious on Greynoise")

                if (ciCount == 1 and agressivity <= 4 or gn == 1 and agressivity <= 4):
                    malicious = 4
                if (ciCount == 1 and agressivity > 4 and agressivity <= 6 or gn == 1 and agressivity > 4 and agressivity <= 6):
                    malicious = 6
                if (ciCount == 1 and agressivity > 6 and agressivity <= 8 or gn == 1 and agressivity > 6 and agressivity <= 8):
                    malicious = 8
                if (ciCount == 1 and agressivity > 8 or gn == 1 and agressivity > 8):
                    malicious = 10
                if (ciCount == 1 and gn == 1 and agressivity <= 4):
                    malicious = 4
                if (ciCount == 1 and gn == 1 and agressivity > 4 and agressivity <= 6):
                    malicious = 6
                if (ciCount == 1 and gn == 1 and agressivity > 6 and agressivity <= 8):
                    malicious = 8
                if (ciCount == 1 and gn == 1 and agressivity > 8):
                    malicious = 10
                print('[!] Malicious:', malicious)
            print("--------------------------------------------------------------------------------------------------------")
            
            if abReports == 0:  # Integrate otx to adjust the result
                print("[+] Not found on AbuseIPDB")
            else:
                print("[!] Reported on AbuseIPDB",
                    "\n\t- Confidence index:",abCnfidence, '%',
                    "\n\t- Count of reports:",abReports)
                if (abReports <= 50 and agressivity < 4 and malicious <= 4):
                    reported = 4
                if (abReports >= 50 and agressivity <= 6 and malicious <= 6):
                    reported = 6
                if (abReports >= 50 and agressivity <= 8 and malicious <= 8):
                    reported = 8     
                if (abReports >= 50 and agressivity > 8 and malicious > 8):
                    reported = 10
                print('[!] Reported:', reported)
            print("--------------------------------------------------------------------------------------------------------")
            
            if otx == 0:
                print("[+] No pulses reported on OTX")
            else:
                print("[!] Count of pulses reported on OTX:",otx)
            print("--------------------------------------------------------------------------------------------------------")

            if tb == 0:
                print("[+] No judgment reported on Threatbook")
            else:
                print("[!] Judgment reported on Threatbook:", tbJudgment)
            print("--------------------------------------------------------------------------------------------------------")

            if tlp == 0:
                print("[+] Not reported in internal IOCs")
            else:
                print(Color.ORANGE + "[!] Reported in internal IOCs" + Color.END)
            print("--------------------------------------------------------------------------------------------------------")
            

            if tb == 0:
                note = (agressivity+malicious+reported)
            else:
                note = (agressivity+malicious+reported+6)

            if rfd == 0:
                note = (agressivity+malicious+reported)
            else:
                note = (agressivity+malicious+reported+4)

            if tlp == 0:
                note = (agressivity+malicious+reported)
            else:
                note = (agressivity+malicious+reported+8)
            
            note = int(note)/3

            print("[!] General note:", round(note, 2))
            if round(note, 2) <= 2:
                print(Color.GREEN + '[!] Low IP' + Color.END)
            if (round(note, 2) > 2 and round(note, 2) < 6):
                print(Color.ORANGE + '[!] Medium IP' + Color.END)
            if (round(note, 2) >= 6 and round(note, 2) < 8):
                print(Color.RED + '[!] High IP' + Color.END)
            if round(note, 2) >= 8:
                print(Color.RED + '[!] Critical IP' + Color.END)
        
        except Exception as err:
            print(Color.RED + 'Error:', err + Color.END)