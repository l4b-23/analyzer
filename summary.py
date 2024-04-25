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
            vtLink = Count.count()[1][2]
            ciCount = Count.count()[4][0]
            ciPortCount = Count.count()[4][1]
            ciVulCount = Count.count()[4][2]
            ciCatCount = Count.count()[4][3]
            abReports = Count.count()[5][0]
            abCnfidence = Count.count()[5][1]
            otx = Count.count()[6]
            tb = Count.count()[7][0]
            tbJudgment = Count.count()[7][1]
            tbPorts = Count.count()[7][2]
            tbLink = Count.count()[7][3]
            gn = Count.count()[8][0]
            gnRiot = Count.count()[8][1]
            dt = Count.count()[2]
            ipsum = Count.count()[3][0]
            ipsumCount = Count.count()[3][1]
            rfd = Count.count()[9]
            tlp = Count.count()[10]
            ipiCountry = Count.count()[11][0]
            ipiOrg = Count.count()[11][1]
            ipiContinent = Count.count()[11][2]
            ipiRegion = Count.count()[11][3]

            agressivity = 0
            malicious = 0
            reported = 0

            print('[+] Country:',str(country),
                  '\n[+] Categorized as public proxy (IP 2 Location):',str(prx),
                  '\n[+] Present in RIOT DB (Greynoise):',gnRiot,
                  "\n\t[+] RIOT informs about IPs used by business services who certainly won't attack you.")
            print("--------------------------------------------------------------------------------------------------------")
            
            if (vt == 0):
                print('[+] Clean on Virus Total')
            else:
                print("[!] Detected on Virus Total",
                      '\n\t- Count of detections:', vt,
                      '\n\t- Count of Antivirus scanned:', vtTotalScanners)
            print("--------------------------------------------------------------------------------------------------------")
            
            if (dt == 0):  # integrate other blacklists to adjust the result
                print("[+] Not in the Duggy Tuxy blacklist")
                agressivity = 2
            else:
                if dt == 1:
                    print("[!] Found in Duggy Tuxy blacklist")
            if (ipsum == 0):
                print("[+] Not in IPsum's blacklists")
                agressivity = 2
            else:
                if ipsum == 1:
                    print("[!] Found in IPsum's blacklists")
            if (rfd == 0):
                print("[+] Not in Redflag Domains")
                agressivity = 2
            else:
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
            else:
                if ciCount == 1:
                    print("[!] Reported malicious on Criminal IP",
                        "\n\t- Count of opened ports:",ciPortCount,
                        "\n\t- Count of vulnerability founded:",ciVulCount,
                        "\n\t- Count of IP category:",ciCatCount)

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

            if gn == 0:
                print('[+] Not reporteded by Greynoise')
            else:
                print("[!] Reported malicious on Greynoise")
            print("--------------------------------------------------------------------------------------------------------")

            if tlp == 0:
                print("[+] Not reported in internal IOCs")
            else:
                print(Color.ORANGE + "[!] Reported in internal IOCs" + Color.END)
            print("--------------------------------------------------------------------------------------------------------")

            note = (agressivity+malicious+reported)
            
            note +=4 if rfd !=0 else 0
            note +=6 if tb !=0 else 0
            note +=10 if tlp !=0 else 0

            # Nested ternary expression to determine the divisor as a function of the note value
            note = int(note) / (4 if note >= 40 else (5 if note >= 50 else 3))

            print("[!] General note:", round(note, 2))
            if round(note, 2) <= 2:
                print(Color.GREEN + '[!] Low IP' + Color.END)
            if (round(note, 2) > 2 and round(note, 2) < 6):
                print(Color.ORANGE + '[!] Medium IP' + Color.END)
            if (round(note, 2) >= 6 and round(note, 2) < 8):
                print(Color.RED + '[!] High IP' + Color.END)
            if round(note, 2) >= 8:
                print(Color.RED + '[!] Critical IP' + Color.END)

            # Report writing
            with open('analyzer_reports/'+TODAY+'/'+ str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
                fileReport.write(" ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write(f"\n Report for: {DOMAIN}, associated with IP address {DOMAIN_NAME_TO_IP}")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write('\n[+] WHOIS Report:')
                fileReport.write(f'\n\t- Organisation/ASN: {ipiOrg}')
                fileReport.write(f'\n\t- Country: {country}')
                fileReport.write(f'\n\t- Country code: {ipiCountry}')
                fileReport.write(f'\n\t- Continent: {ipiContinent}')
                fileReport.write(f'\n\t- Region: {ipiRegion}')
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write(f"\n[+] General note: {str(round(note, 2))}")
                if round(note, 2) <= 2:
                    fileReport.write('\n\t[!] Low IP')
                if (round(note, 2) > 2 and round(note, 2) < 6):
                    fileReport.write('\n\t[!] Medium IP')
                if (round(note, 2) >= 6 and round(note, 2) < 8):
                    fileReport.write('\n\t[!] High IP')
                if round(note, 2) >= 8:
                    fileReport.write('\n\t[!] Critical IP')
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write("\n[+] Internal IOCs status")
                if tlp == 0:
                    fileReport.write("\n\t[+] Not reported in internal IOCs")
                else:
                    fileReport.write("\n\t[!] Reported in internal IOCs")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write(f'\n[+] Present in RIOT DB (Greynoise): {str(gnRiot)}')
                fileReport.write("\n\tRIOT informs about IPs used by business services who certainly won't attack you.")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write("\n[+] Additional infos")
                if (vt == 0):
                    fileReport.write('\n[+] Clean on Virus Total')
                else:
                    fileReport.write("\n[!] Detected on Virus Total")
                    fileReport.write(f'\n\t- Count of detections: {vt}')
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if ciCount == 0:
                    fileReport.write('\n[+] Not reporteded by Criminal IP')
                else:
                    fileReport.write("\n[!] Reported malicious on Criminal IP")
                    fileReport.write(f"\n\t- Count of opened ports: {str(ciPortCount)}")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if abReports == 0:
                    fileReport.write("\n[+] Not found on Abuse IP DB")
                else:
                    fileReport.write("\n[!] Reported on Abuse IP DB")
                    fileReport.write(f"\n\t- Count of reports: {abReports}")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if otx == 0:
                    fileReport.write("\n[+] No pulses reported on OTX")
                else:
                    fileReport.write(f"\n[!] Count of pulses reported on OTX: {otx}")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if tb == 0:
                    fileReport.write("\n[+] No judgment reported on Threatbook")
                else:
                    fileReport.write(f"\n[!] Judgment reported on Threatbook: {tbJudgment}")
                    fileReport.write(f"\n\t- Ports (ThreatBook):")
                    for port in tbPorts:
                        fileReport.write(f"\n\t\t- {port}")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if gn == 0:
                    fileReport.write('\n[+] Not reporteded by Greynoise')
                else:
                    fileReport.write("\n[!] Reported malicious on Greynoise")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if (dt == 0):
                    fileReport.write("\n[+] Not in the Duggy Tuxy blacklist.")
                else:
                    fileReport.write("\n[!] Found in Duggy Tuxy blacklist")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if (ipsum == 0):
                    fileReport.write("\n[+] Not in IPsum's blacklists")
                else:
                    fileReport.write("\n[!] Found in IPsum's blacklists")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if (rfd == 0):
                    fileReport.write("\n[+] Not in Redflag Domains")
                else:
                    fileReport.write("\n[!] Found in Redflag Domains")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write("\n[+] Links:")
                fileReport.write(f"\n\t- Virus Total: {vtLink}")
                fileReport.write(f"\n\t- TreatBook: {tbLink}")
                fileReport.close()
                
        except Exception as err:
            print('Summary error:', err)