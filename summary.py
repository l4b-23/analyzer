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
            # whois
            country = Count.count()[0][0]
            prx = Count.count()[0][1]
            ipi_country = Count.count()[11][0]
            ipi_org = Count.count()[11][1]
            ipi_continent = Count.count()[11][2]
            ipi_region = Count.count()[11][3]
            
            # public CTI
            vt = Count.count()[1][0]
            vt_total_scanners = Count.count()[1][1]
            vt_link = Count.count()[1][2]
            ci_count = Count.count()[4][0]
            ci_port_count = Count.count()[4][1]
            ci_vuln_count = Count.count()[4][2]
            ci_cat_count = Count.count()[4][3]
            ab_reports = Count.count()[5][0]
            ab_cnfidence = Count.count()[5][1]
            otx = Count.count()[6]
            tb = Count.count()[7][0]
            tb_judgment = Count.count()[7][1]
            tb_ports = Count.count()[7][2]
            tb_link = Count.count()[7][3]
            gn = Count.count()[8][0]
            gn_riot = Count.count()[8][1]
            url_scan = Count.count()[12]
            check_phish = Count.count()[13][0]
            check_phish_link = Count.count()[13][1]
            check_phish_verdict = Count.count()[13][2]

            # public blcklists
            dt = Count.count()[2]
            ipsum = Count.count()[3][0]
            ipsum_blacklists = Count.count()[3][1]
            rfd = Count.count()[9]
            c2 = Count.count()[14][0]
            c2_fam = Count.count()[14][1]

            # private blacklist
            tlp = Count.count()[10]

            agressivity = 0
            malicious = 0
            reported = 0

            # Console Report
            print('[+] Country:',str(country),
                  '\n[+] Categorized as public proxy (IP 2 Location):',str(prx),
                  '\n[+] Present in RIOT DB (Greynoise):',gn_riot,
                  "\n\t[+] RIOT informs about IPs used by business services who certainly won't attack you.")
            print("--------------------------------------------------------------------------------------------------------")
            
            if (vt == 0):
                print('[+] Clean on Virus Total')
            else:
                print("[!] Detected on Virus Total",
                      '\n\t- Count of detections:', vt,
                      '\n\t- Count of Antivirus scanned:', vt_total_scanners)
            print("--------------------------------------------------------------------------------------------------------")
            
            if dt == 0:  # integrate other blacklists to adjust the result
                print("[+] Not in the Duggy Tuxy blacklist")
                agressivity = 2
            else:
                print("[!] Found in Duggy Tuxy blacklist")
            if ipsum == 0:
                print("[+] Not in IPsum's blacklists")
                agressivity = 2
            else:
                print("[!] Found in IPsum's blacklists")
            if rfd == 0:
                print("[+] Not in Redflag Domains")
                agressivity = 2
            else:
                print("[!] Found in Redflag Domains")
            if c2 == 0:
                print("[+] Not in C2 Tracker")
                agressivity = 2
            else:
                print(Color.RED + f"[!] Found in C2 Tracker: {c2_fam} (Familly)" + Color.END)

            if (dt == 1 and vt <= 8):
                agressivity = 4
            if (dt == 1 and vt >= 8 and vt <= 15):
                agressivity = 6
            if (dt == 1 and vt >= 16 and vt <= 25):
                agressivity = 8
            if (dt == 1 and vt >= 26):
                agressivity = 10
            if (ipsum == 1 and ipsum_blacklists <= 3):
                agressivity = 4
            if (ipsum == 1 and vt >= 8 and ipsum_blacklists > 3 and  ipsum_blacklists < 5):
                agressivity = 6
            if (ipsum == 1 and vt >= 16 and ipsum_blacklists > 5 and  ipsum_blacklists < 7):
                agressivity = 8
            if (ipsum == 1 and ipsum_blacklists > 7):
                agressivity = 10
            if (dt == 1 and ipsum == 1 and vt <= 3 and ipsum_blacklists < 2):
                agressivity = 4
            if (dt == 1 and ipsum == 1 and vt > 4 and ipsum_blacklists > 2 and ipsum_blacklists < 4):
                agressivity = 6
            if (dt == 1 and ipsum == 1 and vt > 6 and ipsum_blacklists > 4 and ipsum_blacklists < 8):
                agressivity = 8
            if (dt == 1 and ipsum == 1 and vt > 6 and ipsum_blacklists >= 8):
                agressivity = 10
            print('[!] Agressivity:', agressivity)
            print("--------------------------------------------------------------------------------------------------------")
            
            if ci_count == 0:
                print('[+] Not reporteded by Criminal IP')
            else:
                if ci_count == 1:
                    print("[!] Reported malicious on Criminal IP",
                        "\n\t- Count of opened ports:",ci_port_count,
                        "\n\t- Count of vulnerability founded:",ci_vuln_count,
                        "\n\t- Count of IP category:",ci_cat_count)

                if (ci_count == 1 and agressivity <= 4 or gn == 1 and agressivity <= 4):
                    malicious = 4
                if (ci_count == 1 and agressivity > 4 and agressivity <= 6 or gn == 1 and agressivity > 4 and agressivity <= 6):
                    malicious = 6
                if (ci_count == 1 and agressivity > 6 and agressivity <= 8 or gn == 1 and agressivity > 6 and agressivity <= 8):
                    malicious = 8
                if (ci_count == 1 and agressivity > 8 or gn == 1 and agressivity > 8):
                    malicious = 10
                if (ci_count == 1 and gn == 1 and agressivity <= 4):
                    malicious = 4
                if (ci_count == 1 and gn == 1 and agressivity > 4 and agressivity <= 6):
                    malicious = 6
                if (ci_count == 1 and gn == 1 and agressivity > 6 and agressivity <= 8):
                    malicious = 8
                if (ci_count == 1 and gn == 1 and agressivity > 8):
                    malicious = 10
                print('[!] Malicious:', malicious)
            print("--------------------------------------------------------------------------------------------------------")
            
            if ab_reports == 0:  # Integrate otx to adjust the result
                print("[+] Not found on AbuseIPDB")
            else:
                print("[!] Reported on AbuseIPDB",
                    "\n\t- Confidence index:",ab_cnfidence, '%',
                    "\n\t- Count of reports:",ab_reports)
                if (ab_reports <= 50 and agressivity < 4 and malicious <= 4):
                    reported = 4
                if (ab_reports >= 50 and agressivity <= 6 and malicious <= 6):
                    reported = 6
                if (ab_reports >= 50 and agressivity <= 8 and malicious <= 8):
                    reported = 8     
                if (ab_reports >= 50 and agressivity > 8 and malicious > 8):
                    reported = 10
                print(f'[!] Reported: {reported}')
            print("--------------------------------------------------------------------------------------------------------")
                
            if otx == 0:
                print("[+] No pulses reported on OTX")
            else:
                print(f"[!] Count of pulses reported on OTX: {otx}")
            print("--------------------------------------------------------------------------------------------------------")

            if tb == 0:
                print("[+] No judgment reported on Threatbook")
            else:
                print(f"[!] Judgment reported on Threatbook: {tb_judgment}")
            print("--------------------------------------------------------------------------------------------------------")
        
            if isinstance(tb_ports, list):
                print("[!] Top 10 ports listed on Threatbook, see the links below for the full list")
                max_ports = 10
                ports_displayed = 0
                for port in tb_ports:
                    if ports_displayed < max_ports:
                        port_str = ', '.join([f"{key}: {value}" for key, value in port.items()])
                        print(f'\t- {port_str}')
                        ports_displayed += 1
                    else:
                        break
            else:
                print("[+] No opened ports on Threatbook")
            print("--------------------------------------------------------------------------------------------------------")

            if gn == 0:
                print('[+] Not reporteded by Greynoise')
            else:
                print("[!] Reported malicious on Greynoise")
            print("--------------------------------------------------------------------------------------------------------")

            if url_scan == 0:
                print('[+] Not reporteded as malicious by URL Scan report')
            else:
                print("[!] Reporteded as malicious by URL Scan report")
            print("--------------------------------------------------------------------------------------------------------")
            
            if check_phish == 0:
                print('[+] Clean on Check Phish or Scan was unsuccessful')
            else:
                print(f"[!] Reported on Check Phish: {check_phish_verdict}")
            print("--------------------------------------------------------------------------------------------------------")

            if tlp == 0:
                print("[+] Not reported in internal IOCs")
            else:
                print(Color.RED + "[!] Reported in internal IOCs" + Color.END)
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
                fileReport.write(f'\n\t- Organisation/ASN: {ipi_org}')
                fileReport.write(f'\n\t- Country: {country}')
                fileReport.write(f'\n\t- Country code: {ipi_country}')
                fileReport.write(f'\n\t- Continent: {ipi_continent}')
                fileReport.write(f'\n\t- Region: {ipi_region}')
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
                fileReport.write(f'\n[+] Present in RIOT DB (Greynoise): {str(gn_riot)}')
                fileReport.write("\n\tRIOT informs about IPs used by business services who certainly won't attack you.")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write("\n[+] Additional infos")
                if vt == 0:
                    fileReport.write('\n[+] Clean on Virus Total')
                else:
                    fileReport.write("\n[!] Detected on Virus Total")
                    fileReport.write(f'\n\t- Count of detections: {vt}')
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if ci_count == 0:
                    fileReport.write('\n[+] Not reporteded by Criminal IP')
                else:
                    fileReport.write("\n[!] Reported malicious on Criminal IP")
                    fileReport.write(f"\n\t- Count of opened ports: {str(ci_port_count)}")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if ab_reports == 0:
                    fileReport.write("\n[+] Not found on Abuse IP DB")
                else:
                    fileReport.write("\n[!] Reported on Abuse IP DB")
                    fileReport.write(f"\n\t- Count of reports: {ab_reports}")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if otx == 0:
                    fileReport.write("\n[+] No pulses reported on OTX")
                else:
                    fileReport.write(f"\n[!] Count of pulses reported on OTX: {otx}")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if tb == 0:
                    fileReport.write("\n[+] No judgment reported on Threatbook")
                else:
                    fileReport.write(f"\n[!] Judgment reported on Threatbook: {tb_judgment}")
                fileReport.write("\n ---------------------------------------------------------------------")

                if isinstance(tb_ports, list):
                    fileReport.write("\n[!] Top 10 ports listed on Threatbook, see link above for full list")
                    max_ports = 10
                    ports_displayed = 0
                    for port in tb_ports:
                        if ports_displayed < max_ports:
                            port_str = ', '.join([f"{key}: {value}" for key, value in port.items()])
                            fileReport.write(f'\n\t- {port_str}')
                            ports_displayed += 1
                        else:
                            break
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if gn == 0:
                    fileReport.write('\n[+] Not reporteded by Greynoise')
                else:
                    fileReport.write("\n[!] Reported malicious on Greynoise")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if url_scan == 0:
                    fileReport.write('\n[+] Not reporteded as malicious by URL Scan report')
                else:
                    fileReport.write("\n[!] Reported as malicious by URL Scan Report")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if check_phish == 0:
                    fileReport.write('\n[+] Clean on Check Phish or Scan was unsuccessful')
                else:
                    fileReport.write(f"\n[!] Reported on Check Phish: {check_phish_verdict}")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write("\n [+] Checking Blacklists")
                if dt == 0:
                    fileReport.write("\n[+] Not in the Duggy Tuxy blacklist.")
                else:
                    fileReport.write("\n[!] Found in Duggy Tuxy blacklist")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if ipsum == 0:
                    fileReport.write("\n[+] Not in IPsum's blacklists")
                else:
                    fileReport.write("\n[!] Found in IPsum's blacklists")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if rfd == 0:
                    fileReport.write("\n[+] Not in Redflag Domains")
                else:
                    fileReport.write("\n[!] Found in Redflag Domains")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                if c2 == 0:
                    fileReport.write("\n[+] Not in C2 Tracker")
                else:
                    fileReport.write(f"\n[!] Found in C2 Tracker: {c2_fam} (Familly)")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                fileReport.write("\n[+] Links:")
                fileReport.write(f"\n\t- Virus Total: {vt_link}")
                fileReport.write(f"\n\t- TreatBook: {tb_link}")
                fileReport.write(f"\n\t- Check Phisk: {check_phish_link}")
                fileReport.close()
                
        except Exception as err:
            print('Summary error:', err)