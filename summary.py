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
    Calculates scores 
    Returns results in console and text file
    """
    @staticmethod
    def summary():
        try:
            # Variables obtained from the count() function in "analyzer"
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
            ci = Count.count()[4][0]
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
            tf = Count.count()[15][0]
            tf_link = Count.count()[15][1]

            # public blcklists
            dt = Count.count()[2]
            ipsum = Count.count()[3][0]
            ipsum_blacklists = Count.count()[3][1]
            rfd = Count.count()[9]
            c2 = Count.count()[14][0]
            c2_fam = Count.count()[14][1]

            # private blacklist
            tlp = Count.count()[10]



            # ------------------------------------------------------------------------------------------
            """_summary_
            Calculation of the final score
            """
            # ------------------------------------------------------------------------------------------
            agressivity = 2
            malicious = 2
            reported = 2

            # Calculation of Agressivity
            if vt == 0 and dt == 0 and ipsum == 0 and rfd == 0 and c2 == 0:
                agressivity = 2
            elif vt <= 5 and (dt == 0 or ipsum == 0 or rfd == 0 or c2 == 0):
                for value in [dt, rfd]:
                    if value == 1:
                        agressivity += 2
                if ipsum == 1:
                    agressivity = 6
                if c2 == 1:
                    agressivity = 8
            elif vt > 5 and vt <= 10 and (dt == 0 or ipsum == 0 or rfd == 0 or c2 == 0):
                for value in [dt, rfd]:
                    if value == 1:
                        agressivity += 2
                if ipsum == 1:
                    agressivity = 8
                if c2 == 1:
                    agressivity = 10
            elif vt > 10 and (dt == 0 or ipsum == 0 or rfd == 0 or c2 == 0):
                for value in [dt, ipsum, rfd]:
                    if value == 1:
                        agressivity += 2
                if c2 == 1:
                    agressivity = 10
            
            if tf == 1 or tlp == 1:
                agressivity += 10
            
            #  Calculation of Malicious
            if vt == 0 and ci == 0 and gn == 0 and url_scan == 0 and tb == 0:
                malicious = 2
            elif vt < 4 and (ci == 0 or gn == 0 or url_scan == 0 or tb == 0):
                if url_scan == 1:
                    malicious = 4
                if ci == 1 or gn == 1 or tb == 1:
                    malicious = 6
            elif (vt >= 4 and vt <= 10) and (ci == 0 or gn == 0 or url_scan == 0 or tb == 0):
                malicious = 8
            elif vt > 10 and (ci == 0 or gn == 0 or url_scan == 0 or tb == 0):
                malicious = 10
            
            # Calculation of Reported
            if vt == 0 and ab_reports == 0 and otx == 0:
                reported = 2
            elif vt < 4 or ab_reports < 20 or otx < 4:
                reported = 4
            elif (vt >= 4 and vt < 8) or (ab_reports >= 10 and ab_reports < 100) or otx >= 4:
                reported = 6
            elif (vt >= 8 and vt < 10) or ab_reports >= 100 or otx >= 4:
                reported = 8
            else:
                reported = 10
            
            # Operation to ensure that the value of the variable remains within the specified range (between 2 and 10)
            agressivity = min(10, max(2, agressivity))
            malicious = min(10, max(2, malicious))
            reported = min(10, max(2, reported))
            
            final_score = (agressivity + malicious + reported) / 3



            # ------------------------------------------------------------------------------------------
            """_summary_
            Console Report
            """
            # ------------------------------------------------------------------------------------------
            print(f'[+] COUNTRY: {str(country)}',
                  '\n[+] Categorized as public proxy (IP 2 Location):',str(prx),
                  '\n[+] Present in RIOT DB (Greynoise):',gn_riot,
                  "\n\t[+] RIOT informs about IPs used by business services who certainly won't attack you.")
            print("--------------------------------------------------------------------------------------------------------")
            
            if vt == 0:
                print('[+] Clean on Virus Total')
            else:
                print(Color.RED + "[!] Detected on Virus Total" + Color.END,
                      '\n\t- Count of detections:', vt,
                      '\n\t- Count of Antivirus scanned:', vt_total_scanners)
            print("--------------------------------------------------------------------------------------------------------")
            
            if dt == 0:
                print("[+] Not in the Duggy Tuxy blacklist")
            else:
                print(Color.RED + "[!] Found in Duggy Tuxy blacklist" + Color.END)
            if ipsum == 0:
                print("[+] Not in IPSUM's blacklists")
            else:
                print(Color.RED + "[!] Found in IPSUM's blacklists: " + Color.END, f"{ipsum_blacklists}")
            if rfd == 0:
                print("[+] Not in Redflag Domains")
            else:
                print(Color.RED + "[!] Found in Redflag Domains" + Color.END)
            if c2 == 0:
                print("[+] Not in C2 Tracker")
            else:
                print(Color.RED + f"[!] Found in C2 Tracker: " + Color.END, f"{c2_fam} (Familly)")
            if tf == 0:
                print("[+] Not in ThreaTFox")
            else:
                print(Color.RED + "[!] Found in ThreaTFox" + Color.END)
            if tlp == 0:
                print("[+] Not in internal IOCs")
            else:
                print(Color.RED + "[!] Found in internal IOCs" + Color.END)
            print("--------------------------------------------------------------------------------------------------------")
            print(f'[!] Agressivity: {agressivity}')
            print("--------------------------------------------------------------------------------------------------------")
            
            if ci == 0:
                print('[+] Not Considered malicious on Criminal IP')
            else:
                print(Color.RED + "[!] Considered malicious on Criminal IP" + Color.END,
                    "\n\t- Count of opened ports:",ci_port_count,
                    "\n\t- Count of vulnerability founded:",ci_vuln_count,
                    "\n\t- Count of IP category:",ci_cat_count)
            
            if gn == 0:
                print('[+] Not Considered malicious on Greynoise')
            else:
                print(Color.RED + "[!] Considered malicious on Greynoise" + Color.END)
            
            if url_scan == 0:
                print('[+] Not Considered malicious on URL Scan report')
            else:
                print(Color.RED + "[!] Considered malicious on URL Scan report" + Color.END)
            print("--------------------------------------------------------------------------------------------------------")
            print(f'[!] Malicious: {malicious}')
            print("--------------------------------------------------------------------------------------------------------")
            
            if ab_reports == 0:
                print("[+] Not found on AbuseIPDB")
            else:
                print(Color.RED + "[!] Reported on AbuseIPDB" + Color.END,
                    "\n\t- Confidence index:",ab_cnfidence, '%',
                    "\n\t- Count of reports:",ab_reports)

            if otx == 0:
                print("[+] No pulses reported on OTX")
            else:
                print(Color.RED + "[!] Pulses reported on OTX: " + Color.END, f"{otx}")

            if tb == 0:
                print("[+] No judgment reported on ThreaTBook")
            else:
                print(Color.RED + "[!] Judgment reported on ThreaTBook: " + Color.END, f"{tb_judgment}")
        
            if isinstance(tb_ports, list):
                print(Color.RED + "[!] Ports reported on ThreaTBook, see the links above for the full list" + Color.END)
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
                print("[+] No opened ports on ThreaTBook")
            print("--------------------------------------------------------------------------------------------------------")

            if check_phish == 0:
                print('[+] Clean on Check Phish or Scan was unsuccessful')
            else:
                print(Color.RED + "[!] Reported on Check Phish: " + Color.END, f"{check_phish_verdict}")
            print("--------------------------------------------------------------------------------------------------------")
            print(f'[!] Reported: {reported}')
            print("--------------------------------------------------------------------------------------------------------")

            print("[!] General note:", round(final_score, 2))
            if round(final_score, 2) <= 3:
                print(Color.GREEN + '[!] Low IP' + Color.END)

            if (round(final_score, 2) > 3 and round(final_score, 2) < 5.99):
                print(Color.ORANGE + '[!] Medium IP' + Color.END)

            if (round(final_score, 2) >= 5.99 and round(final_score, 2) < 7.99):
                print(Color.RED + '[!] High IP' + Color.END)

            if round(final_score, 2) >= 8:
                print(Color.RED + '[!] Critical IP' + Color.END)



            # ------------------------------------------------------------------------------------------
            """_summary_
            Writes the report to a text file
            """
            # ------------------------------------------------------------------------------------------
            with open(f'/home/{USERNAME}/Documents/analyzer_reports/'+TODAY+'/'+ str(DOMAIN_NAME_TO_IP) + ".txt","a+") as fileReport:
                fileReport.write(" ------------------------------------------------------------------------------------------------------------------------------")
                fileReport.write(f"\n Report for: {DOMAIN}, associated with IP address {DOMAIN_NAME_TO_IP}")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                
                fileReport.write('\n[+] WHOIS Report:')
                fileReport.write(f'\n\t- Organisation/ASN: {ipi_org}')
                fileReport.write(f'\n\t- COUNTRY: {country}')
                fileReport.write(f'\n\t- COUNTRY code: {ipi_country}')
                fileReport.write(f'\n\t- Continent: {ipi_continent}')
                fileReport.write(f'\n\t- Region: {ipi_region}')
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                
                fileReport.write(f"\n[+] General note: {str(round(final_score, 2))}")
                if round(final_score, 2) <= 2:
                    fileReport.write('\n\t[!] Low IP')

                if (round(final_score, 2) > 2 and round(final_score, 2) < 5):
                    fileReport.write('\n\t[!] Medium IP')

                if (round(final_score, 2) >= 5 and round(final_score, 2) < 8):
                    fileReport.write('\n\t[!] High IP')

                if round(final_score, 2) >= 8:
                    fileReport.write('\n\t[!] Critical IP')
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                
                fileReport.write("\n[+] Internal IOCs status")
                if tlp == 0:
                    fileReport.write("\n\t[+] Not in internal IOCs")
                else:
                    fileReport.write("\n\t[!] Found in internal IOCs")
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
                
                if ci == 0:
                    fileReport.write('\n[+] Not considered malicious on Criminal IP')
                else:
                    fileReport.write("\n[!] Considered malicious on Criminal IP")
                    fileReport.write(f"\n\t- Count of opened ports: {str(ci_port_count)}")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                
                if gn == 0:
                    fileReport.write('\n[+] Not considered malicious on Greynoise')
                else:
                    fileReport.write("\n[!] Considered malicious on Greynoise")
                fileReport.write("\n --------------------------------------------------------------------------------------------------------")
                
                if url_scan == 0:
                    fileReport.write('\n[+] Not considered malicious on URL Scan report')
                else:
                    fileReport.write("\n[!] Considered malicious on URL Scan Report")
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
                    fileReport.write("\n[+] No judgment reported on ThreaTBook")
                else:
                    fileReport.write(f"\n[!] Judgment reported on ThreaTBook: {tb_judgment}")
                fileReport.write("\n ---------------------------------------------------------------------")

                if isinstance(tb_ports, list):
                    fileReport.write("\n[!] Top 10 ports listed on ThreaTBook, see link below for full list")
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
                
                if check_phish == 0:
                    fileReport.write('\n[+] Clean on Check Phish or Scan was unsuccessful')
                else:
                    fileReport.write(f"\n[!] Reported on Check Phish: {check_phish_verdict}")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                
                fileReport.write("\n[+] Checking Blacklists")
                if dt == 0:
                    fileReport.write("\n[+] Not in the Duggy Tuxy blacklist.")
                else:
                    fileReport.write("\n[!] Found in Duggy Tuxy blacklist")
                
                if ipsum == 0:
                    fileReport.write("\n[+] Not in IPSUM's blacklists")
                else:
                    fileReport.write(f"\n[!] Found in: {ipsum_blacklists} IPSUM's blacklists")
                
                if rfd == 0:
                    fileReport.write("\n[+] Not in Redflag Domains")
                else:
                    fileReport.write("\n[!] Found in Redflag Domains")
                
                if c2 == 0:
                    fileReport.write("\n[+] Not in C2 Tracker")
                else:
                    fileReport.write(f"\n[!] Found in C2 Tracker: {c2_fam} (Familly)")
                
                if tf == 0:
                    fileReport.write("\n[+] Not in ThreaTFox")
                else:
                    fileReport.write("\n[!] Found on ThreaTFox")
                fileReport.write("\n ----------------------------------------------------------------------------------------------------------------------------")
                
                fileReport.write("\n[+] Links:")
                fileReport.write(f"\n\t- Virus Total: {vt_link}")
                fileReport.write(f"\n\t- TreaTBook: {tb_link}")
                fileReport.write(f"\n\t- ThreaTFox (To Malpedia): {tf_link}")
                fileReport.write(f"\n\t- Check Phisk: {check_phish_link}")
                fileReport.close()
                
        except Exception as err:
            print('Summary error:', err)