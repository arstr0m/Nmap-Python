import time

import nmap
from tqdm import tqdm

output_filename = 'nmap_scan_results.md'


def scan_host(host, arguments):
    if arguments == "":
        arguments = "-T4"
    nm = nmap.PortScanner()
    try:
        print(f"Scanning {host}...")
        with tqdm(total=100, desc=f"Scanning {host}") as pbar:
            nm.scan(hosts=host, arguments=arguments)
            for i in range(10):
                pbar.update(10)
                time.sleep(0.5)
    except Exception as e:
        print(f"Error scanning host {host}: {e}")
        return None
    return nm


def print_scan_results(nm, filename):
    if nm is None:
        print("No scan results to print.")
        return

    with open(filename, 'w') as file:
        file.write('# Nmap Scan Results\n\n')
        for host in nm.all_hosts():
            file.write(f'## Host: {host} ({nm[host].hostname()})\n')
            file.write(f'**State:** {nm[host].state()}\n\n')
            for proto in nm[host].all_protocols():
                file.write(f'### Protocol: {proto}\n')
                lport = nm[host][proto].keys()
                for port in lport:
                    try:
                        port_info = nm[host][proto][port]
                        file.write(f'- **Port:** {port}\n')
                        file.write(f'  - **State:** {port_info["state"]}\n')
                        file.write(f'  - **Service:** {port_info["name"]}\n')
                        file.write(f'  - **Version:** {port_info["product"]}\n')
                    except KeyError as e:
                        file.write(f'  - **Error retrieving info for port {port}: {e}\n')
                file.write('\n')


def main():
    print("Nmap Scanner")
    print("1. Scan a specific host")
    print("2. Scan a whole network")
    choice = input("Enter your choice (1/2): ")

    if choice == '1':
        host_to_scan = input("Enter the host to scan (e.g., 192.168.1.1): ")
    elif choice == '2':
        host_to_scan = input("Enter the network to scan (e.g., 192.168.1.0/24): ")
    else:
        print("Invalid choice. Exiting.")
        return

    print("\nNmap Scan Arguments:")
    print("-T<0-5>: Set the timing template (0-5).")
    print("    -T0: Paranoid (slowest, very thorough)")
    print("    -T1: Sneaky (slower, used to avoid detection)")
    print("    -T2: Polite (slower, used to avoid detection)")
    print("    -T3: Normal (default)")
    print("    -T4: Aggressive (faster scan)")
    print("    -T5: Insane (fastest, may be detected)")
    print("-Pn: No ping, assume the host is up")
    print("-F: Fast scan, scans fewer ports")
    print("-sS: TCP SYN scan (default and most popular scan option)")
    print("-sT: TCP connect scan")
    print("-sU: UDP scan")
    print("-sX: Xmas scan")
    print("-sN: TCP ACK scan")
    print("-sW: Window scan")
    print("-sO: IP protocol scan")
    print("-A: Enables OS detection, version detection, script scanning, and traceroute")
    print("-O: Enables OS detection")
    print("-sV: Service version detection")
    print("-p <port-range>: Scan specific ports (e.g., 22,80,443 or 1-1000)")
    print("--top-ports <number>: Scan the top ports")
    print("--script <script-list>: Run Nmap scripts (e.g., default, vuln, ssh)")
    print("--script-args <args>: Pass arguments to scripts")
    print("-sC: Scan using the default scripts")
    print("--version-all: Try to detect all versions of services")
    print("--traceroute: Perform traceroute")
    print("--reason: Show reason for state")
    print("--open: Show only open ports")
    print("--min-rate <packets/sec>: Set minimum packet send rate")
    print("--max-rate <packets/sec>: Set maximum packet send rate")
    print("-T<0-5>: Set timing template")
    print("-oN <file>: Output to a normal text file")
    print("-oX <file>: Output in XML format")
    print("-oG <file>: Output in grepable format")
    print("-oS <file>: Output in script kiddie format")
    arguments = input("Enter the scan arguments (e.g., -T4 -Pn -F -sS -A): ")

    nm = scan_host(host_to_scan, arguments)
    print_scan_results(nm, output_filename)
    print(f'Results saved to {output_filename}')


if __name__ == "__main__":
    main()
