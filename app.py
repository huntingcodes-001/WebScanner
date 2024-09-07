from flask import Flask, render_template, request, redirect, url_for
import subprocess
import os
from colorama import Fore, Style

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form['target_url']
    output_folder = create_output_folder(target_url)

    # Run the CLI commands
    try:
        run_whois(target_url, output_folder)
        target_ip = resolve_ip(target_url)
        run_nmap(target_ip, output_folder)
        run_sublist3r(target_url, output_folder)
        run_wpscan(target_url, output_folder)
        run_nikto(target_url, output_folder)
        output_file = os.path.join(output_folder, f'output_of_{target_url}.txt')

        # Read the output file and display it on the results page
        with open(output_file, 'r') as f:
            results = f.read()
    except Exception as e:
        results = f"An error occurred: {str(e)}"

    return render_template('results.html', results=results)

def create_output_folder(target_url):
    output_folder = "output"
    target_folder = os.path.join(output_folder, target_url)
    
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)

    return target_folder

def append_to_file(file_path, content):
    with open(file_path, 'a') as file:
        file.write(content)

def resolve_ip(target_url):
    return os.popen(f"host {target_url} | grep 'has address' | awk '{{print $4}}'").read().strip()

def run_whois(target_url, output_folder):
    print(Fore.YELLOW + "[*] Getting Domain Information ..." + Style.RESET_ALL)
    whois_command = f"whois {target_url}"
    whois_output = subprocess.run(whois_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), "\n\n\n######################\nDomain Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), whois_output)

def run_nmap(target_ip, output_folder):
    print(Fore.YELLOW + "[*] Scanning Ports..." + Style.RESET_ALL)
    nmap_command = f"nmap {target_ip}"
    nmap_output = subprocess.run(nmap_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_ip}.txt'), "\n\n\n######################\nPort Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_ip}.txt'), nmap_output)

def run_sublist3r(target_url, output_folder):
    print(Fore.YELLOW + "[*] Finding Subdomains ..." + Style.RESET_ALL)
    sublist3r_command = f"python3 /opt/Sublist3r/sublist3r.py -d {target_url} -v"
    sublist3r_output = subprocess.run(sublist3r_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), "\n\n\n######################\nSubdomain Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), sublist3r_output)

def run_wpscan(target_url, output_folder):
    print(Fore.YELLOW + "[*] Finding vulnerabilities with WPScan ..." + Style.RESET_ALL)
    wpscan_command = f"wpscan --url {target_url}"
    wpscan_output = subprocess.run(wpscan_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), "\n\n\n######################\nWPScan Vulnerability Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), wpscan_output)

def run_nikto(target_url, output_folder):
    print(Fore.YELLOW + "[*] Finding vulnerabilities with Nikto ..." + Style.RESET_ALL)
    nikto_command = f"nikto -h {target_url} -Tuning 123bde -maxtime 1100"
    nikto_output = subprocess.run(nikto_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), "\n\n\n######################\nNikto Vulnerability Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), nikto_output)

if __name__ == '__main__':
    app.run(debug=True)
