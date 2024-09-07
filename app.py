from flask import Flask, render_template, request, jsonify
import subprocess
import os
from threading import Thread
import time

app = Flask(__name__)
scan_status = {
    "status": "",
    "step": "",
    "complete": False,
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form['target_url']
    output_folder = create_output_folder(target_url)

    # Reset scan status
    scan_status["status"] = "Started"
    scan_status["step"] = "Initializing..."
    scan_status["complete"] = False

    # Run the scanning process in a separate thread
    thread = Thread(target=perform_scan, args=(target_url, output_folder))
    thread.start()

    return render_template('scan.html', target_url=target_url)

def perform_scan(target_url, output_folder):
    try:
        update_status("Getting Domain Information ...")
        run_whois(target_url, output_folder)

        update_status("Resolving IP Address ...")
        target_ip = resolve_ip(target_url)

        update_status("Scanning Ports ...")
        run_nmap(target_ip, output_folder)

        update_status("Finding Subdomains ...")
        run_sublist3r(target_url, output_folder)

        update_status("Finding vulnerabilities with WPScan ...")
        run_wpscan(target_url, output_folder)

        update_status("Finding vulnerabilities with Nikto ...")
        run_nikto(target_url, output_folder)

        update_status("Scan Complete", complete=True)
    except Exception as e:
        update_status(f"An error occurred: {str(e)}", complete=True)

def update_status(step, complete=False):
    scan_status["step"] = step
    scan_status["complete"] = complete

@app.route('/scan_status')
def get_scan_status():
    return jsonify(scan_status)

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
    whois_command = f"whois {target_url}"
    whois_output = subprocess.run(whois_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), "\n\n\n######################\nDomain Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), whois_output)

def run_nmap(target_ip, output_folder):
    nmap_command = f"nmap {target_ip}"
    nmap_output = subprocess.run(nmap_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_ip}.txt'), "\n\n\n######################\nPort Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_ip}.txt'), nmap_output)

def run_sublist3r(target_url, output_folder):
    sublist3r_command = f"python3 /opt/Sublist3r/sublist3r.py -d {target_url} -v"
    sublist3r_output = subprocess.run(sublist3r_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), "\n\n\n######################\nSubdomain Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), sublist3r_output)

def run_wpscan(target_url, output_folder):
    wpscan_command = f"wpscan --url {target_url}"
    wpscan_output = subprocess.run(wpscan_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), "\n\n\n######################\nWPScan Vulnerability Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), wpscan_output)

def run_nikto(target_url, output_folder):
    nikto_command = f"nikto -h {target_url} -Tuning 123bde -maxtime 1100"
    nikto_output = subprocess.run(nikto_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), "\n\n\n######################\nNikto Vulnerability Information:\n######################\n\n")
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), nikto_output)

if __name__ == '__main__':
    app.run(debug=True)
