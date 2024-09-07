import subprocess
import os

def create_output_folder(target_url):
    folder_name = f"outputs/{target_url}"
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
    return folder_name

def append_to_file(file_path, content):
    with open(file_path, 'a') as f:
        f.write(content)

def run_whois(target_url, output_folder):
    whois_command = f"whois {target_url}"
    whois_output = subprocess.run(whois_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'output_of_{target_url}.txt'), whois_output)
    return whois_output

def run_nmap(target_ip, output_folder):
    nmap_command = f"nmap {target_ip}"
    nmap_output = subprocess.run(nmap_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'nmap_{target_ip}.txt'), nmap_output)
    return nmap_output

def run_sublist3r(target_url, output_folder):
    sublist3r_command = f"sublist3r -d {target_url}"
    sublist3r_output = subprocess.run(sublist3r_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'sublist3r_{target_url}.txt'), sublist3r_output)
    return sublist3r_output

def run_wpscan(target_url, output_folder):
    wpscan_command = f"wpscan --url {target_url} --no-update"
    wpscan_output = subprocess.run(wpscan_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'wpscan_{target_url}.txt'), wpscan_output)
    return wpscan_output

def run_nikto(target_url, output_folder):
    nikto_command = f"nikto -h {target_url}"
    nikto_output = subprocess.run(nikto_command, shell=True, capture_output=True, text=True).stdout
    append_to_file(os.path.join(output_folder, f'nikto_{target_url}.txt'), nikto_output)
    return nikto_output
