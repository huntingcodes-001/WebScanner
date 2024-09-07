from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import subprocess
import os

app = Flask(__name__)

@app.route('/')
def index():
    scanned_domains = get_scanned_domains()
    return render_template('index.html', scanned_domains=scanned_domains)

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form['target_url']
    output_folder = create_output_folder(target_url)

    # Run the CLI commands (from your existing tool)
    try:
        run_whois(target_url, output_folder)
        run_nmap(target_url, output_folder)
        run_sublist3r(target_url, output_folder)
        run_wpscan(target_url, output_folder)
        run_nikto(target_url, output_folder)
        output_file = os.path.join(output_folder, f'output_of_{target_url}.txt')

        # Read the output file and display it on the results page
        with open(output_file, 'r') as f:
            results = f.read()
    except Exception as e:
        results = f"An error occurred: {str(e)}"

    return render_template('results.html', results=results, target_url=target_url)

@app.route('/scan_results/<target_url>')
def scan_results(target_url):
    output_folder = os.path.join("output", target_url)
    output_file = os.path.join(output_folder, f'output_of_{target_url}.txt')

    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            results = f.read()
        return render_template('results.html', results=results, target_url=target_url)
    else:
        return f"No results found for {target_url}"

def create_output_folder(target_url):
    output_folder = "output"
    target_folder = os.path.join(output_folder, target_url)
    
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    
    if not os.path.exists(target_folder):
        os.makedirs(target_folder)

    return target_folder

def get_scanned_domains():
    output_folder = "output"
    if not os.path.exists(output_folder):
        return []
    return os.listdir(output_folder)

# Placeholder functions for your existing CLI commands
def run_whois(target_url, output_folder):
    pass

def run_nmap(target_url, output_folder):
    pass

def run_sublist3r(target_url, output_folder):
    pass

def run_wpscan(target_url, output_folder):
    pass

def run_nikto(target_url, output_folder):
    pass

if __name__ == '__main__':
    app.run(debug=True)