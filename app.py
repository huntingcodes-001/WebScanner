from flask import Flask, render_template, request, redirect, url_for, flash
from flask_socketio import SocketIO, emit
import os
from cli_tool import run_whois, run_nmap, run_sublist3r, run_wpscan, run_nikto, create_output_folder

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback_default_key')  # Use an environment variable for the secret key
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if request.method == 'POST':
        target_url = request.form['target_url']

        if not target_url:
            flash('Please enter a target URL.')
            return redirect(url_for('index'))

        output_folder = create_output_folder(target_url)

        try:
            target_ip = os.popen(f"host {target_url} | grep 'has address' | awk '{{print $4}}'").read().strip()

            # Emit progress to the client
            emit_status("Starting scan for " + target_url)

            # Step 1: WHOIS Scan
            emit_status("Running Whois scan...")
            whois_result = run_whois(target_url, output_folder)
            emit_status("Whois scan completed.")

            # Step 2: Nmap Scan
            emit_status("Running Nmap scan...")
            nmap_result = run_nmap(target_ip, output_folder)
            emit_status("Nmap scan completed.")

            # Step 3: Sublist3r Scan
            emit_status("Running Sublist3r scan...")
            sublist3r_result = run_sublist3r(target_url, output_folder)
            emit_status("Sublist3r scan completed.")

            # Step 4: WPScan
            emit_status("Running WPScan...")
            wpscan_result = run_wpscan(target_url, output_folder)
            emit_status("WPScan completed.")

            # Step 5: Nikto Scan
            emit_status("Running Nikto scan...")
            nikto_result = run_nikto(target_url, output_folder)
            emit_status("Nikto scan completed.")

            # Combine all results into one
            result = f"<h3>Whois Scan:</h3>{whois_result}"
            result += f"<h3>Nmap Scan:</h3>{nmap_result}"
            result += f"<h3>Sublist3r Scan:</h3>{sublist3r_result}"
            result += f"<h3>WPScan:</h3>{wpscan_result}"
            result += f"<h3>Nikto Scan:</h3>{nikto_result}"

            emit_status("All scans completed.")

            return render_template('results.html', target_url=target_url, output=result)
        except Exception as e:
            flash(f"Error occurred during scanning: {e}")
            return redirect(url_for('index'))

@socketio.on('connect')
def handle_connect():
    print("Client connected")

def emit_status(message):
    socketio.emit('scan_progress', {'data': message})

if __name__ == "__main__":
    socketio.run(app, debug=True)
