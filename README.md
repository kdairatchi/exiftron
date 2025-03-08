# exiftron
# Usage Examples:
1. Generate a test image with preset payloads (PoC)

```
#python3 exiftron.py --test 
```
use instead
```
python3 test.py
```
2. Scan a single image (CLI report)

```
python3 exiftron.py -i test_image.jpg --report -g
```
3. Batch scan a folder of images

```
python3 exiftron.py -b downloaded_images --report -g
```
4. Inject a payload (e.g. RCE) into a single image

```
python3 exiftron.py -i test_image.jpg -p RCE --field Comment --report
```
5. Launch the web dashboard to view results
```
python3 exiftron.py -b downloaded_images --dashboard
```
![image](https://github.com/user-attachments/assets/dce6e062-b5bf-4696-9e8d-da44e6cc6feb)
![image](https://github.com/user-attachments/assets/635a3559-946d-4070-8f2a-7dcbe2ad2412)

This version integrates all features requested: vulnerability and PII detection, payload injection, PoC generation, blind attack ideas, and a dashboard for interactive review.
For production use of the dashboard, consider deploying with a proper WSGI server rather than Flask’s development server.
Update the GROQ_API_KEY if integrating AI analysis (the code placeholder can later be expanded to call Groq’s API for risk scoring).
Additional modules for URL/domain/wayback scanning can be integrated in future versions.
Happy bug hunting and good luck getting those bounties!
