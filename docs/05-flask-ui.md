# Flask Web UI

## Overview
The same scanning engine as the CLI, wrapped in a clean dark-themed
web interface with layer selection, a composite score dashboard, and
a ranked recommendation table with color-coded severity.

## Running

```bash
python3 app.py
# Open http://127.0.0.1:5000
```

## Features
- Checkbox-based layer selection (OS / Network / Web App or all three)
- Target IP and URL inputs for network and web app scans
- Composite score with weakest-layer callout
- Ranked recommendations table (critical → high → medium → low)
- Detailed per-layer findings with PASS/FAIL status
- Author watermark (bottom-right: "by Dhruv Parihar / github.com/Dhruv-parihar")

## Screenshots

| | |
|---|---|
| ![Flask index with watermark](../screenshots/04-flask-ui/02-flask-index-watermark.png) | Main scan form on Windows host — watermark visible bottom-right |
| ![Flask OS results Windows](../screenshots/04-flask-ui/03-flask-results-os-hardening.png) | Results page: OS hardening scan on Windows (33/100) with ranked recommendations |
| ![Flask detailed findings](../screenshots/04-flask-ui/04-flask-results-detailed.png) | Detailed findings table with PASS/FAIL per check |
| ![Flask index Parrot](../screenshots/04-flask-ui/05-flask-parrot-index.png) | Web UI running inside Parrot OS, OS hardening selected |
| ![Flask OS results Parrot](../screenshots/04-flask-ui/06-flask-parrot-os-results.png) | OS hardening results on Parrot (50/100) |
| ![Flask webapp results](../screenshots/04-flask-ui/07-flask-parrot-webapp-results.png) | Web app scan results against DVWA — missing headers, cookie flags |
