# SIP/STIR SHAKEN Analyzer

A web application for analyzing SIP packets with STIR/SHAKEN attestation from PCAP files.

## Features
- Drag-and-drop PCAP file upload
- Multiple file analysis support
- STIR/SHAKEN attestation level detection
- Certificate domain validation
- Call origin information analysis
- Risk assessment for each call
- Diversion header detection

## Requirements
- Python 3.9+
- Flask
- pyshark
- Wireshark/tshark

## Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Ensure Wireshark is installed
# Run application
python app.py
```

## Heroku Deployment
```bash
# Add buildpacks
heroku buildpacks:add --index 1 https://github.com/heroku/heroku-buildpack-apt
heroku buildpacks:add --index 2 heroku/python

# Deploy
git push heroku main
```

## Project Structure
```
/
├── app.py              # Main application
├── requirements.txt    # Python dependencies
├── Procfile           # Heroku configuration
├── Aptfile            # System dependencies
├── runtime.txt        # Python version
└── templates/         # HTML templates
    └── index.html     # Main interface
```

## Author
Gavin Berryman

## License
MIT License