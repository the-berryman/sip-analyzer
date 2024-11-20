import os
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import pyshark
import base64
import json
from datetime import datetime
import re
import asyncio
import nest_asyncio

nest_asyncio.apply()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def analyze_pcap(pcap_file):
    """Analyze PCAP file for STIR/SHAKEN Identity headers"""
    print(f"Starting analysis of {pcap_file}")

    try:
        # Set up event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        cap = pyshark.FileCapture(pcap_file, display_filter='sip')
        findings = []

        for packet in cap:
            print(f"Processing packet: {packet}")

            if hasattr(packet, 'sip'):
                print(f"SIP packet found. Fields: {dir(packet.sip)}")

                for field in dir(packet.sip):
                    if field.startswith('identity'):
                        print(f"Identity field found: {field}")
                        identity_header = getattr(packet.sip, field)
                        analysis = analyze_identity_header(identity_header, packet)
                        findings.append(analysis)

        print(f"Total findings: {len(findings)}")
        cap.close()
        return findings

    except Exception as e:
        print(f"Error in analyze_pcap: {str(e)}")
        raise e


def decode_jwt_parts(jwt_string):
    # Remove 'Identity: ' if present and any whitespace
    jwt_string = jwt_string.strip()
    if jwt_string.startswith('Identity:'):
        jwt_string = jwt_string.split('Identity:')[1].strip()

    # Extract the JWT part
    jwt_match = re.match(r'^([^;]+)', jwt_string)
    if jwt_match:
        jwt_string = jwt_match.group(1)

    # Split into parts
    parts = jwt_string.split('.')

    def decode_part(part):
        # Add padding if needed
        padding = len(part) % 4
        if padding:
            part += '=' * (4 - padding)

        try:
            decoded = base64.urlsafe_b64decode(part)
            return json.loads(decoded)
        except Exception as e:
            print(f"Error decoding part: {e}")
            return None

    header = decode_part(parts[0]) if len(parts) > 0 else None
    payload = decode_part(parts[1]) if len(parts) > 1 else None

    return header, payload


def analyze_identity_header(identity_header, packet):
    """Analyze a single Identity header"""
    try:
        packet_info = {
            'timestamp': packet.sniff_timestamp,
            'source_ip': packet.ip.src if hasattr(packet, 'ip') else None,
            'dest_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
            'sip_method': packet.sip.method if hasattr(packet.sip, 'method') else None
        }

        header, payload = decode_jwt_parts(identity_header)

        analysis = {
            'packet_info': packet_info,
            'raw_identity_header': identity_header,
            'decoded': {
                'header': header,
                'payload': payload
            },
            'analysis': {}
        }

        if payload:
            analysis['analysis'] = {
                'attestation_level': payload.get('attest'),
                'destination_number': payload.get('dest', {}).get('tn', [None])[0],
                'originating_number': payload.get('orig', {}).get('tn'),
                'timestamp': datetime.fromtimestamp(payload['iat']).isoformat() if 'iat' in payload else None,
                'call_id': payload.get('origid')
            }

            analysis['risk_assessment'] = assess_risk(header, payload, packet_info)

        return analysis
    except Exception as e:
        return {
            'error': str(e),
            'raw_identity_header': identity_header
        }


def assess_risk(header, payload, packet_info):
    """Assess potential risks in the STIR/SHAKEN data"""
    risks = []

    if payload.get('attest') != 'A':
        risks.append({
            'level': 'WARNING',
            'type': 'LOW_ATTESTATION',
            'detail': f"Attestation level is {payload.get('attest')} (not A)"
        })

    if 'iat' in payload:
        timestamp = datetime.fromtimestamp(payload['iat'])
        now = datetime.now()
        time_diff = abs((now - timestamp).total_seconds())

        if time_diff > 60:
            risks.append({
                'level': 'WARNING',
                'type': 'OLD_TIMESTAMP',
                'detail': f"Token is {time_diff} seconds old"
            })

    if header and 'x5u' in header:
        x5u = header['x5u'].lower()
        if not any(trusted_domain in x5u for trusted_domain in ['.t-mobile.com', '.verizon.com', '.att.com']):
            risks.append({
                'level': 'WARNING',
                'type': 'UNKNOWN_CERTIFICATE_DOMAIN',
                'detail': f"Certificate domain not recognized: {x5u}"
            })

    return risks


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        print(f"Received file: {file.filename}")  # Add this line

        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        if not file.filename.endswith('.pcap'):
            return jsonify({'error': 'Only .pcap files are supported'}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        findings = analyze_pcap(filepath)
        print(f"Analysis findings: {findings}")  # Add this line

        os.remove(filepath)

        return jsonify({'findings': findings})

    except Exception as e:
        print(f"Error: {str(e)}")  # Add this line
        return jsonify({'error': str(e)}), 500


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'File too large'}), 413


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')