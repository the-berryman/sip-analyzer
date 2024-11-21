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

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"  # Adjust path if needed
os.environ['TSHARK_PATH'] = TSHARK_PATH

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def analyze_pcap(pcap_file):
    """Analyze PCAP file for unique STIR/SHAKEN sessions"""
    try:
        cap = pyshark.FileCapture(pcap_file, display_filter='sip')
        findings = []
        processed_calls = set()  # Track unique call IDs

        for packet in cap:
            if hasattr(packet, 'sip'):
                # Get call ID to group related packets
                call_id = getattr(packet.sip, 'call_id', None)

                # Only process unique calls
                if call_id and call_id not in processed_calls:
                    processed_calls.add(call_id)

                    # Check for Identity header
                    has_identity = False
                    for field in dir(packet.sip):
                        if field.startswith('identity'):
                            has_identity = True
                            identity_header = getattr(packet.sip, field)
                            analysis = analyze_identity_header(identity_header, packet)
                            findings.append(analysis)

                    # If no Identity header, create one basic analysis per call
                    if not has_identity:
                        analysis = analyze_basic_sip(packet)
                        findings.append(analysis)

        cap.close()
        return findings

    except Exception as e:
        print(f"Error in analyze_pcap: {str(e)}")
        raise e


def analyze_basic_sip(packet):
    """Analyze SIP packet without STIR/SHAKEN"""
    try:
        packet_info = {
            'timestamp': packet.sniff_timestamp,
            'source_ip': packet.ip.src if hasattr(packet, 'ip') else None,
            'dest_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
            'sip_method': packet.sip.method if hasattr(packet.sip, 'method') else None,
            'diversion_header': getattr(packet.sip, 'diversion', None),
            'from_display': getattr(packet.sip, 'from_display', None),
            'user_agent': getattr(packet.sip, 'user_agent', None),
            'contact': getattr(packet.sip, 'contact', None),
            'from_uri': getattr(packet.sip, 'from_uri', None),
            'to_uri': getattr(packet.sip, 'to_uri', None)
        }

        analysis = {
            'packet_info': packet_info,
            'analysis': {
                'attestation_level': 'None',
                'originating_number': extract_number(packet_info['from_uri']),
                'destination_number': extract_number(packet_info['to_uri']),
                'timestamp': datetime.fromtimestamp(float(packet_info['timestamp'])).isoformat(),
                'diversion_present': bool(packet_info['diversion_header']),
                'from_display': packet_info['from_display'],
                'user_agent': packet_info['user_agent'],
                'stir_shaken_implemented': False
            },
            'risk_assessment': [{
                'level': 'WARNING',
                'type': 'NO_STIR_SHAKEN',
                'detail': 'No STIR/SHAKEN implementation detected'
            }]
        }

        return analysis

    except Exception as e:
        return {
            'error': str(e),
            'packet_info': packet_info
        }
def extract_number(uri):
    """Extract phone number from SIP URI"""
    if not uri:
        return None
    match = re.search(r'sip:(\+?\d+)@', uri)
    return match.group(1) if match else None

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


def check_certificate_domain(x5u):
    """Enhanced certificate domain validation"""
    trusted_domains = {
        't-mobile': ['.t-mobile.com', 'sticr.fosrvt.com'],  # Added T-Mobile's STIR/SHAKEN domain
        'verizon': ['.verizon.com', '.signalwire.com'],
        'att': ['.att.com', '.attsignal.com'],
        'sprint': ['.sprint.com'],
        'comcast': ['.comcast.com', '.xfinity.com']
    }

    x5u = x5u.lower()
    for carrier, domains in trusted_domains.items():
        if any(domain in x5u for domain in domains):
            return True, carrier
    return False, None


def analyze_identity_header(identity_header, packet):
    """Enhanced SIP header analysis"""
    try:
        packet_info = {
            'timestamp': packet.sniff_timestamp,
            'source_ip': packet.ip.src if hasattr(packet, 'ip') else None,
            'dest_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
            'sip_method': packet.sip.method if hasattr(packet.sip, 'method') else None,
            'diversion_header': getattr(packet.sip, 'diversion', None),
            'from_display': getattr(packet.sip, 'from_display', None),
            'user_agent': getattr(packet.sip, 'user_agent', None),
            'contact': getattr(packet.sip, 'contact', None)
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
                'call_id': payload.get('origid'),
                'diversion_present': bool(packet_info['diversion_header']),
                'from_display': packet_info['from_display'],
                'user_agent': packet_info['user_agent']
            }

            if header and 'x5u' in header:
                is_trusted, carrier = check_certificate_domain(header['x5u'])
                analysis['analysis']['certificate_info'] = {
                    'trusted': is_trusted,
                    'carrier': carrier,
                    'url': header['x5u']
                }

            analysis['risk_assessment'] = assess_risk(header, payload, packet_info)

        return analysis
    except Exception as e:
        return {
            'error': str(e),
            'raw_identity_header': identity_header
        }


def assess_risk(header, payload, packet_info):
    """Enhanced risk assessment"""
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
        is_trusted, carrier = check_certificate_domain(header['x5u'])
        if not is_trusted:
            risks.append({
                'level': 'WARNING',
                'type': 'UNKNOWN_CERTIFICATE_DOMAIN',
                'detail': f"Certificate domain not recognized: {header['x5u']}"
            })

    if packet_info.get('diversion_header'):
        risks.append({
            'level': 'INFO',
            'type': 'DIVERSION_PRESENT',
            'detail': "Call has been diverted"
        })

    return risks


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    uploaded_files = []  # Track uploaded files

    try:
        if 'files[]' not in request.files:
            return jsonify({'error': 'No files uploaded'}), 400

        files = request.files.getlist('files[]')
        all_findings = []

        for file in files:
            if file.filename == '' or not file.filename.endswith('.pcap'):
                continue

            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_files.append(filepath)  # Add to tracking list

            file.save(filepath)
            findings = analyze_pcap(filepath)
            all_findings.append({
                'filename': file.filename,
                'findings': findings
            })

        return jsonify({'results': all_findings})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

    finally:
        # Clean up all uploaded files
        for filepath in uploaded_files:
            try:
                if os.path.exists(filepath):
                    os.remove(filepath)
            except Exception as e:
                print(f"Error removing file {filepath}: {e}")


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'File too large'}), 413


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')