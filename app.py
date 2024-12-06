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


def analyze_sip_fraud_patterns(packet):
    """Deep analysis of SIP headers for fraud detection"""
    fraud_indicators = []
    risk_level = "LOW"

    try:
        # Extract key SIP header information
        packet_info = {
            'source_ip': packet.ip.src if hasattr(packet, 'ip') else None,
            'dest_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
            'from_uri': getattr(packet.sip, 'from_uri', None),
            'to_uri': getattr(packet.sip, 'to_uri', None),
            'pai': getattr(packet.sip, 'p_asserted_identity', None),
            'user_agent': getattr(packet.sip, 'user_agent', None),
            'contact': getattr(packet.sip, 'contact', None),
            'via': getattr(packet.sip, 'via', None),
            'record_route': getattr(packet.sip, 'record_route', None)
        }

        # Check for international routing of domestic calls
        from_number = extract_number(packet_info['from_uri'])
        to_number = extract_number(packet_info['to_uri'])

        if from_number and to_number:
            if (from_number.startswith('1') and to_number.startswith('1') and
                    not packet_info['dest_ip'].startswith(('10.', '172.', '192.168.'))):
                fraud_indicators.append({
                    'type': 'SUSPICIOUS_ROUTING',
                    'detail': 'Domestic call routed internationally',
                    'severity': 'HIGH',
                    'evidence': f"Source: {from_number}, Dest: {to_number}, IP: {packet_info['dest_ip']}"
                })
                risk_level = "HIGH"

        # Check for PAI mismatches
        if packet_info['pai']:
            pai_number = extract_number(packet_info['pai'])
            pai_host = extract_host(packet_info['pai'])
            contact_host = extract_host(packet_info['contact'])

            if pai_host and contact_host and pai_host != contact_host:
                fraud_indicators.append({
                    'type': 'PAI_MISMATCH',
                    'detail': 'P-Asserted-Identity host differs from Contact host',
                    'severity': 'HIGH',
                    'evidence': f"PAI Host: {pai_host}, Contact Host: {contact_host}"
                })
                risk_level = "HIGH"

        # Check for suspicious equipment signatures
        if packet_info['record_route'] and 'sansay' in packet_info['record_route'].lower():
            fraud_indicators.append({
                'type': 'SUSPICIOUS_EQUIPMENT',
                'detail': 'Session border controller information exposed in routing path',
                'severity': 'MEDIUM',
                'evidence': f"Record-Route: {packet_info['record_route']}"
            })
            risk_level = max(risk_level, "MEDIUM")

        # Check for missing STIR/SHAKEN
        has_identity = False
        for field in dir(packet.sip):
            if field.startswith('identity'):
                has_identity = True
                break

        if not has_identity:
            fraud_indicators.append({
                'type': 'NO_STIRSHAKEN',
                'detail': 'Call lacks STIR/SHAKEN attestation',
                'severity': 'MEDIUM',
                'evidence': 'No Identity header present'
            })
            risk_level = max(risk_level, "MEDIUM")

        # Check for verstat failures
        if packet_info['pai'] and 'verstat=No-TN-Validation' in packet_info['pai']:
            fraud_indicators.append({
                'type': 'VERSTAT_FAILURE',
                'detail': 'Number failed verification status check',
                'severity': 'HIGH',
                'evidence': f"PAI: {packet_info['pai']}"
            })
            risk_level = "HIGH"

        return {
            'fraud_analysis': {
                'risk_level': risk_level,
                'indicators': fraud_indicators,
                'analyzed_headers': packet_info
            }
        }

    except Exception as e:
        return {
            'error': str(e),
            'fraud_analysis': {
                'risk_level': 'ERROR',
                'indicators': [],
                'analyzed_headers': {}
            }
        }


def extract_host(uri):
    """Extract host from SIP URI"""
    if not uri:
        return None
    match = re.search(r'@([^:;>]+)', uri)
    return match.group(1) if match else None

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
    """Analyze SIP packet including fraud detection"""
    try:
        # Your existing packet_info collection
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

        # Get fraud analysis
        fraud_results = analyze_sip_fraud_patterns(packet)

        # Combine existing analysis with fraud detection
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
                'stir_shaken_implemented': False,
                'fraud_risk_level': fraud_results['fraud_analysis']['risk_level']
            },
            'risk_assessment': [{
                'level': 'WARNING',
                'type': 'NO_STIR_SHAKEN',
                'detail': 'No STIR/SHAKEN implementation detected'
            }],
            'fraud_indicators': fraud_results['fraud_analysis']['indicators']
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