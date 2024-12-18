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
# new change

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
    """Analyze SIP packet including fraud detection with enhanced fallback parsing"""
    try:
        # Initial packet info collection
        packet_info = {
            'timestamp': packet.sniff_timestamp,
            'source_ip': packet.ip.src if hasattr(packet, 'ip') else None,
            'dest_ip': packet.ip.dst if hasattr(packet, 'ip') else None,
            'sip_method': packet.sip.method if hasattr(packet.sip, 'method') else None,
            'diversion_header': getattr(packet.sip, 'diversion', None),
            'from_display': None,  # We'll set this with enhanced extraction
            'user_agent': getattr(packet.sip, 'user_agent', None),
            'contact': getattr(packet.sip, 'contact', None),
            'from_uri': getattr(packet.sip, 'from_uri', None),
            'to_uri': getattr(packet.sip, 'to_uri', None),
            'number_type': None  # New field for number type
        }

        # Enhanced From Display extraction
        if hasattr(packet.sip, 'from'):
            from_header = getattr(packet.sip, 'from')
            # Try to extract display name between quotes
            display_match = re.search(r'"([^"]+)"', from_header)
            if display_match:
                packet_info['from_display'] = display_match.group(1)
            elif '<' in from_header:
                # Try to get text before the < if no quotes
                display_name = from_header.split('<')[0].strip()
                if display_name:
                    packet_info['from_display'] = display_name

        # Enhanced number extraction with fallbacks
        from_number = None
        to_number = None

        # Try multiple sources for 'from' number
        if packet_info['from_uri']:
            from_number = extract_number(packet_info['from_uri'])
        if not from_number and hasattr(packet.sip, 'from'):
            from_number = extract_number(getattr(packet.sip, 'from'))
        if not from_number and hasattr(packet.sip, 'p_asserted_identity'):
            from_number = extract_number(getattr(packet.sip, 'p_asserted_identity'))
        if not from_number and hasattr(packet.sip, 'remote_party_id'):
            from_number = extract_number(getattr(packet.sip, 'remote_party_id'))

        # Try multiple sources for 'to' number
        if packet_info['to_uri']:
            to_number = extract_number(packet_info['to_uri'])
        if not to_number and hasattr(packet.sip, 'to'):
            to_number = extract_number(getattr(packet.sip, 'to'))
        if not to_number and hasattr(packet.sip, 'request_uri'):
            to_number = extract_number(getattr(packet.sip, 'request_uri'))

        # Enhanced user agent extraction
        user_agent = packet_info['user_agent']
        if not user_agent:
            for field in dir(packet.sip):
                if 'user_agent' in field.lower():
                    user_agent = getattr(packet.sip, field)
                    break

        # Enhanced carrier detection
        carrier_info = None
        # Check X-Carrier header first
        for field in dir(packet.sip):
            if 'carrier' in field.lower():
                carrier_info = getattr(packet.sip, field)
                break

        # If no carrier found, try hostname patterns
        if not carrier_info and hasattr(packet.sip, 'from'):
            from_host = re.search(r'@([^;>]+)', getattr(packet.sip, 'from'))
            if from_host:
                hostname = from_host.group(1)
                carrier_info = identify_carrier_from_hostname(hostname)

        # Number type detection
        if from_number:
            packet_info['number_type'] = identify_number_type(from_number)

        # Get fraud analysis
        fraud_results = analyze_sip_fraud_patterns(packet)

        # Enhanced diversion detection
        diversion_present = bool(packet_info['diversion_header'])
        if not diversion_present:
            for field in dir(packet.sip):
                if 'diversion' in field.lower():
                    diversion_present = True
                    break

        analysis = {
            'packet_info': packet_info,
            'analysis': {
                'attestation_level': 'None',
                'originating_number': from_number or 'N/A',
                'destination_number': to_number or 'N/A',
                'timestamp': datetime.fromtimestamp(float(packet_info['timestamp'])).isoformat(),
                'diversion_present': diversion_present,
                'from_display': packet_info['from_display'] or 'N/A',
                'user_agent': user_agent or 'N/A',
                'carrier': carrier_info or 'N/A',
                'number_type': packet_info['number_type'] or 'Unknown',
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

        # Additional headers that might be present
        extra_headers = {}
        for field in dir(packet.sip):
            if field.startswith('p_') or field.startswith('x_'):
                extra_headers[field] = getattr(packet.sip, field)

        if extra_headers:
            analysis['additional_headers'] = extra_headers

        return analysis

    except Exception as e:
        return {
            'error': str(e),
            'packet_info': packet_info
        }


def identify_carrier_from_hostname(hostname):
    """Identify carrier based on hostname patterns"""
    carrier_patterns = {
        'verizon': [r'verizon\.com$', r'vzw\.com$'],
        'att': [r'att\.com$', r'attws\.com$'],
        'tmobile': [r't-mobile\.com$', r'tmo\.com$'],
        'sprint': [r'sprint\.com$'],
        'bandwidth': [r'bandwidth\.com$'],
        'twilio': [r'twilio\.com$'],
        'vonage': [r'vonage\.com$'],
        'ringcentral': [r'ringcentral\.com$']
    }

    for carrier, patterns in carrier_patterns.items():
        if any(re.search(pattern, hostname, re.I) for pattern in patterns):
            return carrier
    return None


def identify_number_type(number):
    """Identify number type based on known patterns"""
    # Remove any leading + or 1
    number = re.sub(r'^[+1]', '', number)

    # Check for toll-free numbers
    if number.startswith(('800', '888', '877', '866', '855', '844', '833')):
        return "Toll-Free"

    # Check for known VoIP ranges
    voip_prefixes = ['456']  # Add more known VoIP prefixes
    if any(number.startswith(prefix) for prefix in voip_prefixes):
        return "VoIP"

    return "Unknown"

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