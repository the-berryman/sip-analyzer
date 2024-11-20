import os
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import pyshark
import base64
import json
from datetime import datetime
import re

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = '/tmp/pcaps'  # Heroku uses ephemeral filesystem
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# STIR/SHAKEN analysis code (from previous implementation)
def analyze_pcap(pcap_file):
    """
    [Previous analyze_pcap implementation]
    """
    # ... (include all the analysis functions from the previous code)
    pass


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not file.filename.endswith('.pcap'):
        return jsonify({'error': 'Only .pcap files are supported'}), 400

    try:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        findings = analyze_pcap(filepath)

        # Clean up the file after analysis
        os.remove(filepath)

        return jsonify({'findings': findings})

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)