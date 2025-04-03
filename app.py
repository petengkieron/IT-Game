from flask import Flask, request, jsonify, render_template
from werkzeug.utils import secure_filename
import os
import logging
from analyze import analyze_pcap
from virustotal import check_ip_reputation
import requests
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set API key directly in code
os.environ['VIRUSTOTAL_API_KEY'] = '5f849e032b7630642ee85d5f37f53eae71f12cf2189fc5e7a3a988845da88227'

app = Flask(__name__)
app.config.update(
    UPLOAD_FOLDER='uploads',
    ENV='development',
    DEBUG=True
)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

API_URL = "http://93.127.203.48:5000/pcap/latest"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'})
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        results = analyze_pcap(filepath)
        return jsonify(results)

@app.route('/check_ip', methods=['POST'])
def check_ip():
    ip = request.json.get('ip')
    if not ip:
        return jsonify({'error': 'No IP provided'})
    result = check_ip_reputation(ip)
    return jsonify(result)

@app.route('/fetch_pcap', methods=['GET'])
def fetch_pcap():
    try:
        # Télécharger le PCAP depuis l'API
        response = requests.get(API_URL)
        if response.status_code == 200:
            # Créer un nom de fichier unique avec timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"pcap_{timestamp}.pcap"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Sauvegarder le fichier
            with open(filepath, 'wb') as f:
                f.write(response.content)
            
            # Analyser le fichier
            results = analyze_pcap(filepath)
            return jsonify({
                'success': True,
                'filename': filename,
                'results': results
            })
        else:
            return jsonify({
                'success': False,
                'error': f"API error: {response.status_code}"
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    logger.info('Starting Security Analysis Dashboard...')
    logger.info('Server running on http://localhost:5000')
    app.run(host='0.0.0.0', port=5000)
