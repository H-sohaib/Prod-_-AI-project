from flask import Flask, request, jsonify
import numpy as np
import logging
import os
import tempfile
import time
from predict import MalwareClassifier

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='malware_api.log', level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize the malware classifier
try:
    classifier = MalwareClassifier()
    logging.info("Malware classifier initialized successfully")
except Exception as e:
    logging.error(f"Failed to initialize malware classifier: {e}")
    raise

@app.route('/', methods=['GET'])
def home():
    return "Welcome to the Malware Classification API! Use the /predict endpoint to classify malware samples."

@app.route('/predict', methods=['POST'])
def predict():
    # Check if file is in request
    if 'file' not in request.files:
        logging.error("No file provided in request")
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        logging.error("Empty file provided")
        return jsonify({'error': 'Empty file provided'}), 400

    # Save file temporarily
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as temp_file:
            file.save(temp_file.name)
            temp_file_path = temp_file.name
        
        start_time = time.time()
        
        # Use the classifier from predict.py to classify the file
        result = classifier.classify_file(temp_file_path)
        
        # Clean up
        os.unlink(temp_file_path)
        
        # Check if there was an error
        if 'error' in result:
            logging.error(f"Classification failed for {file.filename}: {result['error']}")
            return jsonify({'error': result['error']}), 400
        
        # Log prediction
        logging.info(f"File: {file.filename}, Category: {result['category']}, Confidence: {result['confidence']}")
        
        # Return results
        return jsonify({
            'category': result['category'],
            'confidence': result['confidence'],
            'processing_time': result['processing_time']
        })

    except Exception as e:
        logging.error(f"Prediction failed for {file.filename}: {e}")
        if 'temp_file_path' in locals():
            try:
                os.unlink(temp_file_path)
            except:
                pass
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)