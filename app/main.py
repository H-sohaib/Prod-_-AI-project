from flask import Flask, request, jsonify
import numpy as np
from tensorflow.keras.models import load_model
import joblib
import lief
from ember.ember.features import PEFeatureExtractor
import logging
import os
import tempfile

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(filename='malware_api.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Load model and preprocessing objects
try:
    model = load_model('malware_classifier_model.h5')
    scaler = joblib.load('scaler.pkl')
    label_encoder = joblib.load('label_encoder.pkl')
    extractor = PEFeatureExtractor()
    logging.info("Model and preprocessing objects loaded successfully")
except Exception as e:
    logging.error(f"Failed to load model or preprocessing objects: {e}")
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

        # Extract LIEF features
        pe = lief.parse(temp_file_path)
        if pe is None:
            logging.error(f"Invalid PE file: {file.filename}")
            return jsonify({'error': 'Invalid PE file'}), 400

        features = extractor.feature_vector(pe)
        features = np.array(features).reshape(1, 2381)
        if features.shape != (1, 2381) or np.any(np.isnan(features)):
            logging.error(f"Invalid feature vector for {file.filename}")
            return jsonify({'error': 'Invalid feature vector'}), 400

        # Preprocess features
        features_normalized = scaler.transform(features)

        # Predict
        prediction = model.predict(features_normalized, verbose=0)
        predicted_class = np.argmax(prediction, axis=1)
        category = label_encoder.inverse_transform(predicted_class)[0]
        confidence = float(prediction[0, predicted_class[0]])

        # Log prediction
        logging.info(f"File: {file.filename}, Category: {category}, Confidence: {confidence}")

        # Clean up
        os.unlink(temp_file_path)

        return jsonify({
            'category': category,
            'confidence': confidence
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