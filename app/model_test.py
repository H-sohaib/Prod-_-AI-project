
import numpy as np
import os
import sys
import lief
import joblib
from tensorflow.keras.models import load_model
from ember.ember.features import PEFeatureExtractor
import argparse
import time

class MalwareClassifier:
    """
    A class for malware classification using a pre-trained deep learning model.
    """
    
    def __init__(self, model_path='malware_classifier_model.h5', 
                 scaler_path='scaler.pkl', encoder_path='label_encoder.pkl'):
        """
        Initialize the classifier by loading model and preprocessing objects.
        
        Args:
            model_path (str): Path to the saved model file
            scaler_path (str): Path to the saved scaler object
            encoder_path (str): Path to the saved label encoder object
        """
        try:
            # Load model and preprocessing objects
            self.model = load_model(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoder = joblib.load(encoder_path)
            self.extractor = PEFeatureExtractor()
            print("Model and preprocessing objects loaded successfully")
        except Exception as e:
            print(f"Failed to load model or preprocessing objects: {e}")
            sys.exit(1)
    
    def extract_features(self, file_path):
        """
        Extract features from a PE file.
        
        Args:
            file_path (str): Path to the PE file
            
        Returns:
            numpy.ndarray: Feature vector with shape (1, 2381)
        """
        try:
            # Parse PE file
            with open(file_path, 'rb') as f:
                bytez = f.read()

            features = self.extractor.feature_vector(bytez)
            
            # Extract features
            features = np.array(features).reshape(1, 2381)
            
            # Validate feature vector
            if features.shape != (1, 2381) or np.any(np.isnan(features)):
                raise ValueError(f"Invalid feature vector for {file_path}")
                
            return features
        except Exception as e:
            print(f"Feature extraction failed: {e}")
            raise
    
    def classify_file(self, file_path):
        """
        Classify a PE file.
        
        Args:
            file_path (str): Path to the PE file
            
        Returns:
            dict: Classification results with category and confidence score
        """
        try:
            start_time = time.time()
            
            # Check if file exists
            if not os.path.isfile(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
                
            # Extract features
            features = self.extract_features(file_path)
            
            # Normalize features
            features_normalized = self.scaler.transform(features)
            
            # Predict
            prediction = self.model.predict(features_normalized, verbose=0)
            predicted_class = np.argmax(prediction, axis=1)
            category = self.label_encoder.inverse_transform(predicted_class)[0]
            confidence = float(prediction[0, predicted_class[0]])
            
            processing_time = time.time() - start_time
            
            return {
                'file': os.path.basename(file_path),
                'category': category,
                'confidence': confidence,
                'processing_time': f"{processing_time:.2f}s"
            }
            
        except Exception as e:
            return {'error': str(e)}


def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Classify malware samples using a pre-trained model')
    parser.add_argument('file_path', help='Path to the PE file to classify')
    parser.add_argument('--model', default='malware_classifier_model.h5', help='Path to the model file')
    parser.add_argument('--scaler', default='scaler.pkl', help='Path to the scaler file')
    parser.add_argument('--encoder', default='label_encoder.pkl', help='Path to the label encoder file')
    args = parser.parse_args()
    
    # Initialize classifier
    classifier = MalwareClassifier(
        model_path=args.model,
        scaler_path=args.scaler,
        encoder_path=args.encoder
    )
    
    # Classify file
    result = classifier.classify_file(args.file_path)
    
    # Print result
    if 'error' in result:
        print(f"Error: {result['error']}")
    else:
        print("\n------ Malware Classification Result ------")
        print(f"File:         {result['file']}")
        print(f"Category:     {result['category']}")
        print(f"Confidence:   {result['confidence']:.2%}")
        print(f"Process Time: {result['processing_time']}")
        print("-----------------------------------------\n")


if __name__ == "__main__":
    main()