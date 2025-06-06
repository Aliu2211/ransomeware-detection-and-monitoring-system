import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import logging
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

class RansomwareBehaviorDetector:
    def __init__(self, model_path=None):
        """
        Initialize the ransomware behavior detector
        
        Args:
            model_path (str): Path to a pre-trained model file
        """
        self.scaler = StandardScaler()
        if model_path and os.path.exists(model_path):
            logger.info(f"Loading model from {model_path}")
            self.model = joblib.load(model_path)
            self.is_trained = True
        else:
            logger.info("Creating new model")
            self.model = IsolationForest(
                n_estimators=100,
                max_samples='auto',
                contamination=0.1,
                random_state=42
            )
            self.is_trained = False
    
    def extract_features(self, system_data):
        """
        Extract features from system monitoring data
        
        Args:
            system_data (dict): Dictionary containing system activity data
            
        Returns:
            numpy.ndarray: Feature vector
        """
        features = [
            system_data.get('file_operations_count', 0),
            system_data.get('file_encryption_count', 0),
            system_data.get('file_deletion_count', 0),
            system_data.get('file_creation_count', 0),
            system_data.get('disk_read_rate', 0),
            system_data.get('disk_write_rate', 0),
            system_data.get('cpu_usage', 0),
            system_data.get('memory_usage', 0),
            system_data.get('network_activity', 0)
        ]
        return np.array(features).reshape(1, -1)

    def train(self, training_data):
        """
        Train the anomaly detection model
        
        Args:
            training_data (list): List of dictionaries containing system data
        """
        if not training_data:
            logger.error("No training data provided")
            return False
            
        logger.info(f"Training model with {len(training_data)} samples")
        feature_vectors = []
        
        for data_point in training_data:
            feature_vectors.append(self.extract_features(data_point))
            
        X = np.vstack(feature_vectors)
        X_scaled = self.scaler.fit_transform(X)
        
        self.model.fit(X_scaled)
        self.is_trained = True
        logger.info("Model training complete")
        return True

    def save_model(self, model_path):
        """
        Save the trained model to disk
        
        Args:
            model_path (str): Path to save the model
        """
        if not self.is_trained:
            logger.error("Cannot save untrained model")
            return False
            
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(self.model, model_path)
        logger.info(f"Model saved to {model_path}")
        return True

    def generate_default_training_data(self):
        """
        Generate default training data for normal system behavior
        
        Returns:
            list: List of dictionaries containing simulated normal system data
        """
        logger.info("Generating default training data")
        normal_data = []
        for _ in range(100):
            normal_data.append({
                'file_operations_count': np.random.randint(1, 20),
                'file_encryption_count': 0,
                'file_deletion_count': np.random.randint(0, 5),
                'file_creation_count': np.random.randint(0, 10),
                'disk_read_rate': np.random.uniform(100, 5000),
                'disk_write_rate': np.random.uniform(50, 2000),
                'cpu_usage': np.random.uniform(5, 40),
                'memory_usage': np.random.uniform(20, 60),
                'network_activity': np.random.uniform(100, 5000)
            })
        return normal_data

    def predict(self, system_data):
        """
        Predict if the given system data indicates ransomware activity
        
        Args:
            system_data (dict): Dictionary containing system activity data
        
        Returns:
            float: Anomaly score (-1 for anomaly, 1 for normal)
            float: Decision score
        """
        if not self.is_trained:
            logger.error("Model not trained yet")
            return None, None
        
        features = self.extract_features(system_data)
        features_scaled = self.scaler.transform(features)
        
        prediction = self.model.predict(features_scaled)
        score = self.model.decision_function(features_scaled)
        
        return prediction[0], score[0]

if __name__ == "__main__":
    # Example usage
    detector = RansomwareBehaviorDetector()
    
    # Generate sample training data (normal behavior)
    normal_data = []
    for _ in range(100):
        normal_data.append({
            'file_operations_count': np.random.randint(1, 20),
            'file_encryption_count': 0,
            'file_deletion_count': np.random.randint(0, 5),
            'file_creation_count': np.random.randint(0, 10),
            'disk_read_rate': np.random.uniform(100, 5000),
            'disk_write_rate': np.random.uniform(50, 2000),
            'cpu_usage': np.random.uniform(5, 40),
            'memory_usage': np.random.uniform(20, 60),
            'network_activity': np.random.uniform(100, 5000)
        })
    
    # Train the model
    detector.train(normal_data)
    
    # Test with normal behavior
    normal_test = {
        'file_operations_count': 15,
        'file_encryption_count': 0,
        'file_deletion_count': 3,
        'file_creation_count': 7,
        'disk_read_rate': 3000,
        'disk_write_rate': 1000,
        'cpu_usage': 30,
        'memory_usage': 45,
        'network_activity': 2500
    }
    
    # Test with suspicious behavior (high encryption, deletion, and disk write)
    suspicious_test = {
        'file_operations_count': 500,
        'file_encryption_count': 300,
        'file_deletion_count': 100,
        'file_creation_count': 100,
        'disk_read_rate': 2000,
        'disk_write_rate': 8000,
        'cpu_usage': 90,
        'memory_usage': 85,
        'network_activity': 1500
    }
    
    normal_result, normal_score = detector.predict(normal_test)
    suspicious_result, suspicious_score = detector.predict(suspicious_test)
    
    print(f"Normal behavior prediction: {normal_result}, score: {normal_score}")
    print(f"Suspicious behavior prediction: {suspicious_result}, score: {suspicious_score}")
    
    # Save the model
    detector.save_model("../../data/models/ransomware_detector.joblib")