import numpy as np
import random
import json
import os

def generate_normal_behavior_data(num_samples=100, output_path=None):
    """
    Generate synthetic normal behavior data for training the ransomware detector
    
    Args:
        num_samples (int): Number of data points to generate
        output_path (str): Path to save the generated data as JSON
        
    Returns:
        list: List of dictionaries containing synthetic normal system data
    """
    normal_data = []
    
    # Define reasonable ranges for normal behavior
    for _ in range(num_samples):
        normal_data.append({
            'file_operations_count': random.randint(1, 20),
            'file_encryption_count': 0,  # Normal behavior has no encryption
            'file_deletion_count': random.randint(0, 5),
            'file_creation_count': random.randint(0, 10),
            'disk_read_rate': random.uniform(100, 5000),
            'disk_write_rate': random.uniform(50, 2000),
            'cpu_usage': random.uniform(5, 40),
            'memory_usage': random.uniform(20, 60),
            'network_activity': random.uniform(100, 5000)
        })
    
    # Save to file if path is provided
    if output_path:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(normal_data, f, indent=2)
        print(f"Generated {num_samples} normal behavior data points and saved to {output_path}")
    
    return normal_data

if __name__ == "__main__":
    # Generate training data
    output_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'data',
        'training',
        'normal_behavior.json'
    )
    generate_normal_behavior_data(num_samples=100, output_path=output_path)
