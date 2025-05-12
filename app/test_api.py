import os
import requests
import json
import time
import pandas as pd
from tabulate import tabulate

def test_malware_api(samples_dir="samples", api_url="http://localhost:5000/predict"):
    """
    Test the malware classification API with samples from a directory.
    
    Args:
        samples_dir (str): Path to directory containing malware samples
        api_url (str): URL of the malware classification API endpoint
    """
    results = []
    
    # Check if the samples directory exists
    if not os.path.isdir(samples_dir):
        print(f"Error: Samples directory '{samples_dir}' not found")
        return
    
    # Get list of files in the samples directory
    files = [f for f in os.listdir(samples_dir) if os.path.isfile(os.path.join(samples_dir, f))]
    
    if not files:
        print(f"No files found in '{samples_dir}' directory")
        return
    
    print(f"Testing API with {len(files)} sample files...")
    
    # Test each file
    for filename in files:
        file_path = os.path.join(samples_dir, filename)
        
        try:
            # Send file to API
            with open(file_path, 'rb') as file:
                start_time = time.time()
                response = requests.post(
                    api_url,
                    files={'file': (filename, file, 'application/octet-stream')}
                )
                total_time = time.time() - start_time
            
            # Process response
            if response.status_code == 200:
                data = response.json()
                results.append({
                    'filename': filename,
                    'status': 'Success',
                    'category': data['category'],
                    'confidence': f"{float(data['confidence']):.2%}",
                    'api_processing_time': data['processing_time'],
                    'total_request_time': f"{total_time:.2f}s"
                })
            else:
                error_msg = 'Unknown error'
                try:
                    error_msg = response.json().get('error', error_msg)
                except:
                    pass
                
                results.append({
                    'filename': filename,
                    'status': f'Error ({response.status_code})',
                    'category': 'N/A',
                    'confidence': 'N/A',
                    'api_processing_time': 'N/A',
                    'total_request_time': f"{total_time:.2f}s",
                    'error': error_msg
                })
                
        except Exception as e:
            results.append({
                'filename': filename,
                'status': 'Exception',
                'category': 'N/A',
                'confidence': 'N/A',
                'api_processing_time': 'N/A',
                'total_request_time': 'N/A',
                'error': str(e)
            })
    
    # Convert results to DataFrame for better display
    df = pd.DataFrame(results)
    
    # Display summary statistics
    successful = df[df['status'] == 'Success']
    print("\n===== API Test Results =====")
    print(f"Total samples tested: {len(results)}")
    print(f"Successful classifications: {len(successful)} ({len(successful)/len(results):.1%})")
    
    if len(successful) > 0:
        # Show category distribution
        print("\n--- Category Distribution ---")
        category_counts = successful['category'].value_counts()
        for category, count in category_counts.items():
            print(f"{category}: {count} ({count/len(successful):.1%})")
    
    # Display detailed results
    print("\n--- Detailed Results ---")
    columns = ['filename', 'status', 'category', 'confidence', 'api_processing_time', 'total_request_time']
    print(tabulate(df[columns], headers='keys', tablefmt='grid'))
    
    # Save results to CSV
    results_file = 'api_test_results.csv'
    df.to_csv(results_file, index=False)
    print(f"\nDetailed results saved to: {results_file}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Test the malware classification API')
    parser.add_argument('--dir', default='samples', help='Directory containing sample files')
    parser.add_argument('--url', default='http://localhost:5000/predict', help='API endpoint URL')
    
    args = parser.parse_args()
    
    test_malware_api(samples_dir=args.dir, api_url=args.url)