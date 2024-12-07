import re
import csv
from collections import Counter, defaultdict

# Configurable threshold for detecting suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    with open(file_path, 'r') as log_file:
        logs = log_file.readlines()
    return logs

def count_requests_per_ip(logs):
    ip_counter = Counter()
    for log in logs:
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
        if ip_match:
            ip_counter[ip_match.group(1)] += 1
    return ip_counter

def find_most_frequent_endpoint(logs):
    endpoint_counter = Counter()
    for log in logs:
        endpoint_match = re.search(r'\"(?:GET|POST|PUT|DELETE) (/[^\s]*)', log)
        if endpoint_match:
            endpoint_counter[endpoint_match.group(1)] += 1
    most_frequent = endpoint_counter.most_common(1)
    return most_frequent[0] if most_frequent else ("None", 0)

def detect_suspicious_activity(logs):
    failed_logins = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
            if ip_match:
                failed_logins[ip_match.group(1)] += 1
    return {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file):
    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        
        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        # Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        # Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    # Input and output file paths
    log_file_path = 'sample.log'
    output_file_path = 'log_analysis_results.csv'
    
    # Parse log file
    logs = parse_log_file(log_file_path)
    
    # Count requests per IP
    ip_requests = count_requests_per_ip(logs)
    
    # Find the most accessed endpoint
    most_accessed_endpoint = find_most_frequent_endpoint(logs)
    
    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(logs)
    
    # Display results
    print("Requests per IP:")
    for ip, count in ip_requests.items():
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file_path)
    print(f"\nResults saved to {output_file_path}")

if __name__ == "__main__":
    main()
