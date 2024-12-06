import re
import csv
from collections import defaultdict

def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        return file.readlines()

def count_requests_per_ip(log_lines):
    ip_counts = defaultdict(int)
    for line in log_lines:
        ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            ip = ip_match.group(1)
            ip_counts[ip] += 1
    return sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)

def find_most_frequent_endpoint(log_lines):
    endpoint_counts = defaultdict(int)
    for line in log_lines:
        endpoint_match = re.search(r'\"[A-Z]+\s+(\S+)\s+HTTP', line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_counts[endpoint] += 1
    if endpoint_counts:
        return max(endpoint_counts.items(), key=lambda x: x[1])
    else:
        return None, 0

def detect_suspicious_activity(log_lines, threshold=10):
    failed_login_counts = defaultdict(int)
    for line in log_lines:
        if '401' in line or 'Invalid credentials' in line:
            ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                failed_login_counts[ip] += 1
    return [(ip, count) for ip, count in failed_login_counts.items() if count > threshold]

def save_results_to_csv(ip_requests, most_frequent_endpoint, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(['IP Address', 'Request Count'])
        writer.writerows(ip_requests)

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint', 'Access Count'])
        writer.writerow(most_frequent_endpoint)

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Count'])
        writer.writerows(suspicious_ips)

def main():
    log_file = 'sample.log'  # Input log file
    output_file = 'log_analysis_results.csv'

    # Parse log file
    log_lines = parse_log_file(log_file)

    # Count requests per IP
    ip_requests = count_requests_per_ip(log_lines)

    # Identify most accessed endpoint
    most_frequent_endpoint, access_count = find_most_frequent_endpoint(log_lines)

    # Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(log_lines)

    # Display results
    print("IP Address           Request Count")
    for ip, count in ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    if most_frequent_endpoint:
        print(f"{most_frequent_endpoint} (Accessed {access_count} times)")
    else:
        print("No endpoints found in the log file.")

    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips:
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    save_results_to_csv(ip_requests, (most_frequent_endpoint, access_count), suspicious_ips, output_file)
    print(f"\nResults saved to {output_file}")

if __name__ == '__main__':
    main()

