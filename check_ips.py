import os
from datetime import datetime
import csv
import requests
import json
import sys
import ipaddress

# Replace with your API key
api_key = "<your_abuseip_api_key_here>"

# The URL of the API endpoint
url = "https://api.abuseipdb.com/api/v2/check"

print("="*50)
print("Starting IP Address Analysis".center(50))
print("="*50 + "\n")

# Check if the script was run with a command-line argument
if len(sys.argv) != 2:
    print("Usage: python script.py <ip_addresses.csv>")
    sys.exit(1)

# The name of the CSV file is the first command-line argument
csv_filename = sys.argv[1]

# Function to check if a string is a valid IP address
def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

# Counters for the IP statistics
total_ips = 0
legit_ips = 0
malicious_ips = 0

# Open the CSV file
with open(csv_filename, 'r') as file:
    reader = csv.reader(file)

    # Read the first row to find the index of the IP address column
    first_row = next(reader)
    ip_index = None
    for i, value in enumerate(first_row):
        if is_valid_ip(value):
            ip_index = i
            break

    if ip_index is None:
        print("No IP address column found")
        sys.exit(1)

    # Open the report file
    timestamp = datetime.now().strftime("%Y_%m_%d-%I_%M_%S%p")
    report_filename = os.path.join(os.getcwd(), f"report_{timestamp}.csv")

    with open(report_filename, 'w', newline='') as report:
        writer = csv.writer(report)
        # Write the header row
        writer.writerow(["IP Address", "Malicious", "Confidence Score"])

        # Process the rest of the rows
        for row in reader:
            total_ips += 1  # Increase the total IPs counter

            # The IP address is in the ip_index column
            ip_address = row[ip_index]

            # The parameters for the API request
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }

            # The headers for the API request
            headers = {
                'Accept': 'application/json',
                'Key': api_key
            }

            # Make the API request
            response = requests.get(url, headers=headers, params=params)

            # Parse the JSON response
            data = json.loads(response.text)

            # Check if the 'data' key exists in the dictionary, and if 'abuseConfidenceScore' exists in the 'data' dictionary
            if 'data' in data and 'abuseConfidenceScore' in data['data']:
                # Check if the IP address is malicious
                if data['data']['abuseConfidenceScore'] > 0:
                    malicious_ips += 1  # Increase the malicious IPs counter
                    print(f"IP: {ip_address} is malicious with score: {data['data']['abuseConfidenceScore']}")
                    writer.writerow([ip_address, "Yes", data['data']['abuseConfidenceScore']])
                else:
                    legit_ips += 1  # Increase the legit IPs counter

            else:
                print(f"Unexpected response for IP {ip_address}: {data}")
                
# After processing all rows, print the statistics
print("\n" + "="*50)
print("IP Address Analysis Complete".center(50))
print("="*50)
print(f"\nTotal IPs Processed: {total_ips}")
print(f"Legit IPs: {legit_ips}")
print(f"Malicious IPs: {malicious_ips}")

# Calculate and print ratios
if total_ips > 0:
    print(f"Ratio of Legit IPs: {legit_ips / total_ips * 100:.2f}%")
    print(f"Ratio of Malicious IPs: {malicious_ips / total_ips * 100:.2f}%")
else:
    print("No IPs Processed, Ratios Cannot be Calculated.")

print("\n" + "="*50)
