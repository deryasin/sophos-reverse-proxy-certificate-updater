"""
####################################################
# Script Name: Sophos Speedy Reverse Proxy Certificate Updater (SSRPCU)
# Author: Yasin Tikdemir
# Contact: yasin@tikdemir.net
# Date: 07.10.2024
#
# Description:
# This script is designed to help all the unfortunate admins who have to manage a Sophos firewall and use (or are forced to use) the Reverse Proxy. 
# The script automates the tedious process of updating certificates, turning what would typically be 2 hours of manual labor (depending on the number of entries) 
# into just 15 minutes of watching the shell. 
# Don't forget that Sophos hardcodes a maximum of 50 (55) active entries ;) 
#
# License:
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2024 Yasin Tikdemir
####################################################
"""

import xml.etree.ElementTree as ET
import requests
import urllib3
import argparse
import getpass  # For hidden password input

# Disable insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_firewall_rules_from_api(username, password, firewall_ip, firewall_port):
    """Fetch firewall rules from the API."""
    print("Fetching firewall rules from the API...")
    # Define the API endpoint
    api_url = f'https://{firewall_ip}:{firewall_port}/webconsole/APIController'

    # Build the request body to fetch firewall rules
    reqxml = f"""
    <Request>
        <Login>
            <Username>{username}</Username>
            <Password>{password}</Password>
        </Login>
        <Get>
            <FirewallRule></FirewallRule>
        </Get>
    </Request>
    """

    # Send the POST request using form-data (multipart/form-data)
    files = {
        'reqxml': (None, reqxml)  # The key is 'reqxml', and the value is the XML request body
    }

    response = requests.post(api_url, files=files, verify=False)

    # Print the response for debugging
    print(f"API Response Status Code: {response.status_code}")
    #print(f"API Response Content: {response.text}")  # Print response content

    if response.status_code == 200 and response.text.strip():
        # Parse the XML response
        response_xml = response.text
        print("Successfully fetched firewall rules from API.")
        # Extract the FirewallRules from the response
        root = ET.fromstring(response_xml)
        return root.findall('FirewallRule')
    else:
        print(f"Failed to fetch rules from API. Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        exit()


def load_firewall_rules_from_file(file_path='firewall_rules.xml'):
    """Load firewall rules from a local file."""
    print("Loading firewall rules from file...")
    with open(file_path, 'r') as file:
        xml_data = file.read()

    # Parse the XML
    root = ET.fromstring(xml_data)
    return root.findall('FirewallRule')


def filter_firewall_rules_with_old_certificate(firewall_rules, old_certificate):
    """Filter firewall rules that have the old certificate."""
    filtered_rules = []
    for firewall_rule in firewall_rules:
        certificate = firewall_rule.find('HTTPBasedPolicy/Certificate')
        if certificate is not None and certificate.text == old_certificate:
            filtered_rules.append(firewall_rule)
    return filtered_rules


def list_and_confirm_firewall_rules(filtered_rules):
    """List firewall rules and ask for user confirmation to update them."""
    if filtered_rules:
        print("The following firewall rules with the old certificate will be updated:")
        for rule in filtered_rules:
            rule_name = rule.find('Name').text if rule.find('Name') is not None else "Unnamed Rule"
            print(f" - {rule_name}")

        # Ask for user confirmation
        confirm = input("Do you want to proceed with updating these rules? (yes/no): ").strip().lower()
        return confirm == 'yes'
    else:
        print("No firewall rules with the old certificate found.")
        return False


def update_firewall_rules(filtered_rules, username, password, new_certificate, api_url):
    """Update firewall rules and send POST requests."""
    for rule in filtered_rules:
        rule_name = rule.find('Name').text if rule.find('Name') is not None else "Unnamed Rule"

        # Update the certificate to the new value
        rule.find('HTTPBasedPolicy/Certificate').text = new_certificate

        # Convert the updated <FirewallRule> back into an XML string
        firewall_rule_xml = ET.tostring(rule, encoding='unicode')

        # Construct the full XML payload with login and Set operation
        reqxml = f"""
        <Request>
            <Login>
                <Username>{username}</Username>
                <Password>{password}</Password>
            </Login>
            <Set operation="update">
                {firewall_rule_xml}
            </Set>
        </Request>
        """

        # Send the POST request in form-data format, ignoring SSL cert verification
        files = {'reqxml': (None, reqxml)}
        response = requests.post(api_url, files=files, verify=False)

        # Handle the response
        print(f"Updated: {rule_name} - Certificate changed to {new_certificate}")
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}\n")


def get_args():
    """Get command line arguments."""
    parser = argparse.ArgumentParser(description="Update firewall rules via API or file.")
    parser.add_argument('-i', '--interactive', action='store_true', help="Enable interactive mode to input variables")
    parser.add_argument('--username', type=str, help="Firewall username")
    parser.add_argument('--password', type=str, help="Firewall password")
    parser.add_argument('--firewall-ip', type=str, help="Firewall IP address")
    parser.add_argument('--firewall-port', type=str, default="8443", help="Firewall port (default: 8443)")
    parser.add_argument('--old-cert', type=str, help="Old certificate to replace")
    parser.add_argument('--new-cert', type=str, help="New certificate to set")
    return parser.parse_args()


def main():
    # Get command line arguments
    args = get_args()

    # Interactive mode: ask for variables
    if args.interactive:
        username = input("Enter the firewall username: ")
        # Use getpass to hide password input
        password = getpass.getpass("Enter the firewall password: ")
        firewall_ip = input("Enter the firewall IP address: ")
        firewall_port = input("Enter the firewall port (default 4444): ") or "4444"
        old_certificate = input("Enter the old certificate: ")
        new_certificate = input("Enter the new certificate: ")
    else:
        # Non-interactive mode: use provided command-line arguments
        username = args.username
        password = args.password
        firewall_ip = args.firewall_ip
        firewall_port = args.firewall_port
        old_certificate = args.old_cert
        new_certificate = args.new_cert

        # Check that all required arguments are provided
        if not all([username, password, firewall_ip, old_certificate, new_certificate]):
            print("Error: Missing required arguments. Use -i for interactive mode or provide all necessary arguments.")
            exit()

    # Ask the user where to fetch the firewall rules from
    fetch_source = input("Do you want to fetch the firewall rules from the API or file? (api/file): ").strip().lower()

    if fetch_source == 'api':
        firewall_rules = fetch_firewall_rules_from_api(username, password, firewall_ip, firewall_port)
    elif fetch_source == 'file':
        firewall_rules = load_firewall_rules_from_file()
    else:
        print("Invalid input. Please choose either 'api' or 'file'.")
        exit()

    # Filter firewall rules that have the old certificate
    filtered_rules = filter_firewall_rules_with_old_certificate(firewall_rules, old_certificate)

    # List and confirm the firewall rules to be updated
    if list_and_confirm_firewall_rules(filtered_rules):
        # If the user confirms, update the rules
        api_url = f'https://{firewall_ip}:{firewall_port}/webconsole/APIController'
        update_firewall_rules(filtered_rules, username, password, new_certificate, api_url)
    else:
        print("No updates were made.")


if __name__ == '__main__':
    main()


