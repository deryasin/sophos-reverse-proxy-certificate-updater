# Sophos Speedy Reverse Proxy Certificate Updater 

This script is designed to help all the unfortunate admins who have to manage a Sophos firewall and use (or are forced to use) the Reverse Proxy. 
It will fetch firewall rules from a file or an API, check for certificates, and update certificates only for rules that have a specific "old certificate" value. The script also lists the rules that already have the new certificate.

The script automates the tedious process of updating certificates, turning what would typically be 2 hours of manual labor (depending on the number of entries) 
into just 15 minutes of watching the shell. 
Don't forget that Sophos hardcodes a maximum of 50 (55) active entries ;) 

## Features

- **Interactive Mode**: Prompts for user input if `-i` is provided, including firewall credentials, IP, port, and certificates.
- **Non-Interactive Mode**: Accepts all required inputs as command-line arguments.
- **Fetch Firewall Rules**: Can fetch firewall rules either from an API or from a local XML file.
- **Filter Rules**: Filters and lists rules that:
  - Already have the new certificate.
  - Have the old certificate and are candidates for updating.
- **Confirmation**: Asks for user confirmation before updating the rules.
- **Update Firewall Rules**: Sends an update request to the API, replacing the old certificate with the new one.

## Prerequisites

Ensure you have the following installed:

- **Python 3.x**
- The following Python packages (install via `pip`):
  ```bash
  pip install requests
  ```

## Usage

### 1. Clone the Repository

```bash
git clone https://github.com/deryasin/sophos-reverse-proxy-certificate-updater.git
cd sophos-reverse-proxy-certificate-updater
```

### 2. Run the Script

You can run the script either in **interactive mode** or **non-interactive mode**.

---

### Interactive Mode

Run the script with the `-i` flag to enable interactive mode, where you will be prompted to input the necessary values:

```bash
python main.py -i
```

You will be asked to provide the following information:

- Firewall Username
- Firewall Password (input hidden)
- Firewall IP address
- Firewall Port (default: 4444)
- Old Certificate (the certificate to be replaced)
- New Certificate (the certificate to replace the old one)

For example:

```
Enter the firewall username: admin
Enter the firewall password: ********
Enter the firewall IP address: 192.168.1.1
Enter the firewall port (default 4444): 4444
Enter the old certificate: old-cert
Enter the new certificate: new-cert
Do you want to fetch the firewall rules from the API or file? (api/file): api
```

### Non-Interactive Mode

Alternatively, you can pass the necessary parameters via command-line arguments:

```bash
python script.py --username admin --password password123 --firewall-ip 192.168.1.1 --firewall-port 4444 --old-cert old-cert --new-cert new-cert
```

### Options and Arguments

- `-i, --interactive`: Enable interactive mode to input all variables interactively.
- `--username`: The firewall admin username.
- `--password`: The firewall admin password.
- `--firewall-ip`: The IP address of the firewall.
- `--firewall-port`: The port used to connect to the firewall (default: 8443).
- `--old-cert`: The old certificate value to search for and replace.
- `--new-cert`: The new certificate value to update.

### Sample Command (Non-Interactive Mode)

```bash
python main.py --username admin --password password123 --firewall-ip 192.168.1.1 --firewall-port 8443 --old-cert old-cert --new-cert new-cert
```

### Output

The script will first list the firewall rules that already have the new certificate, followed by the rules that have the old certificate. It will then ask for confirmation before proceeding to update those rules.

Example output:

```
The following firewall rules already have the new certificate:
 - TestRule1

The following firewall rules with the old certificate will be updated:
 - TestRule2
 - TestRule3

Do you want to proceed with updating these rules? (yes/no): yes

Updated: TestRule2 - Certificate changed to new-cert
Status Code: 200
Response: <API response>

Updated: TestRule3 - Certificate changed to new-cert
Status Code: 200
Response: <API response>
```

### Fetching Firewall Rules

When prompted to choose where to fetch the firewall rules from, you can select either:

- `api`: Fetch rules from the firewall API.
- `file`: Load firewall rules from a local XML file (`firewall_rules.xml`).

### Error Handling

If the required parameters are missing or incorrect, the script will print an error message and exit. Make sure to provide valid credentials, IP addresses, and certificates.

---

## License

This project is licensed under the GPL License.

---

## Author

- **Yasin Tikdemir
- GitHub: [@deryasin](https://github.com/deryasin)
