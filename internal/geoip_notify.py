#!/usr/bin/python3.9
"""
Fail2ban UI - A Swiss made, management interface for Fail2ban.

Copyright (C) 2025 Swissmakers GmbH

Licensed under the GNU General Public License, Version 3 (GPL-3.0)
You may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.gnu.org/licenses/gpl-3.0.en.html

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

# This file is for testing purposes only.
# (Must be copied to "/etc/fail2ban/action.d/geoip_notify.py")
#python3.9 -c "import maxminddb; print('maxminddb is installed successfully')"

import sys
import subprocess

# Manually set Python path where maxminddb is installed
sys.path.append("/usr/local/lib64/python3.9/site-packages/")

try:
    import maxminddb
except ImportError:
    print("Error: maxminddb module not found, even after modifying PYTHONPATH.")
    sys.exit(1)


# Path to MaxMind GeoIP2 database
GEOIP_DB_PATH = "/usr/share/GeoIP/GeoLite2-Country.mmdb"

def get_country(ip):
    """
    Perform a GeoIP lookup to get the country code from an IP address.
    Returns the country code (e.g., "CH") or None if lookup fails.
    """
    try:
        with maxminddb.open_database(GEOIP_DB_PATH) as reader:
            geo_data = reader.get(ip)
            if geo_data and "country" in geo_data and "iso_code" in geo_data["country"]:
                return geo_data["country"]["iso_code"]
    except Exception as e:
        print(f"GeoIP lookup failed: {e}", file=sys.stderr)
    return None

def parse_placeholders(placeholder_str):
    """
    Parses Fail2Ban placeholders passed as a string in "key=value" format.
    Returns a dictionary.
    """
    placeholders = {}
    for item in placeholder_str.split(";"):
        key_value = item.split("=", 1)
        if len(key_value) == 2:
            key, value = key_value
            placeholders[key.strip()] = value.strip()
    return placeholders

def send_email(placeholders):
    """
    Generates and sends the email alert using sendmail.
    """
    email_content = f"""Subject: [Fail2Ban] {placeholders['name']}: banned {placeholders['ip']} from {placeholders['fq-hostname']}
Date: $(LC_ALL=C date +"%a, %d %h %Y %T %z")
From: {placeholders['sendername']} <{placeholders['sender']}>
To: {placeholders['dest']}

Hi,

The IP {placeholders['ip']} has just been banned by Fail2Ban after {placeholders['failures']} attempts against {placeholders['name']}.

Here is more information about {placeholders['ip']}:
{subprocess.getoutput(placeholders['_whois_command'])}

Lines containing failures of {placeholders['ip']} (max {placeholders['grepmax']}):
{subprocess.getoutput(placeholders['_grep_logs'])}

Regards,
Fail2Ban"""

    try:
        subprocess.run(
            ["/usr/sbin/sendmail", "-f", placeholders["sender"], placeholders["dest"]],
            input=email_content,
            text=True,
            check=True
        )
        print("Email sent successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to send email: {e}", file=sys.stderr)

def main(ip, allowed_countries, placeholder_str):
    """
    Main function to check the IP's country and send an email if it matches the allowed list.
    """
    allowed_countries = allowed_countries.split(",")
    placeholders = parse_placeholders(placeholder_str)

    # Perform GeoIP lookup
    country = get_country(ip)
    if not country:
        print(f"Could not determine country for IP {ip}", file=sys.stderr)
        sys.exit(1)

    print(f"IP {ip} belongs to country: {country}")

    # If the country is in the allowed list or "ALL" is selected, send the email
    if "ALL" in allowed_countries or country in allowed_countries:
        print(f"IP {ip} is in the alert countries list. Sending email...")
        send_email(placeholders)
    else:
        print(f"IP {ip} is NOT in the alert countries list. No email sent.")
        sys.exit(0)  # Exit normally without error

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: geoip_notify.py <ip> <allowed_countries> <placeholders>", file=sys.stderr)
        sys.exit(1)

    ip = sys.argv[1]
    allowed_countries = sys.argv[2]
    placeholders = sys.argv[3]

    main(ip, allowed_countries, placeholders)
