# PyTIKit
A comprehensive python tool for threat intelligence and local file operations

# Functions:
Query URL with Virus Total <br />
Query Email address with Emailrep.io <br />
Query Domains with Virus Total <br />
Query IP Address with Virus Total <br />
Geo Locate IP address with GeoCoder and IPInfo <br />
Scan File Sytem for hashes and query hashes with NSRL DB & Virus Total <br />
File Metadata Extraction <br />
View inforamtion about running processes <br />
Log Analysis (Windows: Account Creation, Linux: Successful SSH connections & Account Creation) <br />
Command Log - View command history on Linux <br />
Section Hashing - imphash and rich PE hash <br />
Network Traffic - Analyse a hosts nwtwrok traffic  <br />
Reporting - Generate reports based on findings <br />

# Install dependancies
pip install -r requirements.txt <br />

# Add your API keys for Virus Total and Emailrep.io
Virus Total: Add in - PyTIKit/vt_ip_url_domain_query/apikey.py & /PyTIKit/malware_scanner/vt_hashlookup.py<br />
EmailRep.io: Add in - PyTIKit/email_query/apikey.py <br />

# Usage
Linux: <br />
From the application root directory run the following command: <br />
sudo python3 app.py <br />

Windows: <br />
Start command prompt with admin privileges, from application root directory run the following command: <br />
python3 app.py <br />
