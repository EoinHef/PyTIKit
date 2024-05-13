import requests
import colours
from vt_ip_url_domain_query import apikey

# Function to query a domain via virus total
def query_domain_virustotal(domain):
    try:
        # Base URL for API to query Virsu Total API for a domain
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        # Request headers to be added to the request
        headers = {
            "Accept": "application/json",
            "x-apikey": apikey.VT_API_KEY
        } 
        # Make the request and store the result in the response variable
        response = requests.get(url, headers=headers)
        # Debugging, print the response code from the API incase of errors
        print(f"{colours.BOLD}{colours.BLUE}API Response Code: {colours.RESET}" + str(response.status_code))
        # If response code is 200, successful request made 
        if response.status_code == 200:
            # Convert respone to json format
            report = response.json()
            # Return the report
            return report
        else:
            print("Error during query")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None
 
# Function to parse the return for output to screen       
def parse_domain_report(report):
    if report:
        domain = report["data"]["id"]
        # Print data for the user
        print(f"{colours.BOLD}{colours.GREEN}Link to VT report: {colours.RESET}https://www.virustotal.com/gui/domain/{domain}")
        print(f"{colours.BOLD}{colours.GREEN}Latest Scan Harmless Votes: {colours.RESET}" + str(report["data"]["attributes"]["last_analysis_stats"]["harmless"]))
        print(f"{colours.BOLD}{colours.GREEN}Latest Scan Malicious Votes: {colours.RESET}" + str(report["data"]["attributes"]["last_analysis_stats"]["malicious"]))  
    
         # Write data to text file
        with open("Domain_Query_Report.txt", "w") as report_file:
            report_file.write(f"Link to VT report: https://www.virustotal.com/gui/domain/{domain}\n")
            report_file.write("Latest Scan Harmless Votes: " + str(report["data"]["attributes"]["last_analysis_stats"]["harmless"]) + "\n")
            report_file.write("Latest Scan Malicious Votes: " + str(report["data"]["attributes"]["last_analysis_stats"]["malicious"]) + "\n")
            print("Report written to Domain_Query_Report.txt")
    
    else:
        print("Report contains no data!!")