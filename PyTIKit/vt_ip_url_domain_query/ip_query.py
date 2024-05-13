import requests
from vt_ip_url_domain_query import apikey
import colours

# Function to query an IP address
def query_ip_virustotal(ip):
    try:
        # URL to query the Virus Total API for IP address
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
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
    
def parse_ip_report(report):
    try:
        # If the report contains data print the following
        if report:
            ip = report["data"]["id"]
            print(f"{colours.BOLD}{colours.GREEN}Report for IP: {colours.RESET}" + ip)
            print(f"{colours.BOLD}{colours.GREEN}Link to VT report:{colours.RESET} https://www.virustotal.com/gui/ip-address/{ip}")
            print(f"{colours.BOLD}{colours.GREEN}AS Owner: {colours.RESET}"+ report["data"]["attributes"]["as_owner"])
            print(f"{colours.BOLD}{colours.GREEN}Country of origin: {colours.RESET}" + report["data"]["attributes"]["country"])
            print(f"{colours.BOLD}{colours.GREEN}Malicous Detections: {colours.RESET}" + str(report["data"]["attributes"]["last_analysis_stats"]["malicious"]))
            print(f"{colours.BOLD}{colours.GREEN}Suspicious Detections: {colours.RESET}" + str(report["data"]["attributes"]["last_analysis_stats"]["suspicious"]))
            print(f"{colours.BOLD}{colours.GREEN}Harmless Votes: {colours.RESET}" + str(report["data"]["attributes"]["total_votes"]["harmless"]))
            print(f"{colours.BOLD}{colours.GREEN}Malicious Votes: {colours.RESET}" + str(report["data"]["attributes"]["total_votes"]["malicious"]))
            if report["data"]["attributes"]["whois"]:
                print(f"*"*50)
                print(f"{colours.BOLD}{colours.GREEN}Whois data:{colours.RESET} \n" + report["data"]["attributes"]["whois"])
                print(f"*"*50)
                
            # Write data to text file
            with open("IP_Query_Report.txt", "w") as report_file:
                report_file.write("Report for IP: " + report["data"]["id"] + "\n")
                report_file.write(f"Link to VT report: https://www.virustotal.com/gui/ip-address/{ip}\n")
                report_file.write("AS Owner: " + report["data"]["attributes"]["as_owner"] + "\n")
                report_file.write("Country of origin: " + report["data"]["attributes"]["country"] + "\n")
                report_file.write("Malicous Detections: " + str(report["data"]["attributes"]["last_analysis_stats"]["malicious"]) + "\n")
                report_file.write("Suspicious Detections: " + str(report["data"]["attributes"]["last_analysis_stats"]["suspicious"]) + "\n")
                report_file.write("Harmless Votes: " + str(report["data"]["attributes"]["total_votes"]["harmless"]) + "\n")
                report_file.write("Malicious Votes: " + str(report["data"]["attributes"]["total_votes"]["malicious"]) + "\n")
                if report["data"]["attributes"]["whois"]:
                    report_file.write("*"*50 + "\n")
                    report_file.write("Whois data:\n" + report["data"]["attributes"]["whois"] + "\n")
                    report_file.write("*"*50 + "\n")
                print("Report written to IP_Query_Report.txt")
        # If the report does not contain data let the user know
        else:
            print("Report contains no data!!")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None
    