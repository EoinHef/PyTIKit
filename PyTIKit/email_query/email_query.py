from emailrep import EmailRep
from email_query import apikey
import colours

def query_email(email):
    # Create client
    emailrep = EmailRep(apikey.EMAIL_REP_KEY)
    # Return the result of the query function for the email entered
    return emailrep.query(email)

def parse_email_report(report):
    try:    
        # Write report to txt file
        with open("Email_Rep_Query.txt", "w") as report_file:
            report_file.write("Email Address Report:\n")
            report_file.write("Email Queried: " + report["email"] + "\n")
            report_file.write("Reputation: " + report['reputation'] + "\n")
            report_file.write("Suspicious: " + str(report['suspicious']) + "\n")
            report_file.write("References: " + str(report['references']) + "\n")
            report_file.write("Reputation: " + report['reputation'] + "\n")
            report_file.write("Suspicious: " + str(report['suspicious']) + "\n")
            report_file.write("References: " + str(report['references']) + "\n")
            report_file.write("Blacklisted: " + str(report['details']['blacklisted']) + "\n")
            report_file.write("Malicious Activity: " + str(report['details']['malicious_activity']) + "\n")
            report_file.write("Credentials Leaked: " + str(report['details']['credentials_leaked']) + "\n")
            report_file.write("Data Breach: " + str(report['details']['data_breach']) + "\n")
            report_file.write("First Seen: " + report['details']['first_seen'] + "\n")
            report_file.write("Last Seen: " + report['details']['last_seen'] + "\n")
            report_file.write("Domain Exists: " + str(report['details']['domain_exists']) + "\n")
            report_file.write("Domain Reputation: " + report['details']['domain_reputation'] + "\n")
            report_file.write("Summary:\n")
            report_file.write(report['summary'] + "\n")

        # Print the report for the user
        print(f"{colours.BOLD}{colours.GREEN}Email Address Report:{colours.RESET}")
        print(f"{colours.BOLD}{colours.GREEN}Email Queried: {colours.RESET}" + report["email"])
        print(f"{colours.BOLD}{colours.GREEN}Reputation: {colours.RESET}" + report['reputation'])
        print(f"{colours.BOLD}{colours.GREEN}Suspicious: {colours.RESET}" + str(report['suspicious']))
        print(f"{colours.BOLD}{colours.GREEN}References: {colours.RESET}" + str(report['references']))
        print(f"{colours.BOLD}{colours.GREEN}Reputation: {colours.RESET}" + report['reputation'])
        print(f"{colours.BOLD}{colours.GREEN}Suspicious: {colours.RESET}" + str(report['suspicious']))
        print(f"{colours.BOLD}{colours.GREEN}References: {colours.RESET}" + str(report['references']))
        print(f"{colours.BOLD}{colours.GREEN}Blacklisted: {colours.RESET}" + str(report['details']['blacklisted']))
        print(f"{colours.BOLD}{colours.GREEN}Malicious Activity: {colours.RESET}" + str(report['details']['malicious_activity']))
        print(f"{colours.BOLD}{colours.GREEN}Credentials Leaked: {colours.RESET}" + str(report['details']['credentials_leaked']))
        print(f"{colours.BOLD}{colours.GREEN}Data Breach: {colours.RESET}" + str(report['details']['data_breach']))
        print(f"{colours.BOLD}{colours.GREEN}First Seen: {colours.RESET}" + report['details']['first_seen'])
        print(f"{colours.BOLD}{colours.GREEN}Last Seen: {colours.RESET}" + report['details']['last_seen'])
        print(f"{colours.BOLD}{colours.GREEN}Domain Exists: {colours.RESET}" + str(report['details']['domain_exists']))
        print(f"{colours.BOLD}{colours.GREEN}Domain Reputation: {colours.RESET}" + report['details']['domain_reputation'])
        print(f"{colours.BOLD}{colours.GREEN}Summary:{colours.RESET}")
        print(report['summary'])
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None