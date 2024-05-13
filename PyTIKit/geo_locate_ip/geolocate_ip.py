import geocoder
import colours

# Function to get GeoLocation data on an IP address
def get_ip_geolocation(ip):
    try:
        # Query the IP
        result = geocoder.ipinfo(ip)
        # Print the result of the query
        print(f"{colours.BOLD}{colours.GREEN}IP Address Queried:{colours.RESET}  {result.ip}\n"
            f"{colours.BOLD}{colours.GREEN}Country:{colours.RESET} {result.country}\n"
            f"{colours.BOLD}{colours.GREEN}Region:{colours.RESET} {result.state}\n"
            f"{colours.BOLD}{colours.GREEN}City:{colours.RESET} {result.city}\n"
            f"{colours.BOLD}{colours.GREEN}Location:{colours.RESET} {result.latlng}\n"
            f"{colours.BOLD}{colours.GREEN}Organisation:{colours.RESET} {result.org}\n"
            f"{colours.BOLD}{colours.GREEN}Postal:{colours.RESET} {result.postal}"
            )
        # Add the data to the report file
        with open("GeoLocate_IP_Query.txt", "w", encoding="utf-8")as report:
            report.write(f"IP Address queried: {ip}\n"
                        f"Country: {result.country}\n"
                        f"Region: {result.state}\n"
                        f"City: {result.city}\n"
                        f"Location: {result.latlng}\n"
                        f"Organisation: {result.org}\n"
                        f"Postal: {result.postal}"
            )
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None    