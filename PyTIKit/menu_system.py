from vt_ip_url_domain_query.ip_query import *
from vt_ip_url_domain_query.domain_query import *
from vt_ip_url_domain_query.apikey import *
from vt_ip_url_domain_query.url_query import *
from command_history.disply_history import *
from geo_locate_ip.geolocate_ip import *
from network.list_connections import *
from metadata.metadata import *
from malware_scanner.query_hashes_nsrl import *
from malware_scanner.scanner import *
from malware_scanner.vt_hashlookup import *
from malware_scanner.query_report import *
from geo_locate_ip import *
from email_query.email_query import *
from command_history import *
from log_analysis import *
from processes.processes import *
from log_analysis.ssh_connections import *
from log_analysis.account_creation import *
from section_hashing.section_hashing import *
import platform
import colours

# Function to display amlware scanner menu options
def malware_scanner_menu():
    # While loop as guard
    while True:
        print("1. Scan File System")
        print("2. Printed currently stored filepaths and file hashes")
        print("3. Query NSRL DB")
        print("4. Query VirusTotal")
        print("5. Write Report")
        print("6. Return to file analysis menu")
        # Handle errors
        try:
            # Capture user input and return choice if in range
            choice = int(input("Select an option: "))
            if 1 <= choice <= 6:
                return choice
            # Let the user know that selceted value not in range
            else:
                print("Invalid choice. Please choose a number between 1 and 6.") 
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 6.")
 
# Function to display section hashing menu options            
def section_hashing_menu():
    
    pass

# Main menu of program
def main_menu():
    while True:
        print(f"\n{colours.BOLD}{colours.GREEN}Main Menu:{colours.RESET}")
        print("1. File Analysis")
        print("2. Online Queries")
        print("3. Netowork Monitoring")
        print("4. Host Analysis")
        print("5. Log Analysis")
        print("6. Quit")
        choice = input("Enter your choice: ")

        # Sub menu options
        if choice == '1':
            submenu_1()
        elif choice == '2':
            submenu_2()
        elif choice == '3':
            submenu_3()
        elif choice == '4':
            submenu_4()
        elif choice == '5':
            submenu_5()
        # Exit the program if 6 selected
        elif choice == '6':
            print("Quitting the program.")
            break
        # Validate input
        else:
            print("Invalid choice. Please try again.")

# Sub menu 1 for File Analysis functions
def submenu_1():
    # While loop
    while True:
        print(f"\n{colours.BOLD}{colours.GREEN}File Analysis Menu:{colours.RESET}")
        print("1. Malware Scanner")
        print("2. See file metadata")
        print("3. Section Hashing")
        print("4. Go back to Main Menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            print("You selected Option: Malware Scanner")
            # Create empty dictionary to store file hashes and later, the return for malicious files from Virus Total
            hashes = {}
            # While loop for menu
            while True:
                # Get user input
                choice = malware_scanner_menu()
                if choice == 1:
                    print("Scan the file system selected")
                    # Get the root directory from the user as input
                    root_dir = input("Enter the root directory of the filesystem you want to scan: ")
                    # Update the hashes dictionary with the return from the scan_filesystem function
                    hashes = scan_filesystem(root_dir)
                elif choice == 2:
                    # Print the hashes currently in dictionary
                    print("Printing currently stored filepaths and file hashes")
                    print_hashes(hashes)
                elif choice == 3:
                    # Check to see if program running on Windows
                    if  platform.system() == "Windows":
                        # Let user knwo function not working on Windows
                        print("Apologies, this function is currently BROKEN on Windows")
                    else:
                        # Any other OS, call the function
                        print("Querying NSRL RDS via CIRCL")
                        hashes = query_circl(hashes)
                elif choice == 4:
                    # Query Virus total with hashes in dictionary
                    print("Query Virus Total")
                    hashes = query_vt(hashes)
                elif choice == 5:
                    # Write a report to file 
                    print("Write report selected")
                    write_report(hashes)
                elif choice == 6:
                    print("Returning to File Analysis Menu")
                    # Break the loop if option 5 selected
                    break
        elif choice == '2':
            print("You selected Option: See file metadata")
            # Get user input
            file_path = input("Enter the path to the file: ")
            # Pass file path to function
            print_file_metadata(file_path)
        elif choice == '3':
            print("You selected Option: Section Hashing")
            # Get user inout   
            path_to_exe = input("Please enter the path to the PE to obtain hashes: ")
            try:
                # Call hash extracting function
                md5_hash = get_md5_hash(path_to_exe)
                sha1_hash = get_sha1_hash(path_to_exe)
                sha256_hash = get_sha256_hash(path_to_exe)
                sha512_hash = get_sha512_hash(path_to_exe)
                imphash = get_imp_hash(path_to_exe)
                richheader_hash = get_richheader_hash(path_to_exe)
                # Store the filname and hashes in a file
                store_hashes(path_to_exe, md5_hash, sha1_hash, sha256_hash, sha512_hash, imphash, richheader_hash)
            except Exception as error:
                print(f"Error: {error}")             
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")            

def submenu_2():
    while True:
        print(f"\n{colours.BOLD}{colours.GREEN}Online Queries Menu:{colours.RESET}")
        print("1. Query IP address")
        print("2. Query URL")
        print("3. Query Domain")
        print("4. Query Email address")
        print("5. Geo Locate IP Address")
        print("6. Return to main menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            print("You selected Option: Query IP address")
            # Get user input IP address
            ip_address = input("Enter the IP address to query: ")
            # Pass IP to qury function
            ip_info = query_ip_virustotal(ip_address)  # Query VirusTotal for IP information
            # Parse return from VT API
            parse_ip_report(ip_info)
        elif choice == '2':
            print("You select Option: Query URL")
            # Get user to input the URL
            url = input("Enter URL to be queried: ")
            # Query the URL with Virus total
            url_info = query_url_virustotal(url)
            # Parse and print the URL data
            parse_url_report(url_info)
        elif choice == '3':
            print("You select Option: Query Domain")
            # Get user input domain    
            domain = input("Enter the domain to query: ")
            # Pass domain to qury function
            domain_info = query_domain_virustotal(domain)  
            # Print the domain info
            if domain_info:
                parse_domain_report(domain_info)
        elif choice == '4':
            print("You select Option: Query Email Address")
            # Get user input email address
            email_address = input("Enter the Email address to query: ")
            result = query_email(email_address)
            parse_email_report(result)
        elif choice == '5':
            print("You select Option: Geo Locate IP Address")
            ip = input("Enter IP address:")
            get_ip_geolocation(ip)
        elif choice == '6':
            break
        else:
            print("Invalid choice. Please try again.")

def submenu_3():
    while True:
        print(f"\n{colours.BOLD}{colours.GREEN}Network Monitoring Menu:{colours.RESET}")
        print("1. List Network Connections")
        print("2. Go back to Main Menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            print("You selected Option: List Network Connections")
            list_network_connections()
        elif choice == '2':
            break
        else:
            print("Invalid choice. Please try again.")
            
def submenu_4():
    while True:
        print(f"\n{colours.BOLD}{colours.GREEN}Host Analysis Menu:{colours.RESET}")
        print("1. View Running Processes")
        print("2. View Linux Command History")
        print("3. Go back to Main Menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            print("You selected Option: View Running Processes")
            # Get the user to enter username to see all that usernames processes
            username = input("Enter username to target(Leave blank for all processes): ")
            view_processes(username)
        elif choice == '2':
            print("You selected Option: View Linux Command History")
            view_linux_cmd_history()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

def submenu_5():
    while True:
        print(f"\n{colours.BOLD}{colours.GREEN}Log Analysis Menu:{colours.RESET}")
        print("1. View Successful SSH Connections")
        print("2. View Account Creations")
        print("3. Go back to Main Menu")
        choice = input("Enter your choice: ")

        if choice == '1':
            print("You selected Option: View Successful SSH Connections")
            ssh_sessions()
        elif choice == '2':
            print("You selected Option: View Account Creations")
            user_creation()
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")