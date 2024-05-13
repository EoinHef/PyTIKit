import psutil
import colours

def view_processes(username):
    # Exception Handling
    try:
        # Open the report file in write mode
        with open("Processes_Report.txt", 'w') as report_file:
            # Iterator that accesses the running processes on a computer
            for process in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'exe', 'status']):
                # Check if username was entered
                if username:
                    # If username was entered, print only processes with that username
                    if username == process.info['username']:
                        # Format and write the process information to the report file
                        report_file.write(f"PID: {process.info['pid']}\n"
                                           f"  PPID: {process.info['ppid']}\n"
                                           f"  Username: {process.info['username']}\n"
                                           f"  Process Name: {process.info['name']}\n"
                                           f"  Execute Path: {process.info['exe']}\n"
                                           f"  Status: {process.info['status']}\n\n")
                        # Print the process information to the console
                        print(f"{colours.BOLD}{colours.GREEN}PID: {process.info['pid']}{colours.RESET}\n"  
                              f"  PPID: {process.info['ppid']}\n"  
                              f"  Username: {process.info['username']}\n"  
                              f"  Process Name: {process.info['name']}\n"  
                              f"  Execute Path: {process.info['exe']}\n"
                              f"  Status: {process.info['status']}")
                # If no username entered, print all processes
                else:
                    # Format and write the process information to the report file
                    report_file.write(f"PID: {process.info['pid']}\n"
                                       f"  PPID: {process.info['ppid']}\n"
                                       f"  Username: {process.info['username']}\n"
                                       f"  Process Name: {process.info['name']}\n"
                                       f"  Execute Path: {process.info['exe']}\n"
                                       f"  Status: {process.info['status']}\n\n")
                    # Print the process information to the console
                    print(f"{colours.BOLD}{colours.GREEN}PID: {process.info['pid']}{colours.RESET}\n"  
                          f"  PPID: {process.info['ppid']}\n"  
                          f"  Username: {process.info['username']}\n"  
                          f"  Process Name: {process.info['name']}\n"  
                          f"  Execute Path: {process.info['exe']}\n"
                          f"  Status: {process.info['status']}")

        print(f"Process information written to Processes_Report.txt")
    # Handle exception
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")


