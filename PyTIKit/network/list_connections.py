import platform
import subprocess

# Function to list network connections on Windows and Linux
def list_network_connections():
    try:
        # Checking for the platform the program is being run on, if Linux excute this
        if platform.system() == "Linux":
            try: 
                command_ss = "ss -tup state established"
                output = subprocess.run(command_ss,shell=True,text=True,capture_output=True)
                print(output.stdout)
                with open('NetworkConnections_Report.txt', 'w') as report_file:
                    report_file.write(output.stdout)
            # Exception handling
            except subprocess.CalledProcessError:
                print("Failed to get network connections.")
            
        # Checking for the platform the program is being run on, if Windows excute this    
        elif platform.system() == "Windows": 
            try:
                # Create the netstat command
                command_netstat = ["netstat", "-b"]
                # Execute the command and capture the output as text
                output = subprocess.run(command_netstat, shell=True, text=True, capture_output=True)
                # Print the output for the user
                print(output.stdout)
                # Write the information to a file
                with open('NetworkConnections_Report.txt', 'w') as report_file:
                    report_file.write(output.stdout)
            except subprocess.CalledProcessError:
                print("Failed to get network connections.")
        # If unsupported platform, let user know
        else:
            print("Unsupported platform.")
            return
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None
