import subprocess
import platform
import colours

def user_creation():
    try:
        if platform.system() == 'Linux':
            # Building the command and running with the subprocess module, also capturing the output
            cmd = subprocess.run(['grep', 'adduser', '/var/log/auth.log', '-A', '5'], capture_output=True)
            # Convert from bytes to a string
            string = cmd.stdout.decode("utf-8")
            # Use split to split the entries with the '--' characters as the delimiter
            entries = string.split('--')
            # Write data to text file
            with open("Account_Creation.txt", "w") as report_file:
                for entry in entries:
                    report_file.write("New account created:\n")
                    report_file.write(entry + "\n")
                    report_file.write("*" * 100 + "\n")
            # Print each entry
            for entry in entries:
                print(f'{colours.BOLD}{colours.GREEN}New account created:{colours.RESET}')
                print(entry)
                print('*'*100)
        else:
            # Define the PowerShell command
            powershell_command = "Get-EventLog -LogName Security -InstanceId 4720"
            # Execute the PowerShell command
            completed = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True, universal_newlines=True)
            # Write data to text file
            with open("Account_Creation.txt", "w") as report_file:
                report_file.write(completed.stdout)
            # Print the output
            print(completed.stdout)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None