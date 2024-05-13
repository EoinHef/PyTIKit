import subprocess
import colours

def ssh_sessions():
    try:
        # Building the command and running with the subprocess module, also capturing the output
        cmd = subprocess.run(['grep', 'Accepted password for', '/var/log/auth.log', '-A', '2'], capture_output=True)
        # Convert from bytes to a string
        string = cmd.stdout.decode("utf-8")
        # Use split to split the entries with the '--' characters as the delimiter
        entries = string.split('--')
        # Write data to text file
        with open("SSH_Connections.txt", "w") as report_file:
            for entry in entries:
                report_file.write("Successful SSH Connection:\n")
                report_file.write(entry + "\n")
                report_file.write("*" * 100 + "\n")
        # Print each entry
        for entry in entries:
            print(f'{colours.BOLD}{colours.GREEN}Successful SSH Connection:{colours.RESET}')
            print(entry)
            print('*'*100)
    except Exception as e:
        print(f"An unexpected error occurred: {(e)}")
        return None
    