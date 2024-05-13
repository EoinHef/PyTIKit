from datetime import datetime
import os
import colours

# Function to read file metadata
def print_file_metadata(file_path):
    # Try block for errors and exceptions handling
    try:
        # Get file metadata
        stat = os.stat(file_path)

        # Use the stat object to print metadata
        
        print(f"{colours.BOLD}{colours.GREEN}File Metadata:{colours.RESET}")
        print(f"File Path: {colours.BOLD}{colours.GREEN}{file_path}{colours.RESET}")
        print(f"File Permissions (Octal): {colours.BOLD}{colours.GREEN}{stat.st_mode}{colours.RESET} - {colours.BLUE}This indicates the access permissions for the file owner, group owner, and others (read, write, execute).{colours.RESET}")
        print(f"File Owner UID: {colours.BOLD}{colours.GREEN}{stat.st_uid}{colours.RESET} - {colours.BLUE}This is the numeric user ID of the file's owner. It can be used to map to a username on the system.{colours.RESET}")
        print(f"File Group GID: {colours.BOLD}{colours.GREEN}{stat.st_gid}{colours.RESET} - {colours.BLUE}This is the numeric group ID of the file's group. It can be used to map to a group name on the system.{colours.RESET}")
        print(f"File Size (Bytes): {colours.BOLD}{colours.GREEN}{stat.st_size}{colours.RESET} - {colours.BLUE}This represents the size of the file in bytes.{colours.RESET}")

        # Convert from epoch time to more readable format
        access_time = datetime.fromtimestamp(stat.st_atime)
        modification_time = datetime.fromtimestamp(stat.st_ctime)
        print(f"Last Access Time: {access_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")  # Format with microseconds
        print(f"Last Modification Time: {modification_time.strftime('%Y-%m-%d %H:%M:%S.%f')}")
        # Add the data to file
        with open("MetaData_Report.txt", 'w') as file:
            file.write(f"File Metadata:\n")
            file.write(f"File Permissions (Octal): {stat.st_mode} - This indicates the access permissions for the file owner, group owner, and others (read, write, execute).\n")
            file.write(f"File Owner UID: {stat.st_uid} - This is the numeric user ID of the file's owner. It can be used to map to a username on the system.\n")
            file.write(f"File Group GID: {stat.st_gid} - This is the numeric group ID of the file's group. It can be used to map to a group name on the system.\n")
            file.write(f"File Size (Bytes): {stat.st_size} - This represents the size of the file in bytes.\n")
            file.write(f"Last Access Time: {access_time.strftime('%Y-%m-%d %H:%M:%S.%f')}\n")
            file.write(f"Last Modification Time: {modification_time.strftime('%Y-%m-%d %H:%M:%S.%f')}\n")           
    # Handle any exceptions in try block
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
  