import os

# Function to display the command history on a Linux system
def view_linux_cmd_history():
    try:
        # Ask the user how many commands from history they want to see
        number_cmds = input("Enter the number of commands you wish to see(Leave blank for all): ")
        report = "Command_History_Linux.txt"
        # Check to see if the user inputted a value
        if number_cmds:
            # Use tail command to get the user inputted number of commands
            cmd = f'tail -n {number_cmds} ~/.bash_history'
            cmd2 = f'tail -n {number_cmds} ~/.bash_history > {report}' 
            # Run the command
            os.system(cmd)
            os.system(cmd2)
        # If the user does not enter a number, print all contents of bash_history
        else:
            cmd = 'cat ~/.bash_history'
            cmd2 = f'cat ~/.bash_history > {report}'
            os.system(cmd)
            os.system(cmd2)
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None 