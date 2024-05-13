"""
Author: Eoin Heffernan / B00138546
Tool built in fulfillment of Thesis requirements
App Name: PyTIKit
"""

import menu_system
import art
import colours

def main():
    menu_system.main_menu()


# Entry point of the program
if __name__ == "__main__":
    ascii_art = art.text2art("PyTIKit")
    print(f"{colours.BOLD}{colours.GREEN}{ascii_art}{colours.RESET}")
    print(f"{colours.BOLD}{colours.GREEN}Author: Eoin Heffernan / B00138546{colours.RESET}")
    main()