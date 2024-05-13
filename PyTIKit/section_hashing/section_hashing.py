import pefile
import os
import hashlib
import colours

# Function to obtain a md5 hash from a portable execuatble
def get_md5_hash(exe):
    try:
        # Open and read the file
        with open(exe, "rb") as file:
            data = file.read()
            # Obtain the hash of the file data and return
            md5_hash = hashlib.md5(data).hexdigest()
            # Get the filename from the path and print the filename
            filename = os.path.basename(exe)
            print(f"{colours.BOLD}{colours.GREEN}File Name:{colours.RESET} {filename}")
            print(f"{colours.BOLD}{colours.GREEN}MD5 Hash:{colours.RESET} {md5_hash}")
        return md5_hash
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None

# Function to obtain a sha1 hash from a portable execuatble
def get_sha1_hash(exe):
    try:    
        # Open and read the file
        with open(exe, "rb") as file:
            data = file.read()
            # Obtain the hash of the file data and return
            sha1_hash = hashlib.sha1(data).hexdigest()
            print(f"{colours.BOLD}{colours.GREEN}Sha-1 Hash:{colours.RESET} {sha1_hash}")
        return sha1_hash
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None

# Function to obtain a sha 256 hash from a portable execuatble
def get_sha256_hash(exe):
    try:
        # Open and read the file
        with open(exe, "rb") as file:
            data = file.read()
            # Obtain the hash of the file data and return
            sha256_hash = hashlib.sha256(data).hexdigest()
            print(f"{colours.BOLD}{colours.GREEN}Sha-256 Hash:{colours.RESET} {sha256_hash}")
        return sha256_hash
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None

# Function to obtain a sha 512 hash from a portable execuatble
def get_sha512_hash(exe):
    try:
        # Open and read the file
        with open(exe, "rb") as file:
            data = file.read()
            # Obtain the hash of the file data and return
            sha512_hash = hashlib.sha512(data).hexdigest()
            print(f"{colours.BOLD}{colours.GREEN}Sha-512 Hash:{colours.RESET} {sha512_hash}")
        return sha512_hash
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None

# Function to obtain a IAT hash from a portable execuatble
def get_imp_hash(exe):
    try:    
        # Loading the execuatble and staore in a variable
        pe = pefile.PE(exe)
        # Extract the IMPHash
        imp_hash = pe.get_imphash()
        # Print the hash value
        print(f"{colours.BOLD}{colours.GREEN}IMPHash:{colours.RESET} {imp_hash}")
        return imp_hash
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None
    
# Function to extract rich header PE hash   
def get_richheader_hash(exe):
    try:
        # Loading the execuatble and staore in a variable
        pe = pefile.PE(exe)
        # Extract the rich header PE hash
        rich_header_hash = pe.get_rich_header_hash()
        # Print the hash value
        print(f"{colours.BOLD}{colours.GREEN}Rich Header hash:{colours.RESET} {rich_header_hash}")
        return rich_header_hash
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None

# Function to store filename and hashes if not already present in file    
def store_hashes(filepath,md5_hash, sha1_hash, sha256_hash, sha512_hash, imphash, header_hash):
    try:
        # Get the filename from the file path
        filename = os.path.basename(filepath)
        entry = (f"Filename: {filename}\n"
                f"MD5: {md5_hash}\n"
                f"SHA-1: {sha1_hash}\n"
                f"SHA-256: {sha256_hash}\n"
                f"SHA-512: {sha512_hash}\n"
                f"IMPHash: {imphash}\n"
                f"Rich Header PE Hash: {header_hash}\n")

        # Check if the file exists and read all contents to check is entry already present
        if os.path.exists("File_Hashes.txt"):
            with open("File_Hashes.txt", "r") as file:
                # Read the contents of the file
                content = file.read()
                # Check if the entry is already present in the file
                if entry in content:
                    # Let user know entry is already present
                    print("Entry already exists for the given file and hashes.")
                    return

        # Append new entry and entry separator if not a duplicate
        with open("File_Hashes.txt", "a") as file:
            # Write the filename, IMPHash and rich header PE hash
            file.write(entry)
            file.write('*' * 80 + '\n')
            # Let user know entry was added to the file
            print("New entry added successfully.")
    except Exception as e:
        print(f"An unexpected error occurred: {str(e)}")
        return None


