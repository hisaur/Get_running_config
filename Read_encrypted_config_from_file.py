from cryptography.fernet import Fernet
from netmiko import ConnectHandler
from tabulate import tabulate
import os
import sys
from os import walk
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import binascii
import codecs
#This script was developed by Toktosunov Alexandr. 
# Use this code as much as you want.
#If you found this code useful, please give me recomendation or endorsment on LinkedIn:
#  https://www.linkedin.com/in/aleksandr-toktosunov-b76577151/
# Path of the backup's folder
def Select_directory():
    directory_list = []
    i=0
    for dirname, dirnames, filenames in os.walk('.'):
    # print path to all subdirectories first.
        for subdirname in dirnames:
            i+=1
            directory_list.append ([i,os.path.join(dirname,subdirname)])
    print (directory_list)
    return directory_list
    #here user chooses directory which contains the config
    #by default this script creates directories with following names "# of day,Month,Year"
def Ask_user_to_choose_directory(aDirectory_list):
    print (tabulate(aDirectory_list,headers=["#","Folder"],tablefmt="rst"))
    choosed_folder = int(input("Enter directory number of the desired folder: "))
    path_to_folder = aDirectory_list[choosed_folder-1][1]
    print (path_to_folder)
    return path_to_folder
#this peace of code uses netmiko to copy backup config to router 
    # and save running config to startup config
    # In order to work SSH must be enabled on a device
def Restore_config(aRunning_config,IP_address, username,password,enable_secret):
    ssh_connection = ConnectHandler(
        device_type = "cisco_ios",
        ip = IP_address,
        username = username,
        password = password,
        secret  = enable_secret,
    )
    ssh_connection.enable()
    result = ssh_connection.find_prompt() + "\n"
    ssh_connection.send_command(aRunning_config, delay_factor=2)
    ssh_connection.send_command("copy run start", delay_factor=2)
    result = ssh_connection.send_command("show run", delay_factor=2)
    ssh_connection.disconnect()
    print ("Current config","\n",result)

#This part of the code was taken from https://warsang.ovh/taking-bytes-as-input-in-python3/
# This code transfers input salt from string to bytes 
def to_string(bytes_string) :
    return bytes_string.decode('ISO-8859-1')

def to_bytes(string) :
    return string.encode('ISO-8859-1')
def input_fix(string):
    return codecs.decode(string,"unicode_escape")
    #main dunction that tides all script together
def main():
    directory_list = Select_directory()
    path = Ask_user_to_choose_directory(directory_list)
    dirs = os.listdir( path )
    file_list = []
    i=0
    print (dirs)
    for item in dirs:
        # this code print folder files that were created by script "Get_running_config.py"
        i+=1
        file_list.append ([i,item])
        #just pretty table style
    print (tabulate(file_list, headers=["#","File_Name"],tablefmt="rst"))
    user_choise = int(input("Enter number of file to decrypt it: "))
    #peace of code to open file,that was choosed by user
    file = open(path+"/"+file_list[user_choise-1][1], "r")
    file_content = file.read().encode()
    print (file_content)
    password_for_encryption = input ("Enter password for encrypting backups: ")
    password_for_encryption_bytes = password_for_encryption.encode()
    salt_string = input('Please input salt bytes string such as \xca\xfe\xba\xbe >>> ')
    string_of_bytes = input_fix(salt_string)
    print(" <---- String of bytes to bytesstring --->\n ")
    salt_bytes = to_bytes(string_of_bytes)
    #This peace of the code decrypts the data with help of salt and password
    print (salt_bytes)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_bytes,
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(password_for_encryption_bytes))
    f = Fernet(key)
    token = f.decrypt(file_content)
    token_string = token.decode()
    print (token_string)
    #this peace of code helps to restore configuration, but on cisco routers and swirtches with previous configuration this will lead to 
    #merge in currunt config and backup config
"""
Under construction!

    User_input_restore = input("Do you want to restore configs?(Beware backup will be merged with current config![No]): ")
    if User_input_restore == "Yes" or User_input_restore == "yes":
        username = input("Enter username: ")
        password = input("Enter password: ")
        enable_secret = input("Enter enable password: ")
        #programm takes ip from name of the backup file's name
        name_of_the_backup = file_list[user_choise-1][1]
        #you can hardcode ip here
        ip = name_of_the_backup.partition("_")[0]
        Restore_config(token_string,ip,username,password,enable_secret)
    else:
        sys.exit()
main()
 """
    
