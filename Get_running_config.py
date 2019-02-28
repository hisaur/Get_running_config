from netmiko import ConnectHandler
from cryptography.fernet import Fernet
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import time
import hashlib
import json
#This script was developed by Toktosunov Alexandr. 
# Use this code as much as you want.
#If you found this code useful, please give me recomendation or endorsment on LinkedIn:
#  https://www.linkedin.com/in/aleksandr-toktosunov-b76577151/
# This small script get running config from devices and creates encrypted fyles from this configs
# You can Read files with script READ_Ecncrypted_config_from_file.py
# this function gets running config
def Get_running_config(IP_address,username,password,enable_secret):
    ssh_connection = ConnectHandler(
        device_type = "cisco_ios",
        ip = IP_address,
        username = username,
        password = password,
        secret  = enable_secret,
    )
    ssh_connection.enable()
    result = ssh_connection.find_prompt() + "\n"
    result += ssh_connection.send_command("terminal length 0", delay_factor=2)
    running_config = ssh_connection.send_command("show run", delay_factor = 2)
    ssh_connection.send_command("terminal length 24", delay_factor=2)
    ssh_connection.disconnect()
    print (running_config)
    return running_config
    # this function creates dictionary with passwords and IP addresses
def Ask_for_username_and_password():
    yes_or_no = input ("Are all username and passwords are the same? print 'yes' or 'no'")
    if yes_or_no == "yes" or yes_or_no == "Yes":
        username = input ("Enter username ")
        password = input ("Enter password ")
        enable_secret = input ("Enter enable_password ")
        intventory_list = [
            # you must add here ip addresses of the devices in the following manner
        {"IP":"10.1.1.1","Username":username,"Password":password,"Enable_secret":enable_secret},
        {"IP":"10.1.1.2","Username":username,"Password":password,"Enable_secret":enable_secret},
        {"IP":"10.1.1.3","Username":username,"Password":password,"Enable_secret":enable_secret}
        ]    
        return intventory_list
    elif yes_or_no == "no" or yes_or_no == "No":
        intventory_list = [
            # you must add here ip addresses of the devices in the following manner
        {"IP":"10.1.1.1","Username":input("Username1"),"Password":input("password1"),"Enable_secret":input("Enable secret1")},
        {"IP":"10.1.1.2","Username":input("Username2"),"Password":input("password2"),"Enable_secret":input("Enable secret2")},
        {"IP":"10.1.1.3","Username":input("Username3"),"Password":input("password3"),"Enable_secret":input("Enable secret3")}
        ]  
    
        print (intventory_list)  
        return intventory_list
        #You cand just hardcode Usernames and passwords, but i consider it insecure
        #in oreder to do this just remove if and elif statements
def main ():
    inventory_list = Ask_for_username_and_password()
    dirname = time.strftime("%d,%B,%Y")
    try:
        os.mkdir(dirname)
    except FileExistsError:
        print ("directory with this name already exist")
    for item in inventory_list:
        running_config = Get_running_config (item["IP"],item["Username"],item["Password"],item["Enable_secret"])
    #Encryption part
        password_for_encryption = input ("Enter password for encryption: ")
        password_for_encryption_bytes = password_for_encryption.encode()
        salt = os.urandom(16)
        salt_list = []
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password_for_encryption_bytes))
        f = Fernet(key)
    #Write encrypted running config into file with date and time
        name_of_the_file = item["IP"]+"_"+time.strftime("%d,%B,%Y")
        running_config = running_config.encode()
        token = f.encrypt(running_config)
        token_string = token.decode()
        path = dirname
        path_create = os.path.join(path,name_of_the_file +".txt")
    # this code will save salt for each device in the separate file called salt_list.txt
        with open (path_create,"a+") as text_file:
            text_file.write (token_string)
            text_file.close()
        salt_list.append ([name_of_the_file+".txt","Salt: ",salt])
        path_create_salt = os.path.join(path,"salt_list" )
        with open (path_create_salt+time.strftime("%d,%B,%Y")+".txt","a+") as text_file:
            for item in salt_list:
                text_file.write (str(item))
                text_file.close()
        print ("Please keep secure your password and Salt list, which you can find in the directory")
main()