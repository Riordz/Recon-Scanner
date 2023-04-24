import os
import subprocess
import datetime
import socket
import threading
import csv

# Title: *Insert FYP Title Name*
# Author: Ryan O'Riordan / R00179917

print("\n WELCOME!")

def menu():
        print("\n 1. Port Scan \n 2. IP/MAC Discovery \n 3. Live Host Status \n 4. OS Detection \n 5. Instructions \n 6. Port Scan on a list of IP's \n 7. Quit \n ")

def portScan(ip, port): # Port Scan definition using the socket module to connect to ports. Works in conjuction with startScan() for threading purposes. 
    try:
        x = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        x.settimeout(1)
        x.connect((ip, port))
        service = socket.getservbyport(port)
        print(f"Port: {port} | Status: OPEN | Service: {service} ")
        x.close()
    except:
        pass

def recentHosts(): # Using subprocesses to connect to terminal and perform arp -a for arp cache table. Output is parsed to show ip:MAC addresses. 
    try:
        activeCmdlet = subprocess.check_output(['arp', '-a']).decode('utf-8')
        activeResults = activeCmdlet.split('\n')
        RecentHosts = []
        for section in activeResults:
            if 'dynamic' in section or 'static' in section:
                activeParse = section.split()
                ipAddr = activeParse[0]
                MacAddr = activeParse[1]
                RecentHosts.append((ipAddr, MacAddr))
        for entry in RecentHosts:
            print(f"IP: {entry[0]} is associated with MAC: {entry[1]}")          
    except subprocess.CalledProcessError:
        print("Error")


def liveHost():
    target = input("please enter target IP: ")
    pingOp = os.system("ping -n 1 " + target + " >NUL")
    if pingOp == 0:
        print(f"Host {target} is Active")
    else:
        print(f"Host {target} is NOT Active")

def osDetection():
    ip_address = input("Enter Target IP for OS Detection: ")
    activeCmdlet = subprocess.check_output(['ping', ip_address]).decode('utf-8')
    parsedLine = activeCmdlet.split('\n')

    for line in parsedLine:
        if 'TTL=' in line:
            ttl_value = int(line.split('TTL=')[1].split()[0])
            break
    else:
        print("TTL value not found")
        exit()

    listofOS = ['Linux/Unix,', 'Windows', 'Cisco', 'Unknown']

    if 1 <= ttl_value <= 64:
        print(f"Host {ip_address} OS: {listofOS[0]}")
    elif 65 <= ttl_value <= 128:
        print(f"Host {ip_address} OS: {listofOS[1]}")
    elif 129 <= ttl_value <= 255:
        print(f"Host {ip_address} OS: {listofOS[2]}")
    else:
        print(f"Host {ip_address} OS: {listofOS[3]}")



def instructions():
    while True:
        print("\n 1. Port Scan \n 2. Active Hosts \n 3. Live Host Status \n 4. OS Detection \n 5. Return \n")
        y = input("Please choose from the following: \n")

        if y == '1':
            file1 = "portScanInstruct.txt"
            with open(file1) as file:
                output = file.read()
            print(output)

        elif y == '2':
            file1 = "activeHostInstruct.txt"
            with open(file1) as file:
                output = file.read()
            print(output)

        elif y == '3':
            file1 = "liveHostInstruct.txt"
            with open(file1) as file:
                output = file.read()
            print(output)

        elif y == '4':
            file1 = "osDetectInstruct.txt"
            with open(file1) as file:
                output = file.read()
            print(output)

        elif y == '5':
            return

        else:
            print("Invalid, Try again..")

def startScan(ip): 
    for port in range(1, 65535):
        thread = threading.Thread(target=portScan, args=(ip, port,))
        thread.start()

def fileScanThread(ip, port):
    thread = threading.Thread(target=portScan, args=(ip, port,))
    thread.start()

def fileScan(filePath):
    try:
        with open(filePath) as f:
            ipList = f.read().splitlines()
            for ip in ipList:
                if ip.strip() != "":
                    print(f"Scanning {ip}: \n")
                    for port in range(1, 65535):
                       fileScanThread(ip, port)
    except FileNotFoundError:
        print(f"File {filePath} does not exist")



while True:
    menu()
    x = input("Please Choose from the following options: (1-7) \n")
    
    if x == "1":
        time = datetime.datetime.utcnow() # Date and Time conversion
        formatDate = time.strftime('%d-%m-%y')
        formatTime = time.strftime('%H:%M')
        print(f"\nDate: {formatDate}  Time: {formatTime}")
        print("============================================") 

        target_ip = input("Enter Target IPv4 Address: ")
        startScan(target_ip)

    elif x == "2":
        time = datetime.datetime.utcnow() # Date and Time conversion
        formatDate = time.strftime('%d-%m-%y')
        formatTime = time.strftime('%H:%M')
        print(f"\nDate: {formatDate}  Time: {formatTime}")
        print("============================================")
        recentHosts()


    elif x == "3":
        time = datetime.datetime.utcnow() # Date and Time conversion
        formatDate = time.strftime('%d-%m-%y')
        formatTime = time.strftime('%H:%M')
        print(f"\nDate: {formatDate}  Time: {formatTime}")
        print("============================================")
        liveHost()


    elif x == "4":
        time = datetime.datetime.utcnow() # Date and Time conversion
        formatDate = time.strftime('%d-%m-%y')
        formatTime = time.strftime('%H:%M')
        print(f"\nDate: {formatDate}  Time: {formatTime}")
        print("============================================")
        osDetection()

    elif x == "5":
        time = datetime.datetime.utcnow() # Date and Time conversion
        formatDate = time.strftime('%d-%m-%y')
        formatTime = time.strftime('%H:%M')
        print(f"\nDate: {formatDate}  Time: {formatTime}")
        print("============================================")
        instructions()

    elif x == "6":
        time = datetime.datetime.utcnow() # Date and Time conversion
        formatDate = time.strftime('%d-%m-%y')
        formatTime = time.strftime('%H:%M')
        print(f"\nDate: {formatDate}  Time: {formatTime}")
        print("============================================")
        filePath = input("Enter Full Filepath: ")
        fileScan(filePath)

    elif x == "7":
        time = datetime.datetime.utcnow() # Date and Time conversion
        formatDate = time.strftime('%d-%m-%y')
        formatTime = time.strftime('%H:%M')
        print(f"\nDate: {formatDate}  Time: {formatTime}")
        print("============================================")
        print("Thank you for using the program")
        quit()

    else:
        print("Wrong Selection. Please Choose Between 1-7.")




