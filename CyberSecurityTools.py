from socket import *
from datetime import date
import sys
import ftplib
import os
from winreg import *

def anonLogin(hostname):
    printList = []
    try:
        tgtIP = gethostbyname(hostname)
        print("[+] Resolved hostname: Success!")
        printList.append("[+] Resolved hostname: Success!")
    except:
        print("[-] Cannot resolve %s"% tgtHost)
        printList.append("[-] Cannot resolve %s"% tgtHost)
        return printList
    try:
        ftp = ftplib.FTP(tgtIP)
        ftp.login('anonymous')
        print("\n [+] " + str(hostname) + " FTP Anonymous Login Success")
        printList.append("\n [+] " + str(hostname) + " FTP Anonymous Login Success")
        ftp.quit()
        return printList
    except Exception:
        print("\n [-] " + str(hostname) + " FTP Anonymous Login Failed")
        printList.append("\n [-] " + str(hostname) + " FTP Anonymous Login Failed")
        return printList
#anonLogin("90.130.70.73")

def connectionScan(tgtHost, tgtPort): #Main method to make connection, takes ip and port
    try:
        connectionSocket = socket(AF_INET, SOCK_STREAM)
        connectionSocket.connect((tgtHost, tgtPort))
        print("[+] %d tcp open"% tgtPort)
        return("[+] %d tcp open"% tgtPort)
        connectionSocket.close()
    except:
        print("[-] %d tcp closed"% tgtPort)
        return("[-] %d tcp closed"% tgtPort)

def portScan(tgtHost, tgtPorts):
    portPrints = []
    if tgtPorts != []:
        print("Attempting to get the IP of %s"% tgtHost)
        portPrints.append("\nAttempting to get the IP of %s"% tgtHost)
        try:
            tgtIP = gethostbyname(tgtHost)
            print("Attempt success!")
            portPrints.append("\nAttempt success!")
        except:
            print("[-] Cannot resolve %s"% tgtHost)
            portPrints.append("\n[-] Cannot resolve %s"% tgtHost)
            return portPrints
    
        try:
            tgtName = gethostbyaddr(tgtIP)
            print("\n[+] Scan result of %d: "% tgtName[0])
            portPrints.append("\n[+] Scan result of %d: "% tgtName[0])
        except:
            print("\n[+] Scan result of %s: "% tgtIP)
            portPrints.append("\n[+] Scan result of %s: "% tgtIP)
        setdefaulttimeout(1)
        for tgtPort in tgtPorts:
            print('Scanning port: %d'% tgtPort)
            portPrints.append('\nScanning port: %d'% tgtPort)
            portPrints.append(connectionScan(tgtHost, int(tgtPort)))
        return portPrints
    else:
        print("Sorry, you need to input at least one port!")

def formatMenu(prompts):
    for i in prompts:
        print(i)
    
def formatMenuPrompt():
    return 'Enter an option using the numbers provided: '

def getUserChoice(string):
    complete = False
    while complete == False:
        userInput = input(string)
        userInput = userInput.strip()
        if userInput != "":
            complete = True
            break
    return userInput

def printFile(printList):
    if printList != []:
        portLogFileName = input("Choose a name for this file, or use the name of an existing log file - ")
        portLogFileName += ".txt"
        fout = open(portLogFileName, "a+")
        logName = input("\nAssign a name to this Site log, or press enter to skip - ")
        if len(logName) != 0:
            fileInsert = logName + " - " + xDate + "\n"
        else:
            fileInsert = xDate + "\n"
        fout.write(fileInsert)
        for i in printList:
            fout.write(i)
        fout.close()

def sid2user(sid):
    try:
        key = OpenKey(HKEY_LOCAL_MACHINE,
                      'SOFTWARE\Microsoft\Windows_NT\CurrentVersion\ProfileList'
                      + '\\' + sid)
        (value, type) = QueryValueEx(key, 'ProfileImagePath')
        user = value.split('\\')[-1]
        return user
    except:
        return sid

def returnDir():
    dirs=['C:\\Recycler\\', "C:\\Recycled\\", "C:\\$Recycle.Bin\\"]
    for recycleDir in dirs:
        if os.path.isdir(recycleDir):
            return recycleDir
    return None

def findRecycled(recycleDir):
    xLst = []
    dirList = os.listdir(recycleDir)
    for sid in dirList:
        files = os.listdir(recycleDir + sid)
        user = sid2user(sid)
        print('\n[*] Listing Files for User: ' + str(user))
        xLst.append('\n[*] Listing Files for User: ' + str(user))
        for file in files:
            print('[+] Found File: ' + str(file))
            xLst.append('[+] Found File: ' + str(file))
        return xLst

def main():
    today = date.today()
    xDate = today.strftime("%m/%d/%y")
    optionsList = ['What would you like to do?', '[1] Make a scan', '[2] Save the results of previous port scan', '[3] FTP-Anon-Scan', '[4] Save the results of previous FTP scan', '[5] Check for deleted files', '[6] Save Deleted Files', '[7] Exit']
    while 1:
        formatMenu(optionsList)
        choice = getUserChoice(formatMenuPrompt())
        if choice == "1":
            printList = []
            websiteToScan = getUserChoice("\nPlease input the website/ip you wish to scan: ")
            ports = []
            portList = True
            while portList:
                port = getUserChoice("Please input a port, or enter 'Q' to continue, or enter '*' for every port (This option will reappear, allowing for you to scan multiple ports at once): ")
                port = port.lower()
                if  port == "q":
                    portList = False
                elif port == "*":
                    lengthCheck = input("Warning, this would take a VERY long time, do you wish to proceed?[Y/N] ")
                    lengthCheck = lengthCheck.lower()
                    if lengthCheck == "y":
                        for i in range(65535):
                            strPort = int(i)
                            ports.append(strPort)
                        portList = False
                else:
                    try:
                        checkPort = int(port)
                        if checkPort <= 65535 or checkPort >= 0:
                            ports.append(checkPort)
                        else:
                            print("That port is not within the range of 0-65535")
                    except:
                        print("That is not a valid port, please try again")
            xLst = portScan(websiteToScan, ports)
            for i in xLst:
                printList.append(i)
        elif choice == "2":
            try:
                printFile(printList)
                printList = []
            except:
                print("\nI am sorry, please perform a Port scan first!")
        elif choice == "3":
            xFTP = getUserChoice("\nPlease input the website/ip you wish to scan: ")
            ftpList = anonLogin(xFTP)
        elif choice == "4":
            try:
                printFile(ftpList)
                ftpList = []
            except:
                print("\nI am sorry, please perform a FTP scan first!")
        elif choice =="5":
            recycledDir = returnDir()
            delList = findRecycled(recycledDir)
        elif choice == "6":
            try:
                for i in delList:
                    print(i)
            except:
                print("\nI am sorry, Please run a delete scan first!")
        elif choice == "7":
            sys.exit( 0 )
        else:
            print("Invalid choice, please try again")

if __name__ == '__main__':
    main()