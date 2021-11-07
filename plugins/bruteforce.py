import module
import sys
import pyshark
import json
from datetime import datetime

PROTOCOL = "ftp"
FTP_LOGIN_FAIL_PATTERN = "Response: 530 Login incorrect"
BRUTEFORCE_TIME = 60
BRUTEFORCE_TOTAL_DECTECT = 10
packet_analyst = None




def generateDataFromFile(fileCSV):
    f = open(fileCSV,'r')
    raw_data = f.readlines()
    row = None
    data = []
    for i in range(0,len(raw_data)):
        tmp = raw_data[i].split(",")
        row = {"time":tmp[0],"protocol":tmp[1],"src_ip":tmp[2],
        "src_port":tmp[3],"dst_ip":tmp[4],"dst_port":tmp[5],"info":tmp[7]}
        row = json.loads(json.dumps(row))
        data.append(row)       
    return data


def checkBruteForce(data):
    
    ftp_login_fail = False
    packet_analyst_info = None
    analysting = False
    count = 0
    image = []
    for i in data:
        if(i["protocol"]==PROTOCOL):
            if(str(i["info"]).find(FTP_LOGIN_FAIL_PATTERN)==0):
                ftp_login_fail = True
                packet_analyst_info = {"protocol":i["protocol"],"src_ip":i["src_ip"],"dst_ip":i["dst_ip"],"time":i["time"],
                "count":0,"alert":False}
                packet_analyst_info = json.loads(json.dumps(packet_analyst_info))
                if(checkIfPacketNeedFollow(image,i)<0):
                    image.append(packet_analyst_info)
                indexPacketFollow = checkIfPacketNeedFollow(image,i)

                time_partern = datetime.strptime(str(image[indexPacketFollow]["time"]), '%Y-%m-%d %H:%M:%S.%f')
                analysting = True
          
            if(str(i["info"]).find(FTP_LOGIN_FAIL_PATTERN)<0):
               
                ftp_login_fail = False
            if(ftp_login_fail==True and analysting==True):
                indexPacketFollow = checkIfPacketNeedFollow(image,i)
                if(indexPacketFollow>=0):                   
                    time_packet = datetime.strptime(str(image[indexPacketFollow]["time"]), '%Y-%m-%d %H:%M:%S.%f') 
                    interval = time_packet - time_partern
                    time_partern = time_packet
                    if(int(interval.seconds)<=BRUTEFORCE_TIME):
                       image[indexPacketFollow]["count"] = image[indexPacketFollow]["count"]+1    
                     
                    for i in image:
                        if(i["count"]>=BRUTEFORCE_TOTAL_DECTECT):
                            if(i["alert"]==False):
                                print("FTP BRUTEFORCE DETECTED !")
                                print("Detect brute force attack from ip address "+ i["dst_ip"]
                                +" to ip address "+ i["src_ip"]+" at "+i["time"]) 
                                analysting = False
                                i["count"] = 0
                                i["alert"] = True
                                image.remove(i)
def checkIfPacketNeedFollow(image,packetJS):  
    count = 0
    exist = False
    for i in image:
        
        if (str(i["src_ip"]) == str(packetJS["src_ip"]) and
                    str(i["dst_ip"]) == str(packetJS["dst_ip"])):

                    exist = True   
        count = count+1          
    if(exist==True):
        
        return count-1
    return -1


def ids(fileCSV):
    checkBruteForce(generateDataFromFile(fileCSV))



            

