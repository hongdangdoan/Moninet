from datetime import datetime
from logging import info
from py import test
import pyshark
import sys
import json
import csv
import time
from pathlib import Path
import os
import plugins.bruteforce as BRUTEFORCE


TIME_DELAY = 30

def network_conversation(packet):
  try:
    layers = packet.layers
    if(len(layers)>4):
        protocol = layers[len(layers)-2]._layer_name
    if(len(layers)<=4):
        protocol = layers[len(layers)-1]._layer_name 
    time = packet.sniff_time
    source_address = packet.ip.src
    destination_address = packet.ip.dst
    source_port = None
    destination_port = None
    if(hasattr(packet,'tcp') or hasattr(packet,'udp')):  
        source_port = packet[packet.transport_layer].srcport
        destination_port = packet[packet.transport_layer].dstport
    
    length = packet.length
    info = getInfoOfPacket(packet)
    dataSet = {"time":str(time),"protocol":protocol,"source_address":source_address,"source_port":source_port,
    "destination_address":destination_address,"destination_port":destination_port, "length":length,"info":info}
    result = json.loads(json.dumps(dataSet))
    return result
  except AttributeError as e:
    pass

def showNetWorkConversation(fileCapture):
    capture = pyshark.FileCapture(fileCapture,only_summaries=True)
    conversation = []
    for packet in capture:
        results = network_conversation(packet)
        if(results!=None):
            conversation.append(results)

    for item in conversation:
        print(item)

def writeToCSV(filePCAP,fileCSV):
    f = open(fileCSV,'w',newline='',encoding='UTF-8')
    writer = csv.writer(f)
    capture = pyshark.FileCapture(filePCAP, only_summaries=True)
    header = []
    data = []
    dataSummary = []
    summary = dir(capture[0])
    for i in summary:
        if(checkDifferentField(i)==False):
            header.append(i)
    writer.writerow(header)
    try:
        for packet in capture:
            row = []
            for i in summary:
                if(checkDifferentField(i)==False):
                    if(len(str(getattr(packet,i)))>0):
                        value = str(getattr(packet,i))
                        value = value.replace("\\xe2\\x86\\x92", "->")
                        row.append(value)
                    else:
                        row.append(str(getattr(packet,i))) 
            data.append(row)
        writer.writerows(data)
    except AttributeError as e:
        pass
    f.close()


def liveCapture(fileCSV, interface):
    print("Monitoring on ",interface)
    f = open(fileCSV,'w', newline='')
    writer = csv.writer(f)
    header = ['time','protocol','source_address','source_port','destination_address','destination_port','length','info']
    writer.writerow(header)
    while(True):
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously(packet_count=5):
            results = network_conversation(packet)
            if(results!=None):
                row = [results["time"],results["protocol"],results["source_address"],results["source_port"],
                    results["destination_address"],results["destination_port"], results["length"], results["info"]]
                print(row)
                writer.writerow(row)


def checkDifferentField(field):
    summary = ['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__',
     '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__',
      '__reduce_ex__', 
    '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_field_order', '_fields',
    'summary_line']
    for i in summary:
        if(i==field):
            return True
    return False

def liveCaptureTest(fileCSV, interface):
    print("Monitoring on ",interface)
    f = open(fileCSV,'w', newline='')
    writer = csv.writer(f)
    header = ['time','protocol','source_address','source_port','destination_address','destination_port','length']
    writer.writerow(header)
    while(True):
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously(packet_count=5):
            
                print(dir(packet))
                # writer.writerow(row)

def getInfoOfPacket(packet):
    field = ['frame_info', 'ftp', 'get_multiple_layers', 'get_raw_packet', 'highest_layer',
     'interface_captured', 'ip', 'layers', 'length', 'number', 'pretty_print', 'show', 'sniff_time', 
     'sniff_timestamp', 'tcp', 'transport_layer']
 


    if (hasattr(packet,'ftp' )):
        if(hasattr(packet['ftp'],'request' )):
            field = packet['ftp']._all_fields
            if(field['ftp.request']=='1'):
                    info = "Request: "+field['ftp.request.command']+" "+ field['ftp.request.arg']
                    return info
            if(field['ftp.request']=='0'):
                    info = "Response: "+field['ftp.response.code']+" "+ field['ftp.response.arg']
                    return info
    else:
        return None      

def liveMonitor(fileCSV, interface):
    print("Monitoring on ",interface)
    last_delay = datetime.today().strftime('%Y-%m-%d-%H:%M:%S.%f')
    last_delay = datetime.strptime(str(last_delay),'%Y-%m-%d-%H:%M:%S.%f')
    fileExist = False
    if(Path(fileCSV).is_file()):
        fileExist = True
        os.remove(fileCSV)
    f = open(fileCSV,'a', newline='')
    writer = csv.writer(f)
    header = ['time','protocol','source_address','source_port','destination_address','destination_port','length','info']
    writer.writerow(header)
    while(True):
        timeNow = datetime.today().strftime('%Y-%m-%d-%H:%M:%S.%f')
        timeNow = datetime.strptime(str(timeNow),'%Y-%m-%d-%H:%M:%S.%f')
        if(int((timeNow-last_delay).seconds)>TIME_DELAY):
            print("ANALYSTING.........")
            BRUTEFORCE.ids(fileCSV)

            last_delay = timeNow
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously(packet_count=5):
            results = network_conversation(packet)
            if(results!=None):
                row = [results["time"],results["protocol"],results["source_address"],results["source_port"],
                    results["destination_address"],results["destination_port"], results["length"], results["info"]]
                print(row)
                writer.writerow(row)
   
