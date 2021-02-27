from scapy.all import *
import os
import struct
import socket
from bitstring import BitArray
from pynput.keyboard import Listener
import threading

def stopfilter(packet):
    global stopflag
    return stopflag



class scapythread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        sniff(filter="ip or icmp", prn=packet_proccesing, stop_filter=stopfilter)
        sorted_sourceips={}
        sorted_values=sorted(sourceipis.values())
        sorted_values.reverse()
        for i in sorted_values:
            for k in sourceipis.keys():
                if sourceipis[k] == i:
                    sorted_sourceips[k] = sourceipis[k]
                    break
        logfile = open(filename+".txt","w")
        logfile.write("Packets count:\n")
        logfile.write("TCP: "+str(count_tcp)+"\n")
        logfile.write("UDP: "+str(count_udp)+"\n")
        logfile.write("ICMP: "+str(count_icmp)+"\n")
        logfile.write("Fragmented: "+str(fragmentedpackets)+"\n")
        logfile.write("----------------------------------------------------\n")
        logfile.write("Avg/Min/Max length:\n")
        logfile.write("avg is: "+str(sumlengths/count_packets)+"\n")
        logfile.write("min is: " + str(minsizepacket) + "\n")
        logfile.write("max is: " + str(maxsizepacket) + "\n")
        logfile.write("----------------------------------------------------\nSource IPs in desc order by packet sent:\n")
        for i in sorted_sourceips:
            logfile.write(i+" : "+str(sorted_sourceips[i])+"\n")
        logfile.close()
        os._exit(0)

count_packets=0
count_udp=0
count_tcp=0
count_icmp=0
fragmentedpackets=0
sumlengths=0
minsizepacket=100000000
maxsizepacket=0


def packet_proccesing(packet):
    global count_packets
    count_packets+=1
    global sumlengths
    sumlengths+=packet.len
    global maxsizepacket
    if(packet.len>maxsizepacket):
        maxsizepacket=packet.len
    global minsizepacket
    if(packet.len<minsizepacket):
        minsizepacket=packet.len
    rawpacket=raw(packet)
    ipheader = rawpacket[14:34]
    protocolnumber=ipheader[9]
    fragment=ipheader[6]
    ip_header = struct.unpack("!12s4s4s", ipheader)
    if(fragment==64 or fragment==0):
        pass
    else:
        global fragmentedpackets
        fragmentedpackets+=1
    sourceip=socket.inet_ntoa(ip_header[1])
    if (sourceip in sourceipis.keys()):
        sourceipis[sourceip]+=1
    else:
        sourceipis[sourceip]=1
    if(protocolnumber==1):
        print("protocol:icmp  Source IP:" + socket.inet_ntoa(ip_header[1]) + " Destination IP:" + socket.inet_ntoa(ip_header[2]) + " length: " +str(packet.len))
        global count_icmp
        count_icmp+=1
    elif(protocolnumber==6):
        print("protocol:tcp  Source IP:" + socket.inet_ntoa(ip_header[1]) + " Destination IP:" + socket.inet_ntoa(ip_header[2]) + " length: " +str(packet.len))
        global count_tcp
        count_tcp+=1
    elif(protocolnumber==17):
        print("protocol:udp  Source IP:" + socket.inet_ntoa(ip_header[1]) + " Destination IP:" + socket.inet_ntoa(
            ip_header[2]) + " length: " +str(packet.len))
        global count_udp
        count_udp+=1
    else:
        pass

stopflag=False

sourceipis={}

def on_press(key):  # The function that's called when a key is pressed
    global stopflag
    print("sniffing stopped")
    stopflag=True

def on_release(key):  # The function that's called when a key is released
    pass
filename=input("enter the filename u want to save your log in:\n")
choice=input("press S to start sniffing and after starting press any key to stop:\n")
if(choice=="S" or choice=="s"):
    with Listener(on_press=on_press, on_release=on_release) as listener:  # Create an instance of Listener
        sniffthread = scapythread()
        sniffthread.start()
        listener.join()  # Join the listener thread to the main thread to keep waiting for keys





