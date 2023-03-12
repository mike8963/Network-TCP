import socket
import struct
import random
import os
import array
import numpy as np

'''
********************************
2021/6/13 B073040050 Wong Chang Min


********************************
'''

HOST = "127.0.0.1"
PORT = 8080
server_IP = (HOST,PORT)

RTT = 15
MSS = 1024
threshold = 64
buffer_size = 512*1024
TCPheader_len = 20
window_size = 29200

ACK    = 16 #16 
SYN    = 2  #02
FIN    = 1  #01
SYNACK = 18 #18
FINACK = 17 #17


def getChecksum(packet):
    if len(packet) % 2 != 0:
            packet += b'\0'

    res = sum(array.array("H", packet))
    res = (res >> 16) + (res & 0xffff)
    res += res >> 16

    return (~res) & 0xffff

def dns_function(domain):
    result = socket.getaddrinfo(domain,None)
    return result[0][4][0]

class TCPprotocol():
    def __init__(self):
        self.dip, self.dport = server_IP
        self.sip, self.sport = socket.gethostbyname(socket.gethostname()), 20
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.seq = random.randint(1,10000)
        self.ack_num = 0

    '''
    TCP header structure
    
     0      7 8     15 16    23 24    31
    +--------+--------+--------+--------+
    |   source port   |    dest port    |
    +--------+--------+--------+--------+
    |         sequence number           |
    +--------+--------+--------+--------+
    |      acknowledgement number       |
    +--------+--------+--------+--------+
    |head_len|  flag  | receive window  |
    +--------+--------+--------+--------+
    |     checksum    | Urg data pointer|
    +--------+--------+--------+--------+
    | data...                           |

    '''

    def TCPheader(self, tcp_len, seq, ack_num, flags, window):
        self.seq = seq
        self.ack_num = ack_num
        src_ip = socket.inet_aton(self.sip)
        dest_ip = socket.inet_aton(self.dip)
        sp,dp,head_len,checksum,ug_ptr = self.sport,self.dport,tcp_len << 4 ,0 ,0
        tcp_header = struct.pack('!HHIIBBHHH',sp,dp,self.seq,self.ack_num,head_len,flags,window,checksum,ug_ptr)
        pseudo_header = struct.pack('!4s4sBBH',src_ip,dest_ip,0,socket.IPPROTO_TCP,len(tcp_header))
        checksum = getChecksum(pseudo_header + tcp_header)
        tcp_header = tcp_header[0:16] + struct.pack('H',checksum) + tcp_header[18:]
        return tcp_header
    
    def send_packet(self,data,target,flag):
        if flag == 1:
            packet = self.TCPheader(5,self.seq,self.ack_num,ACK,window_size) + data
        else:
            packet = self.TCPheader(5,self.seq,self.ack_num,ACK,window_size) + data.encode()
        self.sock.sendto(packet,target)



    def send_SYN(self,target):
        print("[TCP] send a packet(SYN) to %s : %s" %target,"(seq = %s, ack_num = %s)"  %(self.seq,self.ack_num))
        syn_packet = self.TCPheader(5,self.seq,0,SYN,window_size)
        self.sock.sendto(syn_packet,target)

    def send_SYNACK(self,target):
        print("[TCP] send a packet(SYNACK) to %s : %s" %target,"(seq = %s, ack_num = %s)"  %(self.seq,self.ack_num))
        synack_packet = self.TCPheader(5,self.seq,self.ack_num,SYNACK,window_size)
        self.sock.sendto(synack_packet,target)

    def send_ACK(self,target):
        print("[TCP] send a packet(ACK) to %s : %s" %target,"(seq = %s, ack_num = %s)"  %(self.seq,self.ack_num))
        ack_packet = self.TCPheader(5,self.seq,self.ack_num,ACK,window_size)
        self.sock.sendto(ack_packet,target)

    def send_FIN(self,target):
        print("[TCP] send a packet(FIN) to %s : %s" %target,"(seq = %s, ack_num = %s)"  %(self.seq,self.ack_num))
        ack_packet = self.TCPheader(5,self.seq,self.ack_num,FIN,window_size)
        self.sock.sendto(ack_packet,target)

    def send_FINACK(self,target):
        print("[TCP] send a packet(FINACK) to %s : %s" %target,"(seq = %s, ack_num = %s)"  %(self.seq,self.ack_num))
        ack_packet = self.TCPheader(5,self.seq,self.ack_num,FINACK,window_size)
        self.sock.sendto(ack_packet,target)    

    def three_way_handshake(self,target):
        print("=======================================")
        print("[system] start three-way handshake: ")
        self.send_SYN(target)
        
        while(True):
            indata,addr = self.sock.recvfrom(MSS)
            sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
            if sp != self.sport or dp != self.dport or flags != SYNACK:
                continue
            
            #receive SYNACK
            print("[system] receive packet(SYN/ACK) from %s : %s " %addr,"(seq = %s, ack_num = %s)"  %(seq,ack_num))

            self.seq = ack_num
            self.ack_num = seq + 1
            self.send_ACK(target)
            print("[system] finished three-way handshake. ")
            print("=======================================")
            # finish three-way handshake
            return True

    def four_way_handshake(self,target):
        print("=======================================")
        print("[system] start four-way handshake: ")
        self.send_FIN(target)
        
        while(True):
            indata,addr = self.sock.recvfrom(MSS)
            sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
            if sp != self.sport or dp != self.dport or flags != FINACK:
                continue
            
            #receive SYNACK
            print("[system] receive packet(FIN/ACK) from %s : %s " %addr,"(seq = %s, ack_num = %s)"  %(seq,ack_num))

            self.seq = ack_num
            self.ack_num = seq + 1
            self.send_ACK(target)
            print("[system] finished four-way handshake. ")
            print("=======================================")
            # finish four-way handshake
            return True
    
    def close(self):
        exit(1)