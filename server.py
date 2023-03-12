from TCP import *

def create_server():
    sock = TCPprotocol()
    sock.sock.bind(server_IP)
    print("=======================================")
    print("[server] start server at %s :%s" %server_IP)
    while(True):
        
        indata,addr = sock.sock.recvfrom(MSS)
        sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
        if sp != sock.sport or dp != sock.dport or flags != SYN:
            exit(1)
        
        #receive SYN
        print("[server] receive packet(SYN) from %s : %s " %addr,"(seq = %s, ack_num = %s)"  %(seq,ack_num))
        
        sock.ack_num = seq + 1
        sock.send_SYNACK(addr)

        indata,addr = sock.sock.recvfrom(MSS)
        sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
        if sp != sock.sport or dp != sock.dport or flags != ACK:
            print("[server] doesn't receive ACK packet")
            exit(1)
        print("[server] receive a packet(ACK) from %s : %s" %addr, "(seq = %s, ack_num = %s)" %(seq,ack_num))
        print("[server] finished three-way handshake. ")
        print("=======================================")
        status = 0
        while(True):
            indata, addr = sock.sock.recvfrom(MSS)
            sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
            data = indata[20:]
            sock.seq = ack_num
            sock.ack_num = seq + len(data)

            if len(data) == 0 and flags == ACK:
                print("[server] receive a packet(ACK) from %s : %s" %addr, "(seq = %s, ack_num = %s)" %(seq,ack_num))
            elif len(data) == 0 and flags == FIN:
                print("[server] receive a packet(FIN) from %s : %s" %addr, "(seq = %s, ack_num = %s)" %(seq,ack_num))
                sock.send_FINACK(addr)
                indata, addr = sock.sock.recvfrom(MSS)
                sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
                data = indata[20:]
                sock.seq = ack_num
                sock.ack_num = seq + len(data)
                
                if len(data) == 0 and flags == ACK:
                    print("[server] receive a packet(ACK) from %s : %s" %addr, "(seq = %s, ack_num = %s)" %(seq,ack_num))
                    print("[server] disconnect with %s : %s" %addr)
                    break
            elif status == 0:
                data = indata[20:].decode()
                if data == "video":
                    print("[server] receive a video transmit request from %s : %s" %addr)
                    status = 1
                elif data == "dns":
                    print("[server] receive a dns transmit request from %s : %s" %addr)
                    status = 2
                elif data == "math":
                    print("[server] receive a math transmit request from %s : %s" %addr)
                    status = 3
                #elif data == "exit"
                #   TCP four-way handshake
            
                sock.send_ACK(addr)

            elif status == 1:
                data = indata[20:].decode()
                filename = "./%s.mp4" %data
                if os.path.isfile(filename):
                    fileInfo = struct.calcsize('128sl')
                    filename = os.path.basename(filename).encode('utf-8')
                    filesize = os.stat(filename).st_size
                    fhead = struct.pack('128sl', filename, filesize)
                    sock.send_packet(fhead,addr,1)
                    f= open(filename,'rb')
                    while(True):
                        indata, addr = sock.sock.recvfrom(MSS)
                        sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
                        data = indata[20:]
                        if flags == ACK:
                            print("[server] receive a packet(ACK) from %s : %s"%addr," (seq = %s, ack_num = %s)" %(seq,ack_num))
                            sock.seq = ack_num
                            sock.ack_num = seq + len(data)
                            data = f.read(MSS - TCPheader_len)
                            if not data:
                                print("[server] video transmit finish")
                                status = 0
                                break
                            print("[server] send %s Bytes"%(len(data)+TCPheader_len), " to %s : %s" %addr," (seq = %s, ack_num = %s)"  %(sock.seq,sock.ack_num))
                            sock.send_packet(data,addr,1)
                        
                else:
                    sock.send_packet("not found",addr,0)

            elif status == 2:
                data = indata[20:].decode()
                print("[server] receive : %s" %data)
                result = dns_function(data)
                print("[server] return result %s" %result)
                sock.send_packet(result,addr,0)
                status = 0

            elif status == 3:
                choose,a,b, = struct.unpack('!Bff',indata[20:])
                print('[server] receive: function %s,a = %s,b = %s' %(choose,a,b))
                if choose == 1:
                    res = a + b
                elif choose == 2:
                    res = a - b
                elif choose == 3:
                    res = a * b
                elif choose == 4:
                    res = a / b
                elif choose == 5:
                    res = pow(a,b)
                elif choose == 6:
                    res = np.sqrt(a)
                data = struct.pack('f',res)
                print("[server] result: ",res)
                sock.send_packet(data,addr,1)

                status = 0
if __name__ == "__main__":
    create_server()
    

