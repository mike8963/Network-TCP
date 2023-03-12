from TCP import *



if __name__ == "__main__":
    
    sock = TCPprotocol()
    sock.three_way_handshake(server_IP)
    status = 0
    while(True):  
        if status == 0:
            print("[system] choose a option number")
            print("[system] (1) video")
            print("[system] (2) dns")
            print("[system] (3) math")
            print("[system] (4) exit")
            choose = int(input())
            if choose == 1:
                data = "video"
            elif choose == 2:
                data = "dns"
            elif choose == 3:
                data = "math"
            elif choose == 4:
                # four-way handshake
                sock.four_way_handshake(server_IP)
                sock.close()
            else:
                print("[system] please input a number")
                continue
            
            status = choose

            sock.send_packet(data,server_IP,0)

            indata,addr = sock.sock.recvfrom(MSS)
            sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
            data = indata[20:]
            sock.seq = ack_num
            sock.ack_num = seq + len(data)
            data = indata[20:].decode()

        elif status == 1:
            data = input("[system] please input video number: ")
            sock.send_packet(data,server_IP,0)
            new_filename = "./new_%s.mp4" %data

            indata,addr = sock.sock.recvfrom(MSS)
            sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
            data = indata[20:]
            sock.seq = ack_num
            sock.ack_num = seq + len(data)
           
            if data != "not found":
                while(True):
                    fileInfo_zise = struct.calcsize('128sl')
                    filename, filesize = struct.unpack('128sl',data)
                    
                    
                    recvd_size = 0
                    f = open(new_filename, 'wb')
                    sock.send_ACK(server_IP)

                    while not recvd_size == filesize:
                        indata,addr = sock.sock.recvfrom(MSS)
                        sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
                        data = indata[20:]
                        sock.seq = ack_num
                        sock.ack_num = seq + len(data)
                        

                        f.write(data)
                        recvd_size += len(data)
                        sock.send_ACK(server_IP)
                    f.close()
                    print("[system] video downloaded")
                    print("=======================================")
                    status = 0
                    break
            else:
                print("[system] video not found")
        elif status == 2:
            print("[system] please input website: ")
            data = input()
            sock.send_packet(data,server_IP,0)

            indata,addr = sock.sock.recvfrom(MSS)
            sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
            data = indata[20:]
            sock.seq = ack_num
            sock.ack_num = seq + len(data)
            data = indata[20:].decode()
            print("[system] dns result: %s" %data)
            print("=======================================")
            sock.send_ACK(server_IP)
            status = 0
        elif status == 3:
            print("[system] please choose a function")
            print("[system] (1) add")
            print("[system] (2) sub")
            print("[system] (3) mul")
            print("[system] (4) div")
            print("[system] (5) power")
            print("[system] (6) square root")
            
            '''
            0x001: add
            0x010: sub
            0x011: mul
            0x100: div
            0x101: power
            0x110: square root
            '''
            choose = int(input())
            if choose <= 0 or choose >6:
                print("[system] please input number 1~6 to choose function")
                continue

            if choose == 6:
                print("[system] please input a number")
                a = float(input("a: "))
                b = float(0)
            else:
                print("[system] please input two number")
                a = float(input("a: "))
                b = float(input("b: "))

            data = struct.pack('!Bff',choose,a,b)
            sock.send_packet(data,server_IP,1)

            indata,addr = sock.sock.recvfrom(MSS)
            sp,dp,seq,ack_num,head_len,flags,window,checksum,ug_ptr = struct.unpack('!HHIIBBHHH',indata[:20])
            data = indata[20:]
            sock.seq = ack_num
            sock.ack_num = seq + len(data)
            
            print("[system] result: ",struct.unpack('f',data)[0])
            status = 0



    sock.close()
