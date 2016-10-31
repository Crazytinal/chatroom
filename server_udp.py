
#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet

import socket, sys
import select
from struct import *
import packet_tool

def broadcast(sender, msg): 
    
    # udp header fields
    udp_source = 1234
    source_ip = '127.0.0.1' # TODO  get ip
    user_data = msg


    for receiver in client_list:
        if receiver != sender:
            try:

                udp_dest = receiver[1]
                dest_ip = receiver[0]
                packet =  packet_tool.construct_packet(source_ip, dest_ip, udp_source, udp_dest, user_data)
                s.sendto(packet, (dest_ip, 0)) #dest_addr
            except:
                print 'fuck'



#create an INET, datagram socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
except socket.error , msg:
    # print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
socket_list = [sys.stdin, s]

client_list = []

while True:
    read_sockets, write_sockets, error_sockets = select.select(socket_list , [], [])
    for sock in read_sockets:
        if sock  == s:
            packet = s.recvfrom(65565)

            #packet string from tuple
            packet = packet[0]

            #take first 20 characters for the ip header
            ip_header = packet[0:20]

            #now unpack them :)
            iph = unpack('!BBHHHBBH4s4s' , ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4

            # ttl = iph[5]
            # protocol = iph[6]
            s_addr = str(socket.inet_ntoa(iph[8]));
            d_addr = str(socket.inet_ntoa(iph[9]));

            # print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)
            # print s_addr, d_addr


            udp_header = packet[iph_length:iph_length+8]

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
            # print udph
            source_port = udph[0]
            dest_port = udph[1]
            udp_length = udph[2]
            udp_checksum = udph[3]
            udph_length = 8

            # server port: 1234    client port: 4321  
            # in this case, server receive udp from client
            if dest_port == 1234 :
                sender = (s_addr,source_port)

                if sender not in client_list:
                    client_list.append((s_addr,source_port))
                print client_list

                print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' UDP  length : ' + str(udp_length)

                h_size = iph_length + udph_length
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]

                if not data:
                    print '\nDisconnected from chat server'
                    sys.exit()
                else:
                    print 'Data : ' + data

                    # client want ip list

                    # client want to with group
                    sys.stdout.write("enter command: ")
                    sys.stdout.flush()
        else:
            msg = sys.stdin.readline()

            broadcast(sender,msg)






