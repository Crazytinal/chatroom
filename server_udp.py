
#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet

import socket, sys
import select
from struct import *
import packet_tool


SHOW_IP = "0"
GROUP_CHAT = "1"






#create an INET, datagram socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
except socket.error , msg:
    # print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
socket_list = [sys.stdin, s]

client_list = []
server_port = 1234

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
            if dest_port == server_port :
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
                    command = data[0]
                    print command

                    if command == GROUP_CHAT:
                        packet_tool.broadcast(sender, data[1:], client_list, s)
                    elif command == SHOW_IP:
                        ip_info = str(client_list)
                        packet_tool.send_packet(server_port, sender, SHOW_IP+ip_info, s)


                    # client want to with group
                    sys.stdout.write("enter command: ")
                    sys.stdout.flush()
        else:
            msg = sys.stdin.readline()

            packet_tool.broadcast(' ',msg, client_list, s)






