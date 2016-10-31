
#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet

import socket, sys
import select
import random
import packet_tool
import ast
from struct import *

SHOW_IP = "0"
GROUP_CHAT = "1"
CHECK_IF_ONLINE = "2"

# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time

    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w

    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

#create an INET, STREAMing socket
try:
    server_ip = raw_input('please input the ip of your server: ')
    cli_name = raw_input('pick up a name for yourself: ')
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
socket_list = [sys.stdin, s]

client_port = 1234 + int(random.random()*100)

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

            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            # print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

            udp_header = packet[iph_length:iph_length+8]

            #now unpack them 
            source_port, dest_port, udp_length, udp_checksum  = unpack('!HHHH' , udp_header)
            
            udph_length = 8

            if dest_port == client_port:

                print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' UDP  length : ' + str(udp_length)

                h_size = iph_length + udph_length
                data_size = len(packet) - h_size

                #get data from the packet
                data = packet[h_size:]

                # client receive udp from server
                if source_port == 1234:

                    if not data:
                        print '\nDisconnected from chat server'
                        sys.exit()
                    else:
                        print 'Data : ' + data
                        # sys.stdout.write("enter command: ")
                        # sys.stdout.flush()

                        if data[0] == SHOW_IP:
                            client_list = ast.literal_eval(data[1:])
                            print client_list
                        elif data[0] == GROUP_CHAT:
                            print 'GROUP_CHAT'
                        elif data[0] == CHECK_IF_ONLINE:
                            receiver = (server_ip, source_port)
                            print receiver
                            msg = cli_name
                            packet_tool.send_packet(client_port, receiver, msg, s)

                else:
                    print source_port
                    print data

                receiver_port = source_port
                receiver_ip = str(s_addr)
        else:
            msg = sys.stdin.readline()


            # now start constructing the packet

            #source_ip = '10.0.2.15'
            source_ip = '127.0.0.1'
            # dest_ip = '172.18.181.227' # or socket.gethostbyname('www.google.com')
            dest_ip = server_ip # or socket.gethostbyname('www.google.com')

            command = msg[0:3]
            user_data = msg


            # udp header fields
            udp_source = client_port   # source port
            udp_dest = 1234   # destination port
            
            if command == "p2p":
                receiver_port = int(msg[3:8])
                user_data = msg[8:]

                # receiver_port = input("receiver_port: ")

                udp_dest = receiver_port
                print 'udp_dest: ', udp_dest

            elif command == "\ip":
                user_data = '0'
            else:
                user_data = "1" + user_data

            # final full packet - syn packets dont have any data
            packet = packet_tool.construct_packet(source_ip, dest_ip, udp_source, udp_dest, user_data)


            s.sendto(packet, (dest_ip, 0)) #dest_addr
