
#Packet sniffer in python for Linux
#Sniffs only incoming TCP packet

import socket, sys
import select
from struct import *

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
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()

# receive a packet
socket_list = [sys.stdin, s]

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

            #now unpack them :)
            udph = unpack('!HHHH' , udp_header)
            # print udph
            source_port = udph[0]
            dest_port = udph[1]
            udp_length = udph[2]
            udp_checksum = udph[3]
            udph_length = 8
            if dest_port == 4321  and source_port == 1234:
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
                    sys.stdout.write("enter command: ")
                    sys.stdout.flush()
        else:
            msg = sys.stdin.readline()


            # now start constructing the packet
            packet = '';

            #source_ip = '10.0.2.15'
            source_ip = '127.0.0.1'
            #dest_ip = '172.18.181.227' # or socket.gethostbyname('www.google.com')
            dest_ip = '127.0.0.1' # or socket.gethostbyname('www.google.com')



            user_data = msg

            # udp header fields
            udp_source = 4321   # source port
            udp_dest = 1234   # destination port
            udp_length = 8+len(user_data)
            udp_check = 0

            # the ! in the pack format string means network order
            udp_header = pack('!HHHH' , udp_source, udp_dest,udp_length, udp_check)


            # pseudo header fields
            source_address = socket.inet_aton( source_ip )
            dest_address = socket.inet_aton(dest_ip)
            placeholder = 0
            protocol = socket.IPPROTO_UDP

            psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , udp_length);
            psh = psh + udp_header + user_data;

            if len(user_data) % 2 == 1:
                psh = psh + '\0'
            udp_check = checksum(psh)

            # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
            udp_header = pack('!HHH' , udp_source, udp_dest, udp_length) + pack('H', udp_check)

            # final full packet - syn packets dont have any data
            packet =  udp_header + user_data


            s.sendto(packet, (dest_ip, 0)) #dest_addr
