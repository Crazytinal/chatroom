from struct import *
import socket

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

def construct_packet(src_ip, dst_ip, src_port, dst_port, user_data=""):
    # udp header fields
    udp_source = src_port   # source port
    udp_dest = dst_port   # destination port
    udp_length = 8+len(user_data)
    udp_check = 0

    # the ! in the pack format string means network order
    udp_header_for_checksum = pack('!HHHH' , udp_source, udp_dest,udp_length, udp_check)

    # construct the pseudo header
    psh = construct_udp_pseudo_header(src_ip, dst_ip, udp_header_for_checksum, user_data)

    # pad the psh with 0 octect to make it a multiple of 2 octets
    if len(user_data) % 2 == 1:
        psh = psh + '\0'
    udp_check = checksum(psh)

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    udp_header = pack('!HHH' , udp_source, udp_dest, udp_length) + pack('H', udp_check)

    # final full packet 
    packet =  udp_header + user_data

    return packet


def construct_udp_pseudo_header(src_ip, dst_ip, udp_header_for_checksum, user_data):

    # pseudo header fields
    source_address = socket.inet_aton( src_ip )
    dest_address = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_UDP
    udp_length = 8+len(user_data)

    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , udp_length);
    psh = psh + udp_header_for_checksum + user_data

    return psh

def send_packet(src_port, receiver, msg, sock):
    # udp header fields
    udp_source = src_port
    udp_dest = receiver[1]

    source_ip = '127.0.0.1' # TODO  get ip
    dest_ip = receiver[0]

    user_data = msg

    packet =  construct_packet(source_ip, dest_ip, udp_source, udp_dest, user_data)
    sock.sendto(packet, (dest_ip, 0)) #dest_addr    

def broadcast(sender, msg, receivers, sock): 
    server_port = 1234
    for receiver in receivers:
        if receiver != sender:
            # try:
                send_packet(server_port, receiver, msg, sock)
