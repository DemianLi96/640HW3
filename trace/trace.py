import argparse
import os.path
import sys
import threading
from time import ctime, sleep
import struct
import socket
from datetime import datetime
import ipaddress
import re
from datetime import datetime
import random
import re
import socket


class Addr(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.net_addr = (ip, port)

    def __hash__(self):
        return hash(self.ip + str(self.port))

    def __eq__(self, other):
        if self.ip == other.ip and self.port == other.port:
            return True

    def __str__(self):
        return self.ip + ',' + str(self.port)

    def __repr__(self):
        return str(self)




def encoder_header(packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl):
    src_ip_int = int(ipaddress.ip_address(src_ip))
    dest_ip_int = int(ipaddress.ip_address(dest_ip))
    packet_type = bytes(packet_type, "utf-8")
    udp_header = struct.pack("!cLHLHLL", packet_type, src_ip_int, src_port, dest_ip_int, dest_port, seq_num, ttl)
    return udp_header


def decoder_header(udp_header):
    unpack_udp_header = struct.unpack("!cLHLHLL", udp_header)
    packet_type = unpack_udp_header[0].decode('utf8', errors='ignore')
    src_ip = str(ipaddress.ip_address(unpack_udp_header[1]))
    src_port = unpack_udp_header[2]
    dest_ip = str(ipaddress.ip_address(unpack_udp_header[3]))
    dest_port = unpack_udp_header[4]
    seq_num = unpack_udp_header[5]
    ttl = unpack_udp_header[6]
    # print('decoder, ', priority, src_ip, src_port, dest_ip, dest_port, layer_two_len, packet_type, sequence_number, data_length)
    return packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl


def get_diff_millisecond(start_time, end_time):
    diff_seconds = (end_time - start_time).seconds + (end_time - start_time).microseconds / 1000000
    return diff_seconds * 1000





class Packet(object):
    def __init__(self, packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl, payload, all_data):
        self.packet_type = packet_type
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.seq_num = seq_num
        self.ttl = ttl
        self.payload = payload
        self.all_data = all_data


def gen_packet_with_header(packet_type, src_port, dest_ip, dest_port, seq_num, ttl, payload):
    hostname = socket.gethostname()
    src_ip = socket.gethostbyname(hostname)
    header = encoder_header(packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl)
    payload = bytes(payload, "utf-8")
    packet_with_header = header + payload
    return packet_with_header






def handle_tracer_received_data(received_data):
    # payload = received_data[0][26:].decode('utf-8')
    packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl = decoder_header(received_data[0][:21])
    payload = received_data[0][21:].decode('utf-8')
    packet = Packet(packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl, payload, received_data[0])
    return packet






class Tracer(object):
    def __init__(self, trace_port ,src_emu_hostname,src_emu_ip,src_emu_port,
                 dst_hostname,dst_ip,dst_port,debug_opt):
        self.trace_port = trace_port
        hostname = socket.gethostname()
        self.trace_ip = socket.gethostbyname(hostname)

        self.src_emu_hostname = src_emu_hostname
        self.src_emu_ip = src_emu_ip
        self.src_emu_port = src_emu_port
        self.src_emu_addr = Addr(self.src_emu_ip,self.src_emu_port)

        self.dst_hostname = dst_hostname
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.dst_addr = Addr(self.dst_ip,self.dst_port)

        self.buffer_size = 40960
        self.debug_opt = debug_opt
        self.tracer_socket = None
        self.ttl = None

    def print_packet_info(self,packet: Packet, send_receive: str):
        if self.debug_opt == 1:
            print(send_receive)
            print('The source ip and port is ', str(Addr(packet.src_ip, packet.src_port)))
            print('The dest ip and port is ', str(Addr(packet.dest_ip, packet.dest_port)))
            print('The ttl of the packet is ', packet.ttl)
            print()


    def forward(self):
        self.tracer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tracer_socket.bind(('', self.trace_port))
        self.ttl = -1
        hop = 0

        hop_list = []
        received_addr_list = []
        while True:
            self.ttl += 1
            hop += 1

            packet_with_header = gen_packet_with_header(packet_type='T', src_port=self.trace_port, dest_ip=self.dst_ip, dest_port=self.dst_port, seq_num=0, ttl=self.ttl, payload='')
            send_packet = Packet(packet_type='T',src_ip=self.trace_ip, src_port=self.trace_port, dest_ip=self.dst_ip, dest_port=self.dst_port, seq_num=0, ttl=self.ttl, payload='',all_data='')
            self.print_packet_info(packet=send_packet,send_receive='Sending packet')


            self.tracer_socket.sendto(packet_with_header, self.src_emu_addr.net_addr)
            got_request_data = self.tracer_socket.recvfrom(self.buffer_size)
            packet = handle_tracer_received_data(got_request_data)
            self.print_packet_info(packet=packet, send_receive='Receiving packet')
            received_addr = Addr(packet.src_ip, packet.src_port)

            hop_list.append(hop)
            received_addr_list.append(received_addr)

            if received_addr == self.dst_addr:
                print('Hop#   IP,    Port')
                for i in range(len(hop_list)):
                    print(str(hop_list[i]) + ' ' + str(received_addr_list[i]))
                print('TERMINATES')
                break
        self.tracer_socket.close()


def main(args):
    trace_port = int(args.a)
    src_emu_hostname = args.b
    src_emu_ip = socket.gethostbyname(src_emu_hostname)
    src_emu_port = int(args.c)
    dst_hostname = args.d
    dst_ip = socket.gethostbyname(dst_hostname)
    dst_port = int(args.e)
    debug_opt = int(args.f)
    tracer = Tracer(trace_port=trace_port,src_emu_hostname=src_emu_hostname,src_emu_ip=src_emu_ip,src_emu_port=src_emu_port,dst_hostname=dst_hostname,dst_ip=dst_ip,dst_port=dst_port,debug_opt=debug_opt)
    tracer.forward()

def parse_args():
    parse = argparse.ArgumentParser(description='route trace arg')
    parse.add_argument('-a', default=7000, type=int)
    parse.add_argument('-b', type=str)
    parse.add_argument('-c', type=int)
    parse.add_argument('-d', type=str)
    parse.add_argument('-e', type=int)
    parse.add_argument('-f', type=int)

    args = parse.parse_args()
    return args


if __name__ == '__main__':
    got_args = parse_args()

    main(got_args)
    try:
        None
    except:
        print("An exception occurred")
