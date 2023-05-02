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
import copy



def dijkstra(len_topo_table, src, inf=9999999):
    broke = 999999
    addr_dict = copy.deepcopy(len_topo_table)
    addr_list = addr_dict.keys()
    for first_key in addr_list:
        for sed_key in addr_list:
            if first_key == sed_key:
                addr_dict[first_key][sed_key] = 0
            elif sed_key not in addr_dict[first_key]:
                addr_dict[first_key][sed_key] = broke
    # print('addr_dict',addr_dict)
    addr_dis_set = set()
    min_node = src
    dis = dict((k, inf) for k in addr_dict.keys())
    next_hop = dict((k, None) for k in addr_dict.keys())
    dis[src] = 0
    while len(addr_dis_set) < len(addr_dict):
        addr_dis_set.add(min_node)
        for w in addr_dict[min_node]:
            if dis[min_node] + addr_dict[min_node][w] < dis[w]:
                dis[w] = dis[min_node] + addr_dict[min_node][w]
                next_hop[w] = min_node
        new = inf
        for v in dis.keys():
            if v in addr_dis_set: continue
            if dis[v] < new:
                new = dis[v]
                min_node = v

    for key in dis:
        if dis[key] >= broke:
            next_hop.pop(key)

    src_neigh = list(len_topo_table[src].keys())
    src_neigh.append(src)
    # print(next_hop)
    # print('src_neigh',src_neigh)
    # print('if_all_neigh(next_hop,src_neigh)',if_all_neigh(next_hop,src_neigh))
    while not if_all_neigh(next_hop,src_neigh):
        for key in next_hop.keys():
            if next_hop[key] is None:
                continue
            if next_hop[key] not in src_neigh:
                next_hop[key] = next_hop[next_hop[key]]
                # print(next_hop)
    return dis, next_hop


def if_all_neigh(table:dict, neigh_list:list):
    for key in table.keys():
        if table[key] is None:
            continue
        if table[key] not in neigh_list:
            return False
    return True


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


def format_addr_str(addr_str):
    [hostname, port] = re.split(",", addr_str)
    port = int(port)
    ip = socket.gethostbyname(hostname)
    addr = Addr(ip=ip, port=port)
    return addr


def get_topology_table(filename):
    f = open(filename, "r")
    topology_table = {}
    for table_line in f:
        line_list = re.split("[\s]", table_line)
        addr_key = format_addr_str(line_list[0])
        topo_line = []
        for i in range(1, len(line_list)):
            addr_str = line_list[i]
            if addr_str != '':
                addr = format_addr_str(addr_str)
                topo_line.append(addr)
        topology_table[addr_key] = topo_line
    return topology_table


def add_len_topo_table(topology_table):
    len_topo_table = {}
    for key in topology_table:
        len_dict = {}
        for addr in topology_table[key]:
            len_dict[addr] = 1
        len_topo_table[key] = len_dict
    return len_topo_table


def get_forward_table(len_topo_table, addr):
    if len_topo_table == {}:
        return {}
    if len_topo_table[addr] == {}:
        return {}

    dis, next_hop = dijkstra(len_topo_table=len_topo_table, src=addr)
    next_hop.pop(addr)
    for key in next_hop:
        if next_hop[key] == addr:
            next_hop[key] = key
    return next_hop


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


def parse_args():
    parse = argparse.ArgumentParser(description='Emulator arg')
    parse.add_argument('-p', default=5000, type=int)
    parse.add_argument('-f', type=str)
    args = parse.parse_args()
    return args


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


def gen_packet_no_change_src(packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl, payload):
    header = encoder_header(packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl)
    payload = bytes(payload, "utf-8")
    packet_with_header = header + payload
    return packet_with_header


def get_neighbor_dict(payload):
    res = re.split(r'[:,{}\s]', payload)
    clean_list = []
    for i in range(len(res)):
        if res[i] != '':
            clean_list.append(res[i])
    if len(clean_list) % 3 != 0 or len(clean_list) == 0:
        print('something wrong with length')
        return None

    odr = int(len(clean_list) / 3)
    neighbor_info = {}
    for t in range(odr):
        key = Addr(clean_list[3 * t], int(clean_list[3 * t + 1]))
        neighbor_info[key] = int(clean_list[3 * t + 2])
    return neighbor_info


def handle_emulator_received_data(received_data):
    # payload = received_data[0][26:].decode('utf-8')
    packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl = decoder_header(received_data[0][:21])
    payload = received_data[0][21:].decode('utf-8')
    packet = Packet(packet_type, src_ip, src_port, dest_ip, dest_port, seq_num, ttl, payload, received_data[0])
    return packet


class Emulator(object):
    def __init__(self, emu_port, filename):
        self.emu_hostname = socket.gethostname()
        self.emu_ip = socket.gethostbyname(self.emu_hostname)
        self.emu_port = emu_port
        self.addr_cl = Addr(self.emu_ip, self.emu_port)
        self.buffer_size = 40960
        self.hello_interval = 50
        self.link_state_interval = 50
        self.neigh_living_time = 1000
        self.last_hello_time = None
        self.last_ls_time = None
        self.my_ls_seq_num = 1
        self.ttl = 10

        topology_table = get_topology_table(filename)
        self.len_topo_table = add_len_topo_table(topology_table)
        # update when get link state message and hello message error
        self.forward_table = get_forward_table(self.len_topo_table, self.addr_cl)
        # update when get hello message error
        # self.neighbors = self.len_topo_table[self.addr_cl].keys()

        self.seq_dict = dict((k, 0) for k in self.len_topo_table.keys())
        neigh_info = {'if_active': True, 'last_ac_time': datetime.now()}
        self.living_neighbor = dict((neigh, copy.deepcopy(neigh_info)) for neigh in self.len_topo_table[self.addr_cl].keys())

        self.emulator_socket = None

        self.print_topo_table()
        self.print_forward_table()

    def print_topo_table(self):
        print()
        print('Topology: ')
        for first_key in self.len_topo_table:
            if self.len_topo_table[first_key] == {}:
                continue
            line = str(first_key) + ' '
            for sed_key in self.len_topo_table[first_key]:
                line += str(sed_key) + ' '
            print(line)

    def print_forward_table(self):
        print('Forwarding table:')
        if self.forward_table == {}:
            print('None')
        else:
            for key in self.forward_table:
                line = str(key) + ' ' + str(self.forward_table[key])
                print(line)

    def forward(self):
        self.emulator_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.emulator_socket.bind(('', self.emu_port))
        self.emulator_socket.setblocking(0)

        self.last_hello_time = datetime.now()
        self.last_ls_time = datetime.now()

        while True:
            try:
                packet = None
                got_request_data = self.emulator_socket.recvfrom(self.buffer_size)
                packet = handle_emulator_received_data(got_request_data)
                # print(packet.packet_type)
                if packet.packet_type == 'H':

                    src_addr_cl = Addr(packet.src_ip, packet.src_port)
                    last_active_state = self.living_neighbor[src_addr_cl]['if_active']
                    neigh_info = {'if_active': True, 'last_ac_time': datetime.now()}
                    self.living_neighbor[src_addr_cl] = copy.deepcopy(neigh_info)
                    if src_addr_cl not in self.len_topo_table[self.addr_cl]:
                        self.len_topo_table[self.addr_cl][src_addr_cl] = 1
                        self.len_topo_table[src_addr_cl][self.addr_cl] = 1
                        self.forward_table = get_forward_table(self.len_topo_table, self.addr_cl)
                        self.send_ls_message(if_triggered=True)

                    if not last_active_state:
                        self.print_topo_table()
                        self.print_forward_table()

                elif packet.packet_type == 'L':
                    self.handle_ls_message(packet=packet)

                elif packet.packet_type == 'T':
                    # print('get trace packet',datetime.now())
                    self.handle_trace(packet=packet)

                else:
                    self.emulator_socket.sendto(packet.all_data, (packet.dest_ip, packet.dest_port))

            except BlockingIOError:
                none = None
            except ConnectionResetError:
                none = None  # print('close a connect')

            self.send_hello()
            self.send_ls_message(if_triggered=False)
            self.update_neigh_info()

        self.emulator_socket.close()

    def handle_trace(self, packet: Packet):
        received_src_addr = Addr(packet.src_ip, packet.src_port)
        received_dst_addr = Addr(packet.dest_ip, packet.dest_port)
        # print('received_src_addr', received_src_addr)
        # print('packet.ttl', packet.ttl)
        if packet.ttl <= 0:
            packet_with_header = gen_packet_with_header(packet_type=packet.packet_type, src_port=self.emu_port, dest_ip=packet.dest_ip, dest_port=packet.dest_port, seq_num=packet.seq_num, ttl=packet.ttl, payload=packet.payload)
            self.emulator_socket.sendto(packet_with_header, received_src_addr.net_addr)
        if packet.ttl > 0:
            packet.ttl -= 1
            packet_with_header = gen_packet_no_change_src(packet_type=packet.packet_type, src_ip=packet.src_ip, src_port=packet.src_port, dest_ip=packet.dest_ip, dest_port=packet.dest_port, seq_num=packet.seq_num, ttl=packet.ttl, payload=packet.payload)
            next_hop = self.forward_table[received_dst_addr]
            self.emulator_socket.sendto(packet_with_header, next_hop.net_addr)
        return

    def forward_received_ls_message(self, packet: Packet):
        src_addr_cl = Addr(packet.src_ip, packet.src_port)
        for neighbor_addr in self.living_neighbor.keys():
            if self.living_neighbor[neighbor_addr]['if_active'] and neighbor_addr != src_addr_cl:
                packet_with_header = gen_packet_no_change_src(packet_type='L', src_ip=packet.src_ip, src_port=packet.src_port, dest_ip=packet.dest_ip, dest_port=packet.dest_port, seq_num=packet.seq_num, ttl=packet.ttl - 1, payload=packet.payload)
                try:
                    self.emulator_socket.sendto(packet_with_header, neighbor_addr.net_addr)
                except ConnectionResetError:
                    none = None  # print('close a connect')

    def handle_ls_message(self, packet):
        neighbor_info = get_neighbor_dict(packet.payload)
        src_addr_cl = Addr(packet.src_ip, packet.src_port)
        if_change_topo_table = False

        if src_addr_cl == self.addr_cl:
            return
        if packet.seq_num > self.seq_dict[src_addr_cl]:
            self.seq_dict[src_addr_cl] = packet.seq_num
            if self.len_topo_table[src_addr_cl] != neighbor_info:
                self.len_topo_table[src_addr_cl] = copy.deepcopy(neighbor_info)
                for key in self.len_topo_table:
                    if key in neighbor_info:
                        self.len_topo_table[key][src_addr_cl] = neighbor_info[key]
                    elif src_addr_cl in self.len_topo_table[key]:
                        self.len_topo_table[key].pop(src_addr_cl)
                self.forward_table = get_forward_table(self.len_topo_table, self.addr_cl)
                if_change_topo_table = True
            if packet.ttl > 1:
                self.forward_received_ls_message(packet=packet)

        if if_change_topo_table:
            self.print_topo_table()
            self.print_forward_table()

        # print(self.seq_dict)  # print(self.len_topo_table[src_addr_cl])  # print(neighbor_info)

    def update_neigh_info(self):
        if_len_topo_table_changed = False
        for neighbor_addr in self.living_neighbor.keys():
            if self.living_neighbor[neighbor_addr]['if_active']:
                now_time = datetime.now()
                diff_milliseconds = get_diff_millisecond(start_time=self.living_neighbor[neighbor_addr]['last_ac_time'], end_time=now_time)
                if diff_milliseconds > self.neigh_living_time:
                    self.living_neighbor[neighbor_addr]['if_active'] = False
                    if neighbor_addr in self.len_topo_table[self.addr_cl]:
                        self.len_topo_table[self.addr_cl].pop(neighbor_addr)
                        self.len_topo_table[neighbor_addr].pop(self.addr_cl)
                        if_len_topo_table_changed = True

        if if_len_topo_table_changed:
            self.forward_table = get_forward_table(self.len_topo_table, self.addr_cl)
            # print('self.forward_table', self.forward_table)
            self.send_ls_message(if_triggered=True)

        if if_len_topo_table_changed:
            self.print_topo_table()
            self.print_forward_table()

        # print('self.living_neighbor', self.living_neighbor)
        # print('self.len_topo_table[self.addr_cl]', self.len_topo_table[self.addr_cl])
        # print('self.forward_table', self.forward_table)
        return

    def send_hello(self):
        now_time = datetime.now()
        diff_milliseconds = get_diff_millisecond(start_time=self.last_hello_time, end_time=now_time)
        if diff_milliseconds > self.hello_interval:
            # print('hello,', now_time)
            for neighbor_addr in self.living_neighbor.keys():
                if self.living_neighbor[neighbor_addr]['if_active']:
                    packet_with_header = gen_packet_with_header(packet_type='H', src_port=self.emu_port, dest_ip=neighbor_addr.ip, dest_port=neighbor_addr.port, seq_num=0, ttl=0, payload='')
                    try:
                        self.emulator_socket.sendto(packet_with_header, neighbor_addr.net_addr)
                    except ConnectionResetError:
                        none = None  # print('close a connect')
            self.last_hello_time = datetime.now()

    def send_ls_message(self, if_triggered):
        now_time = datetime.now()
        diff_milliseconds = get_diff_millisecond(start_time=self.last_ls_time, end_time=now_time)
        if diff_milliseconds > self.link_state_interval or if_triggered:
            # print('link state,', now_time)
            neighbor_info = self.len_topo_table[self.addr_cl]
            str_payload = str(neighbor_info)

            for neighbor_addr in self.living_neighbor.keys():
                if self.living_neighbor[neighbor_addr]['if_active']:
                    packet_with_header = gen_packet_with_header(packet_type='L', src_port=self.emu_port, dest_ip=neighbor_addr.ip, dest_port=neighbor_addr.port, seq_num=self.my_ls_seq_num, ttl=self.ttl, payload=str_payload)
                    try:
                        self.emulator_socket.sendto(packet_with_header, neighbor_addr.net_addr)
                    except ConnectionResetError:
                        none = None  # print('close a connect')
            self.last_ls_time = datetime.now()
            self.my_ls_seq_num += 1


def main(args):
    # print(args.p)
    emulator = Emulator(emu_port=args.p, filename=args.f, )
    emulator.forward()


if __name__ == '__main__':
    got_args = parse_args()

    main(got_args)
    try:
        None
    except:
        print("An exception occurred")
