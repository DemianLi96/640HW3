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
                addr_dict[first_key][sed_key]=0
            elif sed_key not in addr_dict[first_key]:
                addr_dict[first_key][sed_key] = broke
    print('addr_dict',addr_dict)
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
    return dis, next_hop


class Addr(object):
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

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
        for i in range(1,len(line_list)):
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

    dis, next_hop = dijkstra(len_topo_table=len_topo_table,src=addr)
    next_hop.pop(addr)
    for key in next_hop:
        if next_hop[key] == addr:
            next_hop[key] = key
    return next_hop

def main():
    topology_table = get_topology_table('topology.txt')
    len_topo_table = add_len_topo_table(topology_table)

    addr = Addr('172.20.176.1',6002)
    print(len_topo_table)
    print(len_topo_table[addr].keys())
    forward_table = get_forward_table(len_topo_table, addr)
    print(forward_table)
    dic = {}
    dic2= dic.copy()
    dic2['2']=1
    print(dic)
    print(dic2)


if __name__ == '__main__':
    main()
