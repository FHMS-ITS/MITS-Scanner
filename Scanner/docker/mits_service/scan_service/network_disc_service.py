import ipaddress
import json
import os

import netifaces
import nmap
from config import Config as conf
from nameko.rpc import rpc
import json

class NetworkDiscovery:
    name = "discovery_service"
    netinterfaces = netifaces.interfaces()
    interface_info = netifaces.ifaddresses(netinterfaces[1])
    own_ip = interface_info[2][0]['addr']

    @rpc
    def scan_active_hosts(self):
        '''Determines hosts which are online to reduce their number for gvm input
        or takes ips form previous scan'''
        if conf.Local.TAKE_PREV_IPS and os.path.exists(conf.Local.PATH_PREV_IPS) and os.path.getsize(conf.Local.PATH_PREV_IPS) > 0:
            with open(conf.Local.PATH_PREV_IPS, 'r') as ips_file:
                online_ips = json.load(ips_file)
        else:
            nm = nmap.PortScanner()

            nm.scan(arguments='-iL {} --excludefile {} -T5 --min-parallelism 100 --unprivileged'.format(conf.Local.PATH_SCANRANGES, conf.Local.PATH_EXCLUDE))
            online_ips = [x for x in nm.all_hosts()]
            print("Online IPS: ", online_ips)

            if self.own_ip in online_ips:
                online_ips.remove(self.own_ip)

            print("Final Online Ips: ", online_ips)

            with open(conf.Local.PATH_PREV_IPS, 'w+') as ips_file:
                json.dump(online_ips, ips_file)

        return online_ips

    @rpc
    def get_own_ip(self):
        return self.own_ip

    @rpc
    def get_total_ip_number(self, scan_ranges):
        total_ips = 0
        for ip_range in scan_ranges:
            total_ips = total_ips + ipaddress.ip_network(ip_range).num_addresses
        return total_ips
