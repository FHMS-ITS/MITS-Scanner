import os
from datetime import datetime

from nameko.rpc import RpcProxy
from nameko.rpc import rpc
import logging

from config import Config as conf


class HostInfo:
    def __init__(self, used_ips, left_ips, scan_msg):
        self.used_ips = used_ips
        self.left_ips = left_ips
        self.scan_msg = scan_msg


user_ind = '0'
timehash = datetime.utcnow().strftime('%Y%m%d%H%M%S')


class MainService:
    '''Communicates with all other services'''
    name = "main_service"
    logging.basicConfig(filename='main.log', level=logging.INFO)

    network_disc_rpc = RpcProxy("discovery_service")
    scan_rpc = RpcProxy("scanner_service")
    server_rpc = RpcProxy("server_service")
    tls_scan_rpc = RpcProxy("tls_scan_service")
    if os.getenv('PROJECT_NAME'):
        user_id = os.getenv('PROJECT_NAME')
    else:
        user_id = 'test'

    @rpc
    def send_status_message_to_server(self, message, is_progress):
        return self.server_rpc.send_status_message(message, is_progress)

    @rpc
    def send_json_report_to_server(self, report, num):
        """Sends stored JSON report to server"""
        global user_ind
        global timehash
        return self.server_rpc.send_json_report(report, self.user_id + "_" + user_ind + "_" + timehash + "_" + str(num))

    @rpc
    def pull_report(self):
        """Initiates generation of a new JSON report and returns success message"""
        # global user_ind
        return self.scan_rpc.initiate_json_report_generation()

    @rpc
    def pull_progress(self):
        """Returns Scan progress"""
        global user_ind
        global timehash
        progress = self.scan_rpc.get_task_progress(self.user_id + "_" + user_ind + "_" + timehash)
        return progress

    @rpc
    def initiate_tls_scan(self, ips):
        """Starts TLS Scanner"""
        return self.tls_scan_rpc.initiate_scan(ips)

    @rpc
    def pull_tls_scan_progress(self):
        """Returns if TLS scan completed"""
        completed = self.tls_scan_rpc.get_scan_completed()
        return completed

    @rpc
    def initiate_scan(self, ips=0, limit_ips=0):
        """Starts Scan with provided ips or with active ips if no ips are provided
        Keyword arguments:
            ips -- List of ips to scan (default 0 -> Host discovery)
            limit_ips -- Limitation of how many ips should be scanned (default 0 -> LIMIT_FOR_TARGET * MAX_PARALLEL)
        """
        if ips == 0:
            active_hosts = self.network_disc_rpc.scan_active_hosts()

            if conf.Local.DELETE_ALL_GVM_TASKS:
                self.scan_rpc.delete_all()

            if conf.TLS.TLS_SCAN:
                tls_status = self.tls_scan_rpc.initiate_scan(active_hosts)
                print(tls_status)
        else:
            active_hosts = ips

        if limit_ips == 0:
            max_scan_size = conf.Gvm.LIMIT_FOR_TARGET * conf.Gvm.MAX_PARALLEL
        else:
            max_scan_size = limit_ips * conf.Gvm.LIMIT_FOR_TARGET
        current_scan_hosts = active_hosts[:max_scan_size]
        left_hosts = active_hosts[max_scan_size:]

        global user_ind
        user_ind = str(len(left_hosts))

        global timehash
        timehash = datetime.utcnow().strftime('%Y%m%d%H%M%S')

        host_info = {
            "used_ips": current_scan_hosts,
            "left_ips": left_hosts,
            "scan_msg": self.scan_rpc.start_scan(self.user_id + "_" + user_ind + "_" + timehash, current_scan_hosts)
        }
        return host_info