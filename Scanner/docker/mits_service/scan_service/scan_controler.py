import eventlet

eventlet.monkey_patch()

from nameko.testing.services import entrypoint_waiter, EntrypointWaiterTimeout
from nameko.containers import ServiceContainer
from nameko.standalone.rpc import ServiceRpcProxy
from nameko.exceptions import RemoteError

import logging
import threading
from time import sleep

from main_service import MainService
from config import Config as conf

amqp_config = {'AMQP_URI': 'amqp://guest:guest@rabbitmq'}
container = ServiceContainer(MainService, config=amqp_config)
container.start()
scan_complete = False
gvm_down = False
gvm_over_90 = False
left_ips = []


def send_message_to_server(message, is_progress):
    try:
        with entrypoint_waiter(container, "send_status_message_to_server", timeout=30):
            with ServiceRpcProxy('main_service', config=amqp_config) as cluster_rpc:
                print(cluster_rpc.send_status_message_to_server(message, is_progress))

    except RemoteError:
        print("SERVER COMMUNICATION ERROR")
        logging.error('SERVER COMMUNICATION ERROR')
    except EntrypointWaiterTimeout:
        print("SERVER COMMUNICATION timed out")
        logging.error("SERVER COMMUNICATION timed out")


def start_scan(ips, limit_ips=0):
    global left_ips
    with entrypoint_waiter(container, "initiate_scan", timeout=144000):
        with ServiceRpcProxy('main_service', config=amqp_config) as cluster_rpc:
            host_info = cluster_rpc.initiate_scan(ips=ips, limit_ips=limit_ips)
            left_ips = host_info["left_ips"]
            print(host_info["used_ips"])
            print(host_info["left_ips"])
            print(host_info["scan_msg"])
            logging.info(host_info["scan_msg"])
            send_message_to_server(host_info["scan_msg"], False)


def start_tls_scan(ips, limit_ips=0):
    with entrypoint_waiter(container, "initiate_tls_scan", timeout=144000):
        with ServiceRpcProxy('main_service', config=amqp_config) as cluster_rpc:
            host_info = cluster_rpc.initiate_tls_scan(ips=ips)


def report_thread_func():
    '''Pulls reports and sends reports to server'''
    report_counter = 0
    while not scan_complete:
        sleep(conf.Local.REPORT_PULL_TIME)
        report = "{}"
        try:
            with entrypoint_waiter(container, "pull_report", timeout=100):
                with ServiceRpcProxy('main_service', config=amqp_config) as cluster_rpc:
                    json_report = cluster_rpc.pull_report()
            try:
                f = open(conf.Local.PATH_JSONREPORT, 'r')
                report = f.read()
                f.close()
            except FileNotFoundError:
                pass
        except RemoteError:
            print("REPORT ERROR")
            logging.error('Report generation ERROR')
            continue
        except EntrypointWaiterTimeout:
            print("Report generation timed out")
            logging.error("Report generation timed out")
            continue

        try:
            with entrypoint_waiter(container, "send_json_report_to_server", timeout=100):
                with ServiceRpcProxy('main_service', config=amqp_config) as cluster_rpc:
                    send_status_message_to_server = cluster_rpc.send_json_report_to_server(report, report_counter)

        except RemoteError:
            print("SEND REPORT ERROR")
            logging.error('Report transmission ERROR')
        except EntrypointWaiterTimeout:
            print("Report transmission timed out")
            logging.error("Report transmission timed out")
        report_counter += 1


def progress_thread_func():
    '''Pulls progress and sends progress to server'''
    global scan_complete
    global gvm_over_90
    global gvm_down
    global left_ips
    tls_scan_complete = False

    while not scan_complete:
        sleep(conf.Local.PROGRESS_PULL_TIME)
        try:
            with entrypoint_waiter(container, "pull_progress", timeout=100):
                with ServiceRpcProxy('main_service', config=amqp_config) as cluster_rpc:
                    progress = cluster_rpc.pull_progress()
                    send_message_to_server(progress, True)
                    print(progress)
        except RemoteError:
            print("PROGRESS ERROR")
            logging.error('PROGRESS ERROR')
        except EntrypointWaiterTimeout:
            print("PROGRESS timed out")
            logging.error("PROGRESS timed out")

        try:
            with entrypoint_waiter(container, "pull_tls_scan_progress", timeout=30):
                with ServiceRpcProxy('main_service', config=amqp_config) as cluster_rpc:
                    tls_scan_complete = cluster_rpc.pull_tls_scan_progress()
        except RemoteError:
            print("TLS Scan COMMUNICATION Error")
            logging.error('TLS Scan COMMUNICATION Error')
        except EntrypointWaiterTimeout:
            print("TLS Scan COMMUNICATION Error")
            logging.error("TLS Scan COMMUNICATION Error")

        # If the scan was over 90% gvm has likely not crashed and the scan is not restarted
        if any(prog > "50" for prog in progress):
            gvm_over_90 = True

        # If a scan has not reached 90% and all scans return -1, gvm has likely crashed and is restarted
        if not gvm_down and not gvm_over_90 and all(prog == "-1" for prog in progress):
            gvm_down = True
            print("SCAN DOWN")
            continue

        # If gvm crashes a second time the system is rebooted
        if gvm_down and not gvm_over_90 and all(prog == "-1" for prog in progress):
            print("REBOOT")

        if gvm_over_90 and all(prog == "-1" for prog in progress) and not left_ips:
            print("COMPLETE")
            scan_complete = True

        if (len(progress) - progress.count("-1")) < conf.Gvm.MAX_PARALLEL and left_ips:
            start_scan(ips=left_ips, limit_ips=1)


start_scan(ips=0)
report_thread = threading.Thread(target=report_thread_func)
progress_thread = threading.Thread(target=progress_thread_func)
report_thread.start()
progress_thread.start()
report_thread.join()
progress_thread.join()

send_message_to_server("Scan completed", False)

container.stop()
print("Complete")
logging.info("Scan Complete")
