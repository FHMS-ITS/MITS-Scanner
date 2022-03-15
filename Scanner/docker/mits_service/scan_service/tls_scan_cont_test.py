import eventlet;

eventlet.monkey_patch()

from nameko.testing.services import entrypoint_waiter
from nameko.containers import ServiceContainer
from nameko.standalone.rpc import ServiceRpcProxy

from main_service import MainService

amqp_config = {'AMQP_URI': 'amqp://guest:guest@localhost'}
container = ServiceContainer(MainService, config=amqp_config)
container.start()


def start_tls_scan(ips):
    with entrypoint_waiter(container, "initiate_tls_scan", timeout=144000):
        with ServiceRpcProxy('main_service', config=amqp_config) as cluster_rpc:
            host_info = cluster_rpc.initiate_tls_scan(ips=ips)


start_tls_scan(["192.168.22.11", "127.0.0.1"])
