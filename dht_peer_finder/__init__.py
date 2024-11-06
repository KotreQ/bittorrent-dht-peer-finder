import os
import socket
import threading
from collections import deque
from random import randbytes
from typing import Iterable

from .dht_exceptions import KRPCPacketError, KRPCRequestError
from .dht_packets import (
    KRPCFindNodeQueryPacket,
    KRPCPacket,
    KRPCPingQueryPacket,
    KRPCResponsePacket,
)
from .dht_structures import NODE_ID_SIZE, IpAddrPort, NodeID, NodeInfo, RoutingTable
from .utils.request import Request, RequestHandler, TimedRequest

RECEIVE_BUFFER_SIZE = 65536

BITTORRENT_BOOTSTRAP_ADDRS = [
    ("router.bittorrent.com", 6881),
    ("router.utorrent.com", 6881),
    ("dht.transmissionbt.com", 6881),
]


REQUEST_TIMEOUT = 2

CLOSEST_RESPONSE_COUNT = 16


DEFAULT_CACHE_PATH = "./.cache/btdht.bin"


class BitTorrentDHTClient:
    def __init__(self):
        self.node_id = NodeID(randbytes(NODE_ID_SIZE))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 0))

        self.routing_table = RoutingTable(self.node_id)

        self.request_handler = RequestHandler()

        threading.Thread(target=self.listener_worker, daemon=True).start()

        for bootstrap_addr in BITTORRENT_BOOTSTRAP_ADDRS:
            bootstrap_addr = IpAddrPort(
                socket.gethostbyname(bootstrap_addr[0]), bootstrap_addr[1]
            )
            try:
                node_id = self.get_addr_nodeid(bootstrap_addr)
            except KRPCRequestError:
                continue
            bootstrap_node_info = NodeInfo(node_id, bootstrap_addr)
            self.routing_table.add_node(bootstrap_node_info)

        try:
            self.import_cache()
        except FileNotFoundError:
            pass

        self.bootstrap()

        self.export_cache()

    def export_cache(self, path: str = DEFAULT_CACHE_PATH):
        if os.path.isdir(path):
            raise IsADirectoryError(path)

        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(self.routing_table.export_data())

    def import_cache(self, path: str = DEFAULT_CACHE_PATH):
        with open(path, "rb") as f:
            self.routing_table.import_data(f.read())

    def send_krpc_request(self, krpc_packet: KRPCPacket, addr: IpAddrPort) -> Request:
        request = TimedRequest((krpc_packet, addr), REQUEST_TIMEOUT)
        self.request_handler.add_request(request)

        self.sock.sendto(krpc_packet.to_bencoded(), addr.to_tuple())

        return request

    def listener_worker(self):
        while True:
            recv_data, recv_addr = self.sock.recvfrom(RECEIVE_BUFFER_SIZE)

            recv_addr = IpAddrPort(*recv_addr)

            try:
                recv_krpc_packet = KRPCPacket.from_bencoded(recv_data)
            except KRPCPacketError:
                continue

            for unresolved_request in self.request_handler.to_list():
                request_packet, request_addr = unresolved_request.input_data

                required_response_type = KRPCResponsePacket.create_type(
                    request_packet.METHOD_TYPE
                )

                if (
                    recv_krpc_packet.same_transaction(request_packet)
                    and recv_addr == request_addr
                ):
                    try:
                        # check if packet is of valid type
                        recv_krpc_packet = required_response_type.from_bencoded(
                            recv_data
                        )
                        success = True
                    except KRPCPacketError:
                        success = False

                    unresolved_request.resolve(recv_krpc_packet, success)
                    break

    def check_nodes_connectivity(self, nodes: Iterable[NodeInfo]) -> list[bool]:
        is_online: list[bool] = []

        ping_requests = [
            self.send_krpc_request(
                KRPCPingQueryPacket({b"id": self.node_id.node_id}, None),
                node.ip_addr_port,
            )
            for node in nodes
        ]

        for ping_request in ping_requests:
            ping_request.wait()
            ping_success, _ = ping_request.get_result()
            is_online.append(ping_success)

        return is_online

    def purge_routing_table(self):
        nodes = self.routing_table.get_all_nodes()

        inactive_nodes = []

        for node, is_active in zip(nodes, self.check_nodes_connectivity(nodes)):
            if not is_active:
                inactive_nodes.append(node)

        self.routing_table.remove_nodes(inactive_nodes)

    def get_addr_nodeid(self, addr: IpAddrPort) -> NodeID:
        ping_request = self.send_krpc_request(
            KRPCPingQueryPacket({b"id": self.node_id.node_id}, None),
            addr,
        )

        ping_request.wait()
        ping_success, ping_response = ping_request.get_result()
        if not ping_success:
            raise KRPCRequestError("Ping request failed")

        return NodeID(ping_response.return_values[b"id"])

    def bootstrap(self):
        sent_requests: deque[Request] = deque()

        asked_nodes: set[NodeInfo] = set()
        stale_nodes: set[NodeInfo] = set()

        while True:
            closest_nodes = self.routing_table.get_closest(
                self.node_id, CLOSEST_RESPONSE_COUNT
            )

            nodes_to_ask = list(
                filter(lambda node: node not in asked_nodes, closest_nodes)
            )
            if not nodes_to_ask:
                break

            for request_node in nodes_to_ask:
                request = self.send_krpc_request(
                    KRPCFindNodeQueryPacket(
                        {b"id": self.node_id.node_id, b"target": self.node_id.node_id},
                        None,
                    ),
                    request_node.ip_addr_port,
                )
                sent_requests.append((request_node, request))
                asked_nodes.add(request_node)

            while sent_requests:
                request_node, request = sent_requests.popleft()
                request.wait()

                success, response_packet = request.get_result()
                if not success:
                    stale_nodes.add(request_node)
                    continue

                received_nodes = NodeInfo.from_compact_list(
                    response_packet.return_values[b"nodes"]
                )
                for request_node in received_nodes:
                    self.routing_table.add_node(request_node)

            self.routing_table.remove_nodes(stale_nodes)
