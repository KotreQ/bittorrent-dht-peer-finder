import os
import socket
import threading
from collections import deque
from random import randbytes
from typing import Iterable

from .dht_exceptions import KRPCPacketError, KRPCRequestError
from .dht_packets import (
    KRPCFindNodeQueryPacket,
    KRPCFindNodeResponsePacket,
    KRPCMethodType,
    KRPCPacket,
    KRPCPacketType,
    KRPCPingQueryPacket,
    KRPCPingResponsePacket,
    KRPCQueryPacket,
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

ACTIVE_CHECK_DURATION = 30

CLOSEST_RESPONSE_COUNT = 16

FIND_NODE_RESPONSE_SIZE = 8


DEFAULT_CACHE_PATH = "./.cache/btdht.bin"


class BitTorrentDHTClient:
    def __init__(self):
        self.node_id = NodeID(randbytes(NODE_ID_SIZE))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("", 0))

        self.routing_table = RoutingTable(
            self.node_id, active_node_checker=self.check_nodes_connectivity
        )

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

        # purge after importing
        self.purge_routing_table()

        self.bootstrap()

        # purge once again after bootstrap
        self.purge_routing_table()

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

    def send_krpc_request(
        self, krpc_packet: KRPCQueryPacket, addr: IpAddrPort
    ) -> Request:
        request = TimedRequest((krpc_packet, addr), REQUEST_TIMEOUT)
        self.request_handler.add_request(request)

        try:
            self.sock.sendto(krpc_packet.to_bencoded(), addr.to_tuple())
        except OSError:
            request.resolve(None, False)

        return request

    def resolve_krpc_query(self, krpc_packet: KRPCQueryPacket, addr: IpAddrPort):
        match krpc_packet.METHOD_TYPE:
            case KRPCMethodType.PING:
                response_packet = KRPCPingResponsePacket(
                    {b"id": self.node_id.node_id}, krpc_packet.transaction_id
                )

            case KRPCMethodType.FIND_NODE:
                target_node_id = NodeID(krpc_packet.arguments[b"target"])
                nodes_info = self.routing_table.get_closest(
                    target_node_id, FIND_NODE_RESPONSE_SIZE
                )
                compact_nodes_info = b"".join(
                    node_info.to_compact() for node_info in nodes_info
                )
                response_packet = KRPCFindNodeResponsePacket(
                    {b"id": self.node_id.node_id, b"nodes": compact_nodes_info},
                    krpc_packet.transaction_id,
                )

        self.sock.sendto(response_packet.to_bencoded(), addr.to_tuple())

    def listener_worker(self):
        while True:
            try:
                recv_data, recv_addr = self.sock.recvfrom(RECEIVE_BUFFER_SIZE)
            except OSError:
                continue

            recv_addr = IpAddrPort(*recv_addr)

            try:
                recv_krpc_packet = KRPCPacket.from_bencoded(recv_data)
            except KRPCPacketError:
                continue

            transaction_requests = self.request_handler.to_dict(
                lambda request: request.input_data[0].transaction_id
            ).get(recv_krpc_packet.transaction_id, [])

            match recv_krpc_packet.PACKET_TYPE:
                case KRPCPacketType.RESPONSE:
                    for unresolved_request in transaction_requests:
                        request_packet, request_addr = unresolved_request.input_data

                        if recv_addr == request_addr:
                            try:
                                # check if packet is of valid type
                                required_response_type = KRPCResponsePacket.create_type(
                                    request_packet.METHOD_TYPE
                                )
                                recv_krpc_packet = required_response_type.from_bencoded(
                                    recv_data
                                )
                                success = True
                            except KRPCPacketError:
                                success = False

                            unresolved_request.resolve(recv_krpc_packet, success)
                            break

                case KRPCPacketType.ERROR:
                    for unresolved_request in transaction_requests:
                        request_packet, request_addr = unresolved_request.input_data

                        if recv_addr == request_addr:
                            unresolved_request.resolve(recv_krpc_packet, False)
                            break

                case KRPCPacketType.QUERY:
                    self.resolve_krpc_query(recv_krpc_packet, recv_addr)

    def check_nodes_connectivity(
        self, nodes: Iterable[NodeInfo], *, strict_check: bool = False
    ) -> list[bool]:
        is_online: list[bool] = []

        nodes = list(nodes)

        ping_requests = [
            self.send_krpc_request(
                KRPCPingQueryPacket({b"id": self.node_id.node_id}, None),
                node.ip_addr_port,
            )
            if node.get_seen_time_delta() > ACTIVE_CHECK_DURATION or strict_check
            else None
            for node in nodes
        ]

        for node, ping_request in zip(nodes, ping_requests):
            if ping_request is None:
                is_online.append(True)
                continue
            ping_request.wait()
            ping_success, _ = ping_request.get_result()
            if ping_success:
                node.update_seen_time()
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
