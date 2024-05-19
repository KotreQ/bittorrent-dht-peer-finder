import socket
from random import randbytes
from typing import Iterable

from . import bencode
from .dht_structures import NODE_ID_SIZE, IpAddrPort, NodeID, NodeInfo, RoutingTable

RECEIVE_BUFFER_SIZE = 65536


class BitTorrentDHTConnection:
    def __init__(
        self,
        bootstrap_addr: tuple[str, int],
        *,
        max_retries: int = 3,
        timeout: float = 0.5,
    ):
        self.node_id = NodeID(randbytes(NODE_ID_SIZE))

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

        self.max_retries = max_retries

        self.routing_table = RoutingTable(self.node_id)

        bootstrap_addr_info = IpAddrPort(
            socket.gethostbyname(bootstrap_addr[0]), bootstrap_addr[1]
        )
        bootstrap_node_id = self.get_addr_id(bootstrap_addr_info)
        bootstrap_node = NodeInfo(bootstrap_node_id, bootstrap_addr_info)

        self.routing_table.add_node(bootstrap_node)

    def send_krpc_query(
        self,
        query_type: str,
        query_args: bencode.BencodableDict,
        target: IpAddrPort | NodeID,
    ) -> bencode.BencodableDict:
        if isinstance(target, NodeID):
            target = self.routing_table.get_closest(target)[0].ip_addr_port

        target_addr = target.to_tuple()

        query_args["id"] = self.node_id.node_id

        retries = 0
        while retries <= self.max_retries:
            try:
                transaction_id = randbytes(2)

                request_data = bencode.encode(
                    {
                        "t": transaction_id,
                        "y": "q",  # message type = query
                        "q": query_type,
                        "a": query_args,
                    }
                )

                self.sock.sendto(request_data, target_addr)

                while True:
                    resp_data, resp_addr = self.sock.recvfrom(RECEIVE_BUFFER_SIZE)
                    if target_addr != resp_addr:
                        continue
                    try:
                        resp_data = bencode.decode(resp_data)
                        if not isinstance(resp_data, dict):
                            raise TypeError(
                                f"Response data: {resp_data!r} is of invalid type: {type(resp_data).__name__}"
                            )
                    except (ValueError, TypeError):
                        continue

                    if resp_data.get(b"t") != transaction_id:
                        continue

                    if resp_data.get(b"y") != b"r":  # message type != response
                        continue

                    if b"r" not in resp_data or not isinstance(resp_data[b"r"], dict):
                        continue

                    return resp_data[b"r"]

            except socket.timeout:
                retries += 1

        raise ConnectionError(f"Max retries exceeded: {self.max_retries}")

    def ping(self) -> bool:
        try:
            self.send_krpc_query("ping", {}, NodeID(randbytes(NODE_ID_SIZE)))
        except ConnectionError:
            return False
        return True

    def get_addr_id(self, addr: IpAddrPort) -> NodeID:
        resp = self.send_krpc_query("ping", {}, addr)
        if b"id" not in resp or not isinstance(resp[b"id"], bytes):
            raise TypeError("Node id not found in ping response")
        return NodeID(resp[b"id"])

    def get_torrent_peers(self, torrent_hash: NodeID) -> Iterable[IpAddrPort]:
        nodes_to_check: list[NodeInfo] = []
        for node in self.routing_table.iter_closest(torrent_hash):
            nodes_to_check.append(node)

            while nodes_to_check:
                node = nodes_to_check.pop()

                try:
                    resp = self.send_krpc_query(
                        "get_peers",
                        {"info_hash": torrent_hash.node_id},
                        node.ip_addr_port,
                    )
                    # request successful so add to routing table
                    self.routing_table.add_node(node)
                except ConnectionError:
                    continue

                if b"values" in resp and isinstance(resp[b"values"], list):
                    for value in resp[b"values"]:
                        if not isinstance(value, bytes):
                            raise TypeError(
                                f"Value: {value!r} is of invalid type: {type(value).__name__}"
                            )

                        value = IpAddrPort.from_compact(value)
                        yield value
                    continue

                elif b"nodes" in resp and isinstance(resp[b"nodes"], bytes):
                    encoded_node_infos = resp[b"nodes"]
                    node_infos = NodeInfo.from_compact_list(encoded_node_infos)
                    node_infos.sort(
                        key=lambda node_info: node_info.node_id.distance(torrent_hash),
                        reverse=True,
                    )

                    nodes_to_check.extend(
                        filter(
                            lambda node_info: node_info not in nodes_to_check,
                            node_infos,
                        )
                    )
