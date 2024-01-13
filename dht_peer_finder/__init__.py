import socket
from itertools import chain, islice
from random import randbytes
from typing import Iterable, Self

from . import bencode
from .regex import IP_REGEX

NODE_ID_SIZE = 20
K_BUCKET_SIZE = 20
IP_ADDR_PORT_SIZE = 6
NODE_INFO_SIZE = NODE_ID_SIZE + IP_ADDR_PORT_SIZE

RECEIVE_BUFFER_SIZE = 65536


def bytes_xor(bytesA: bytes, bytesB: bytes) -> bytes:
    assert len(bytesA) == len(bytesB)
    return bytes([byteA ^ byteB for byteA, byteB in zip(bytesA, bytesB)])


class NodeID:
    def __init__(self, node_id: bytes):
        assert len(node_id) == NODE_ID_SIZE
        self.node_id = node_id

    def distance(self, other: Self):
        byte_distance = bytes_xor(self.node_id, other.node_id)
        return int.from_bytes(byte_distance, "big")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            raise TypeError(
                f"Object: {other!r} is of invalid type: {type(other).__name__}"
            )
        return self.node_id == other.node_id


class IpAddrPortInfo:
    def __init__(self, ip: str, port: int):
        ip_match = IP_REGEX.match(ip)
        assert ip_match

        self.ip = list(map(int, ip_match.groups()))
        self.port = port

    @classmethod
    def from_compact(cls, compact: bytes):
        assert len(compact) == IP_ADDR_PORT_SIZE
        return cls(
            socket.inet_ntop(socket.AF_INET, compact[:4]),
            int.from_bytes(compact[4:], "big"),
        )

    def to_tuple(self):
        return ".".join(map(str, self.ip)), self.port

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            raise TypeError(
                f"Object: {other!r} is of invalid type: {type(other).__name__}"
            )
        return self.ip == other.ip and self.port == other.port


class NodeInfo:
    def __init__(self, node_id: NodeID, ip_addr_port: IpAddrPortInfo):
        self.node_id = node_id
        self.ip_addr_port = ip_addr_port

    @classmethod
    def from_compact(cls, compact: bytes):
        assert len(compact) == NODE_INFO_SIZE
        return cls(
            NodeID(compact[:NODE_ID_SIZE]),
            IpAddrPortInfo.from_compact(compact[NODE_ID_SIZE:]),
        )

    @classmethod
    def from_compact_list(cls, compact_list: bytes):
        assert len(compact_list) % NODE_INFO_SIZE == 0
        return [
            cls.from_compact(compact_list[i : i + NODE_INFO_SIZE])
            for i in range(0, len(compact_list), NODE_INFO_SIZE)
        ]

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            raise TypeError(
                f"Object: {other!r} is of invalid type: {type(other).__name__}"
            )
        return self.node_id == other.node_id and self.ip_addr_port == other.ip_addr_port


class RoutingTable:
    def __init__(self, client_node_id: NodeID):
        self.client_node_id = client_node_id
        self.k_buckets: list[list[NodeInfo]] = [[] for _ in range(NODE_ID_SIZE * 8)]

    def _classify_node_id(self, node_id: NodeID) -> int:
        # smaller index means closer to client node
        distance = self.client_node_id.distance(node_id)
        k_bucket_distance = -1
        while distance != 0:
            k_bucket_distance += 1
            distance >>= 1
        return max(0, k_bucket_distance)

    def add_node(self, node_info: NodeInfo):
        k_bucket_index = self._classify_node_id(node_info.node_id)
        k_bucket = self.k_buckets[k_bucket_index]

        if node_info not in k_bucket:
            if len(k_bucket) >= K_BUCKET_SIZE:
                k_bucket.pop(0)
            k_bucket.append(node_info)

    def iter_closest(self, node_id: NodeID) -> Iterable[NodeInfo]:
        target_k_bucket_index = self._classify_node_id(node_id)

        for k_bucket_index in chain(
            range(target_k_bucket_index, -1, -1),
            range(target_k_bucket_index + 1, len(self.k_buckets)),
        ):
            for node_info in sorted(
                self.k_buckets[k_bucket_index],
                key=lambda node_info: node_info.node_id.distance(node_id),
            ):
                yield node_info

    def get_closest(self, node_id: NodeID, max_count: int = 1) -> list[NodeInfo]:
        return list(islice(self.iter_closest(node_id), max_count))

    def __contains__(self, node_info: NodeInfo):
        k_bucket_index = self._classify_node_id(node_info.node_id)
        k_bucket = self.k_buckets[k_bucket_index]

        return node_info in k_bucket


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

        bootstrap_addr_info = IpAddrPortInfo(
            socket.gethostbyname(bootstrap_addr[0]), bootstrap_addr[1]
        )
        bootstrap_node_id = self.get_addr_id(bootstrap_addr_info)
        bootstrap_node = NodeInfo(bootstrap_node_id, bootstrap_addr_info)

        self.routing_table.add_node(bootstrap_node)

    def send_krpc_query(
        self,
        query_type: str,
        query_args: bencode.BencodableDict,
        target: IpAddrPortInfo | NodeID,
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

    def get_addr_id(self, addr: IpAddrPortInfo) -> NodeID:
        resp = self.send_krpc_query("ping", {}, addr)
        if b"id" not in resp or not isinstance(resp[b"id"], bytes):
            raise TypeError("Node id not found in ping response")
        return NodeID(resp[b"id"])
