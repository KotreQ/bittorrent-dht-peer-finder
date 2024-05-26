import socket
from itertools import chain, islice
from typing import Iterable, Self

from .dht_exceptions import *
from .regex import IP_REGEX
from .utils.binary import bytes_xor

NODE_ID_SIZE = 20
K_BUCKET_SIZE = 20
IP_ADDR_PORT_SIZE = 6
NODE_INFO_SIZE = NODE_ID_SIZE + IP_ADDR_PORT_SIZE


class NodeID:
    def __init__(self, node_id: bytes):
        assert len(node_id) == NODE_ID_SIZE
        self.node_id = node_id

    def distance(self, other: Self):
        byte_distance = bytes_xor(self.node_id, other.node_id)
        return int.from_bytes(byte_distance, "big")

    def common_bits(self, other: Self):
        distance = self.distance(other)
        distance_bits = distance.bit_length()
        common_bits = NODE_ID_SIZE * 8 - distance_bits
        return common_bits

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            raise TypeError(
                f"Object: {other!r} is of invalid type: {type(other).__name__}"
            )
        return self.node_id == other.node_id

    def __hash__(self) -> int:
        return hash(self.node_id)


class IpAddrPort:
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

    def __hash__(self) -> int:
        return hash(self.to_tuple())


class NodeInfo:
    def __init__(self, node_id: NodeID, ip_addr_port: IpAddrPort):
        self.node_id = node_id
        self.ip_addr_port = ip_addr_port

    @classmethod
    def from_compact(cls, compact: bytes):
        assert len(compact) == NODE_INFO_SIZE
        return cls(
            NodeID(compact[:NODE_ID_SIZE]),
            IpAddrPort.from_compact(compact[NODE_ID_SIZE:]),
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

    def __hash__(self) -> int:
        return hash((self.node_id, self.ip_addr_port))


class KBucket:
    def __init__(self, client_node_id: NodeID, common_bits: int):
        self.client_node_id = client_node_id
        self.common_bits = common_bits
        self.nodes: list[NodeInfo] = []

    def add_node(self, node: NodeInfo, *, accept_closer: bool = False):
        common_bits = self.client_node_id.common_bits(node.node_id)

        if node in self.nodes:
            return

        if len(self.nodes) >= K_BUCKET_SIZE:
            raise KBucketSpaceError("Not space left in K-Bucket")

        if common_bits < self.common_bits:
            raise TooHighKBucketDistanceError("Not enough common bits in node id")

        if common_bits > self.common_bits and not accept_closer:
            raise TooLowKBucketDistanceError("Too much common bits in node id")

        self.nodes.append(node)

    def pop_closer(self) -> list[NodeInfo]:
        closer_nodes: set[NodeInfo] = set()

        for node in self.nodes:
            common_bits = self.client_node_id.common_bits(node.node_id)
            if common_bits > self.common_bits:
                closer_nodes.add(node)

        popped_nodes: list[NodeInfo] = self.pop_nodes(closer_nodes)

        return popped_nodes

    def pop_nodes(self, nodes: Iterable[NodeInfo]) -> list[NodeInfo]:
        nodes = set(nodes)
        pop_indexes = [i for i, node in enumerate(self.nodes) if node in nodes]
        pop_indexes.sort(reverse=True)

        popped_nodes: list[NodeInfo] = []
        for pop_index in pop_indexes:
            popped_nodes.append(self.nodes.pop(pop_index))

        return popped_nodes


class RoutingTable:
    def __init__(self, client_node_id: NodeID):
        self.client_node_id = client_node_id
        self.k_buckets: list[KBucket] = [KBucket(self.client_node_id, 0)]

    def _get_bucket_index(self, node_id: NodeID) -> int:
        common_bits = self.client_node_id.common_bits(node_id)
        return min(common_bits, len(self.k_buckets) - 1)

    def _add_bucket(self):
        if len(self.k_buckets) >= NODE_ID_SIZE * 8:
            raise IndexError("Max number of buckets reached")

        last_k_bucket = self.k_buckets[-1]
        new_k_bucket = KBucket(self.client_node_id, len(self.k_buckets))

        for node in last_k_bucket.pop_closer():
            new_k_bucket.add_node(node, accept_closer=True)

        self.k_buckets.append(new_k_bucket)

    def add_node(self, node_info: NodeInfo):
        k_bucket_index = self._get_bucket_index(node_info.node_id)
        is_last_bucket = k_bucket_index == len(self.k_buckets) - 1

        k_bucket = self.k_buckets[k_bucket_index]

        try:
            k_bucket.add_node(node_info, accept_closer=is_last_bucket)
        except KBucketSpaceError:
            if is_last_bucket:
                self._add_bucket()

    def iter_closest(self, node_id: NodeID) -> Iterable[NodeInfo]:
        target_k_bucket_index = self._get_bucket_index(node_id)

        for k_bucket_index in chain(
            range(target_k_bucket_index, len(self.k_buckets)),
            range(target_k_bucket_index - 1, -1, -1),
        ):
            for node_info in sorted(
                self.k_buckets[k_bucket_index].nodes,
                key=lambda node_info: node_info.node_id.distance(node_id),
            ):
                yield node_info

    def get_closest(self, node_id: NodeID, max_count: int = 1) -> list[NodeInfo]:
        return list(islice(self.iter_closest(node_id), max_count))
