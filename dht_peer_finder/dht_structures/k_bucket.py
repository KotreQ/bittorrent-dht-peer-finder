from typing import Iterable

from ..dht_exceptions import *
from .node_id import NodeID
from .node_info import NodeInfo

K_BUCKET_SIZE = 20


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
