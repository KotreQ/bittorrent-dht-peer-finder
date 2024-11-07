from itertools import chain, islice
from typing import Callable, Iterable

from ..dht_exceptions import *
from .k_bucket import KBucket
from .node_id import NODE_ID_SIZE, NodeID
from .node_info import NodeInfo


class RoutingTable:
    def __init__(
        self,
        client_node_id: NodeID,
        *,
        active_node_checker: Callable[
            [Iterable[NodeInfo]], list[bool]
        ] = lambda nodes: [True for node in nodes],
    ):
        self.client_node_id = client_node_id
        self.k_buckets: list[KBucket] = [KBucket(self.client_node_id, 0)]

        self.active_node_checker = active_node_checker

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
                self.add_node(node_info)  # retry after adding new k-bucket
            else:
                if self.purge_k_bucket(k_bucket):
                    k_bucket.add_node(node_info)  # retry if purged any nodes

    def remove_nodes(self, node_ids: Iterable[NodeID]):
        node_ids = set(node_ids)
        for k_bucket in self.k_buckets:
            k_bucket.pop_nodes(node_ids)

    def purge_k_bucket(self, k_bucket: KBucket) -> list[NodeInfo]:
        nodes = k_bucket.nodes

        inactive_nodes: list[NodeInfo] = []

        for node_info, is_active in zip(nodes, self.active_node_checker(nodes)):
            if not is_active:
                inactive_nodes.append(node_info)

        return k_bucket.pop_nodes(inactive_nodes)

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

    def get_all_nodes(self) -> list[NodeInfo]:
        return sum((k_bucket.nodes for k_bucket in self.k_buckets), start=[])

    def export_data(self) -> bytes:
        return b"".join(
            node_info.to_compact()
            for k_bucket in self.k_buckets
            for node_info in k_bucket.nodes
        )

    def import_data(self, data: bytes):
        for node_info in NodeInfo.from_compact_list(data):
            self.add_node(node_info)
