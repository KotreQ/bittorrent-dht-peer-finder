from typing import Self

from ..utils.binary import bytes_xor

NODE_ID_SIZE = 20


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
