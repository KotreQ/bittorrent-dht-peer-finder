from .ip_addr_port import IP_ADDR_PORT_SIZE, IpAddrPort
from .node_id import NODE_ID_SIZE, NodeID

NODE_INFO_SIZE = NODE_ID_SIZE + IP_ADDR_PORT_SIZE


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

    def to_compact(self) -> bytes:
        node_id_compact = self.node_id.node_id
        ip_addr_port_compact = self.ip_addr_port.to_compact()

        return node_id_compact + ip_addr_port_compact

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            raise TypeError(
                f"Object: {other!r} is of invalid type: {type(other).__name__}"
            )
        return self.node_id == other.node_id and self.ip_addr_port == other.ip_addr_port

    def __hash__(self) -> int:
        return hash((self.node_id, self.ip_addr_port))
