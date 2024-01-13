from dht_peer_finder import BitTorrentDHTConnection, NodeID


def main():
    torrent_hash = NodeID(bytes.fromhex("2C6B6858D61DA9543D4231A71DB4B1C9264B0685"))

    conn = BitTorrentDHTConnection(("router.bittorrent.com", 6881))
    ping_success = conn.ping()
    print(f"Ping success: {ping_success}")
    for torrent_peer in conn.get_torrent_peers(torrent_hash):
        ip, port = torrent_peer.to_tuple()
        print(f"PEER: {ip}:{port}")


if __name__ == "__main__":
    main()
