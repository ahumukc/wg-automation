from __future__ import annotations

from pathlib import Path

from wgau import alloc, files, wg, wgconf
from wgau.config import AppConfig
from wgau.errors import ClientNotFoundError, KeyMismatchError, Wg0Error
from wgau.models import KeyPair, Peer, WgInterface


def _server_public_key(interface: WgInterface) -> str:
    if not interface.private_key:
        raise Wg0Error("No PrivateKey in wg0.conf [Interface]")
    return wg.derive_public_key(interface.private_key)


def _taken_names(app: AppConfig, peers: list[Peer]) -> set[str]:
    taken = {p.name for p in peers if p.name is not None}
    if app.clients_dir.exists():
        taken |= {
            entry.name
            for entry in app.clients_dir.iterdir()
            if entry.is_dir() and entry.name.startswith(app.client_prefix)
        }
    return taken


def _used_suffixes(app: AppConfig, peers: list[Peer]) -> set[int]:
    ips = [ip for peer in peers for ip in peer.allowed_ips]
    return alloc.used_suffixes(app.address_base, ips)


def add_client(app: AppConfig) -> None:
    app.clients_dir.mkdir(parents=True, exist_ok=True)
    interface, peers = wgconf.parse_wg0(app.wg_conf)

    server_public_key = _server_public_key(interface)
    name = alloc.next_name(app.client_prefix, _taken_names(app, peers))
    client_ip = alloc.next_free_ip(app.address_base, _used_suffixes(app, peers))
    keys = wg.generate_keys()

    wgconf.add_peer(app.wg_conf, name, keys.public_key, keys.psk, client_ip)

    client_dir = files.create_client_dir(app.clients_dir, name)
    files.write_keys(client_dir, keys)
    conf_text = files.render_client_conf(
        keys, client_ip, server_public_key, app
    )
    files.write_client_conf(client_dir, conf_text)
    files.generate_qr_png(client_dir, name, conf_text)

    print(f"Client {name} generated in {client_dir}")
    print(f"  IP:     {client_ip}")
    print(f"  Config: {client_dir / files.CLIENT_CONF_NAME}")


def sync_folders(app: AppConfig) -> int:
    app.clients_dir.mkdir(parents=True, exist_ok=True)
    _, peers = wgconf.parse_wg0(app.wg_conf)

    taken = _taken_names(app, peers)

    def new_name() -> str:
        name = alloc.next_name(app.client_prefix, taken)
        taken.add(name)
        return name

    renamed = wgconf.name_unnamed_peers(app.wg_conf, new_name)
    if renamed:
        print(f"Added BEGIN_PEER/END_PEER markers for {renamed} peer(s) in {app.wg_conf}")
        _, peers = wgconf.parse_wg0(app.wg_conf)  # перечитываем: пиры теперь с именами

    created = 0
    for peer in peers:
        name = peer.name
        if name is None:
            ip = peer.first_ip or "?"
            name = f"{app.client_prefix}_{ip.rsplit('.', 1)[-1]}"
            print(f"Warning: peer {ip} has no BEGIN_PEER marker, "
                  f"using folder name '{name}'")

        client_dir = app.clients_dir / name
        if client_dir.exists():
            continue

        client_dir.mkdir(parents=True)
        files.write_peer_keys_from_wg0(client_dir, peer)

        print(f"Folder created: {client_dir}")
        print(f"  Note: private key for {name} is unknown — client.conf NOT "
              f"generated. Put sec.key into the folder and run "
              f"'wgau conf {name}'.")
        created += 1

    return created


def show_qr(app: AppConfig, client_name: str) -> None:
    client_dir = app.clients_dir / client_name
    if not client_dir.is_dir():
        raise ClientNotFoundError(
            f"Client '{client_name}' not found in {app.clients_dir}"
        )
    files.print_qr_ascii(files.read_client_conf(client_dir))


def make_conf_from_sec_key(app: AppConfig, client_name: str) -> Path:
    client_dir = app.clients_dir / client_name
    sec_key = client_dir / "sec.key"
    if not sec_key.exists():
        raise ClientNotFoundError(f"{sec_key} not found")

    private_key = sec_key.read_text(encoding="utf-8").strip()
    public_key = wg.derive_public_key(private_key)

    expected_pub = client_dir / "pub.key"
    if expected_pub.exists() and expected_pub.read_text().strip() != public_key:
        raise KeyMismatchError(f"sec.key in {client_dir} does not match pub.key")

    interface, peers = wgconf.parse_wg0(app.wg_conf)
    peer = next((p for p in peers if p.name == client_name), None)
    if peer is None:
        raise ClientNotFoundError(
            f"Peer '{client_name}' not found in {app.wg_conf} — "
            f"cannot determine client IP"
        )
    client_ip = peer.first_ip
    if not client_ip:
        raise Wg0Error(f"Peer {client_name} has no AllowedIPs in wg0.conf")

    keys = KeyPair(
        private_key=private_key,
        public_key=public_key,
        psk=peer.psk or "",
    )
    conf_text = files.render_client_conf(
        keys, client_ip, _server_public_key(interface), app
    )
    conf_path = files.write_client_conf(client_dir, conf_text)
    files.generate_qr_png(client_dir, client_name, conf_text)
    return conf_path


def delete_client(app: AppConfig, client_name: str, assume_yes: bool = False) -> None:
    if not client_name or Path(client_name).name != client_name:
        raise ClientNotFoundError(f"Invalid client name: '{client_name}'")

    client_dir = app.clients_dir / client_name

    _, peers = wgconf.parse_wg0(app.wg_conf)
    peer_exists = any(p.name == client_name for p in peers)
    folder_exists = client_dir.is_dir()

    if not peer_exists and not folder_exists:
        raise ClientNotFoundError(
            f"Client '{client_name}' not found in {app.wg_conf} "
            f"nor in {app.clients_dir}"
        )

    if not assume_yes:
        try:
            answer = input(
                f"Delete client '{client_name}' (peer, keys, client.conf, QR)? [y/N] "
            )
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer.strip().lower() not in ("y", "yes"):
            print("Cancelled")
            return

    if wgconf.remove_peer(app.wg_conf, client_name):
        print(f"Peer removed from {app.wg_conf}")

    if folder_exists:
        files.delete_client_dir(client_dir)
        print(f"Folder removed: {client_dir}")

    iface = app.wg_conf.stem
    print("Apply changes to the running tunnel:")
    print(f"  sudo wg syncconf {iface} <(wg-quick strip {iface})")