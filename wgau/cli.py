from __future__ import annotations

import argparse
import sys

from wgau import config, service
from wgau.errors import WgauError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wgau", description="WireGuard client manager"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("add", help="Add new client (keys + folder + peer in wg0.conf)")
    sub.add_parser("sync", help="Create folders for existing peers from wg0.conf")

    show = sub.add_parser("show", help="Show QR code for client")
    show.add_argument("client_name", help="Client name, e.g. client1")

    conf = sub.add_parser("conf", help="Generate client.conf from existing sec.key")
    conf.add_argument("client_name", help="Client name, e.g. client1")

    delete = sub.add_parser("delete", help="Delete client (peer in wg0.conf + client folder)")
    delete.add_argument("client_name", help="Client name, e.g. client1")
    delete.add_argument("-y", "--yes", action="store_true",
                        help="Skip confirmation prompt")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config_path = config.default_config_path()

        if config.ensure_config(config_path):
            print(f"Config was created: {config_path}")
            print("Edit it for your server (ENDPOINT, ADDRESS_BASE, DNS_SERVER, ...)")
            print("and run the command again.")
            return 0

        app = config.load_config(config_path)

        if args.command == "add":
            service.add_client(app)
        elif args.command == "sync":
            created = service.sync_folders(app)
            print(f"Created {created} folder(s)")
        elif args.command == "show":
            service.show_qr(app, args.client_name)
        elif args.command == "conf":
            conf_path = service.make_conf_from_sec_key(app, args.client_name)
            print(f"Config generated: {conf_path}")
            print(f"QR code:     {conf_path.parent / (args.client_name + '.png')}")
        elif args.command == "delete":
            service.delete_client(app, args.client_name, assume_yes=args.yes)
    except WgauError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())