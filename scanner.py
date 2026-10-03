import socket
import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# Common TCP services
COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}


def scan_port(target, port, timeout):
    """
    Scan one TCP port.

    Returns a dictionary if the port is open,
    otherwise returns None.
    """

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))

        if result == 0:
            return {
                "port": port,
                "state": "OPEN",
                "service": COMMON_PORTS.get(port, "Unknown")
            }

    except socket.error:
        pass

    finally:
        sock.close()

    return None


def resolve_target(target):
    """
    Convert a domain name into an IPv4 address.
    """

    try:
        return socket.gethostbyname(target)

    except socket.gaierror:
        return None


def validate_port_range(start_port, end_port):
    """
    Check whether the port range is valid.
    """

    if start_port < 1 or start_port > 65535:
        raise ValueError(
            "Starting port must be between 1 and 65535."
        )

    if end_port < 1 or end_port > 65535:
        raise ValueError(
            "Ending port must be between 1 and 65535."
        )

    if start_port > end_port:
        raise ValueError(
            "Starting port cannot be greater than ending port."
        )


def print_banner():
    print()
    print("=" * 50)
    print("                 NetScope")
    print("            TCP Port Scanner")
    print("=" * 50)
    print()


def save_txt(filename, target, ip, results, elapsed):
    """
    Save results to a text file.
    """

    with open(filename, "w") as file:

        file.write("NetScope Scan Report\n")
        file.write("====================\n\n")

        file.write(f"Target: {target}\n")
        file.write(f"IP Address: {ip}\n")
        file.write(f"Scan Time: {elapsed:.2f} seconds\n\n")

        file.write("Open Ports\n")
        file.write("----------\n")

        if results:

            for result in sorted(
                results,
                key=lambda x: x["port"]
            ):

                file.write(
                    f'{result["port"]}/tcp\t'
                    f'{result["state"]}\t'
                    f'{result["service"]}\n'
                )

        else:
            file.write("No open ports found.\n")


def save_json(filename, target, ip, results, elapsed):
    """
    Save results to a JSON file.
    """

    report = {
        "target": target,
        "ip_address": ip,
        "scan_time_seconds": round(elapsed, 2),
        "open_ports": sorted(
            results,
            key=lambda x: x["port"]
        )
    }

    with open(filename, "w") as file:
        json.dump(report, file, indent=4)


def create_parser():
    """
    Create command-line arguments.
    """

    parser = argparse.ArgumentParser(
        description="NetScope - TCP Port Scanner"
    )

    # Target is optional so that interactive mode works.
    parser.add_argument(
        "target",
        nargs="?",
        help="IP address or domain name"
    )

    parser.add_argument(
        "-s",
        "--start",
        type=int,
        help="Starting port"
    )

    parser.add_argument(
        "-e",
        "--end",
        type=int,
        help="Ending port"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.5,
        help="Timeout in seconds (default: 0.5)"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=50,
        help="Number of concurrent workers (default: 50)"
    )

    parser.add_argument(
        "--common",
        action="store_true",
        help="Scan common TCP ports"
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan all TCP ports"
    )

    parser.add_argument(
        "--output",
        help="Save results to a TXT file"
    )

    parser.add_argument(
        "--json",
        help="Save results to a JSON file"
    )

    return parser


def interactive_mode():
    """
    Get scanning information from the user.
    """

    print_banner()

    target = input(
        "Enter IP address or Domain - "
    ).strip()

    if not target:
        print("[-] Target cannot be empty.")
        return None

    try:
        start_port = int(
            input("Enter the starting port - ")
        )

        end_port = int(
            input("Enter the ending port - ")
        )

        timeout = float(
            input(
                "Enter timeout in seconds "
                "(example: 0.5, 1, 2) - "
            )
        )

    except ValueError:
        print("[-] Please enter valid numbers.")
        return None

    try:
        validate_port_range(
            start_port,
            end_port
        )

    except ValueError as error:
        print(f"[-] {error}")
        return None

    if timeout <= 0:
        print("[-] Timeout must be greater than 0.")
        return None

    return {
        "target": target,
        "ports": range(start_port, end_port + 1),
        "timeout": timeout,
        "workers": 50,
        "output": None,
        "json": None
    }


def cli_mode(args):
    """
    Process command-line arguments.
    """

    if args.timeout <= 0:
        print("[-] Timeout must be greater than 0.")
        return None

    if args.workers <= 0:
        print("[-] Workers must be greater than 0.")
        return None

    # Common ports
    if args.common:

        ports = list(COMMON_PORTS.keys())

    # All ports
    elif args.all:

        ports = range(1, 65536)

    # Custom range
    elif args.start is not None and args.end is not None:

        try:
            validate_port_range(
                args.start,
                args.end
            )

        except ValueError as error:
            print(f"[-] {error}")
            return None

        ports = range(
            args.start,
            args.end + 1
        )

    else:

        print("[-] Please specify a scan mode.")

        print()
        print("Examples:")
        print("  --common")
        print("  --all")
        print("  -s 1 -e 1000")

        return None

    return {
        "target": args.target,
        "ports": ports,
        "timeout": args.timeout,
        "workers": args.workers,
        "output": args.output,
        "json": args.json
    }


def run_scan(config):
    """
    Main scanning engine.
    """

    target = config["target"]
    ports = config["ports"]
    timeout = config["timeout"]
    workers = config["workers"]

    print_banner()

    # Resolve target
    print("[*] Resolving target...")

    ip = resolve_target(target)

    if ip is None:
        print(
            f"[-] Could not resolve target: {target}"
        )
        return

    print(f"[+] Target resolved: {ip}")

    total_ports = len(ports)

    print(f"[*] Ports to scan: {total_ports}")
    print(f"[*] Timeout: {timeout}s")
    print(f"[*] Workers: {workers}")

    print()
    print("[*] Starting scan...")
    print()

    open_ports = []

    start_time = time.perf_counter()

    try:

        with ThreadPoolExecutor(
            max_workers=workers
        ) as executor:

            futures = {
                executor.submit(
                    scan_port,
                    ip,
                    port,
                    timeout
                ): port

                for port in ports
            }

            completed = 0

            for future in as_completed(futures):

                completed += 1

                try:
                    result = future.result()

                except Exception:
                    continue

                if result is not None:

                    open_ports.append(result)

                    print(
                        f'[+] {result["port"]}/tcp'
                        f'\tOPEN'
                        f'\t{result["service"]}'
                    )

                # Show progress every 100 ports
                if (
                    completed % 100 == 0
                    or completed == total_ports
                ):

                    percentage = (
                        completed / total_ports
                    ) * 100

                    print(
                        f"\r[*] Progress: "
                        f"{completed}/{total_ports} "
                        f"({percentage:.1f}%)",
                        end="",
                        flush=True
                    )

    except KeyboardInterrupt:

        print()
        print()
        print("[!] Scan interrupted by user.")
        return

    elapsed = (
        time.perf_counter()
        - start_time
    )

    print()
    print()
    print("=" * 50)
    print("              Scan Completed")
    print("=" * 50)

    print(f"Target       : {target}")
    print(f"IP Address   : {ip}")
    print(f"Open ports   : {len(open_ports)}")
    print(f"Scan time    : {elapsed:.2f} seconds")

    if open_ports:

        print()
        print("Open Ports:")
        print("-" * 40)

        for result in sorted(
            open_ports,
            key=lambda x: x["port"]
        ):

            print(
                f'{result["port"]}/tcp\t'
                f'{result["service"]}'
            )

    else:

        print()
        print("No open ports found.")

    # Save TXT report
    if config["output"]:

        try:

            save_txt(
                config["output"],
                target,
                ip,
                open_ports,
                elapsed
            )

            print(
                f"\n[+] TXT report saved: "
                f"{config['output']}"
            )

        except OSError as error:

            print(
                f"\n[-] Could not save TXT report: "
                f"{error}"
            )

    # Save JSON report
    if config["json"]:

        try:

            save_json(
                config["json"],
                target,
                ip,
                open_ports,
                elapsed
            )

            print(
                f"[+] JSON report saved: "
                f"{config['json']}"
            )

        except OSError as error:

            print(
                f"[-] Could not save JSON report: "
                f"{error}"
            )


def main():

    parser = create_parser()
    args = parser.parse_args()

    # No target = interactive mode
    if args.target is None:

        config = interactive_mode()

    # Target supplied = CLI mode
    else:

        config = cli_mode(args)

    if config is not None:
        run_scan(config)


if __name__ == "__main__":
    main()