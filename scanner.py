import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(target, port, timeout):
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    result=sock.connect_ex((target, port))
    sock.close()

    if result == 0:
        return port
    return None

def main():
    target=input("Enter IP address or Domain - ")
    start_port=int(input("Enter the starting port - "))
    end_port=int(input("Enter the ending port - "))

    timeout=float(input("Enter timeout in seconds (eg. 0.5, 1, 2...) - "))

    try:
        ip=socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] could not resolve the target")
        return

    print(f"\nTarget : {target}")
    print(f"IP address : {ip}")
    print(f"Scanning ports from {start_port} - {end_port}...\n")

    open_ports=[]

    with ThreadPoolExecutor(max_workers=50) as executer:

        tasks=[]
        for ports in range(start_port, end_port+1):
            task=executer.submit(
                scan_port,
                ip,
                ports,
                timeout
            )
            tasks.append(task)

        for task in tasks:
            port=task.result()
            if port is not None:
                open_ports.append(port)
                print(f"[+] Port {port} is OPEN")
    print(f"\nScan Completed, found {open_ports} open ports")

    if open_ports:
        print("\nOpen ports : ")
        for port in sorted(open_ports):
            print(f"{port}")
    else:
        print("No open ports found")

if __name__ == "__main__":
    main()