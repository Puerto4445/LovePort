#!/usr/bin/python
import socket
from termcolor import colored
import argparse
from concurrent.futures import ThreadPoolExecutor
import signal
import sys
import subprocess
from pyfiglet import Figlet

open_sock = []


def Print_Figlet(text):
    figlet = Figlet(font="banner3")
    ascii_art = figlet.renderText(text)
    lolcat_process = subprocess.Popen(["lolcat"], stdin=subprocess.PIPE)
    lolcat_process.communicate(input=ascii_art.encode())


def Close_Custom(sig, frame):
    print(colored(f"[+] You are leaving so fast love?", "red"))
    try:
        for i in open_sock:
            i.close()
        sys.exit(1)
    except SystemExit:
        pass


signal.signal(signal.SIGINT, Close_Custom)


def get_argument():
    parser = argparse.ArgumentParser(description="TCP Port Scanner")
    parser.add_argument(
        "-t",
        "--target",
        dest="target",
        required=True,
        help="IP to scan (Ex: -t 127.0.0.1-224)",
    )
    parser.add_argument(
        "-p",
        "--port",
        dest="port",
        required=True,
        help="Port range o Scan (Ex: -p 1-100)",
    )
    option = parser.parse_args()
    return option.target, option.port


def Initial_Socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    open_sock.append(s)
    return s


def port_scan(port, host):
    s = Initial_Socket()
    try:
        s.connect((host, port))
        s.sendall(b"HEAD /HTTP/1.0\r\n\r\n") # cabecera HTTP
        response = s.recv(1024)
        response = response.decode(errors="ignore").split("\n")[0]
        if response:
            print(colored(f"\n[+] Port {port} UP - {response}", "green"))  
        else:
            print(colored(f"\n[+] Port {port} UP", "green"))

    except (socket.timeout, ConnectionRefusedError, PermissionError):
        pass
    finally:
        s.close()


def Parse_Port(target,str_port):
    if "-" in str_port:
        start, end = map(int, str_port.split("-"))
        return range(start, end + 1)
    elif "," in str_port:
        return map(int, str_port.split(","))
    else:
        return (int(str_port),)


def Scan_port(ports, target):
    with ThreadPoolExecutor(max_workers=50) as e:  # cantidad de hilos a trabajar
        e.map(lambda i: port_scan(i, target), ports)


def main():
    Print_Figlet("LOVEPORT")
    print("\n@puerto4444")
    print("-" * 30)
    target, str_port = get_argument()
    ports = Parse_Port(target, str_port)
    Scan_port(ports, target)


if __name__ == "__main__":
    main()
