#!/usr/bin/python  
import argparse  
import sys  
import threading  
from scapy.all import *  
from concurrent.futures import ThreadPoolExecutor, as_completed  
from termcolor import colored  
import subprocess  
from pyfiglet import Figlet  
import os  
import socket  
import signal


reported_ports = set()  
lock = threading.Lock()  

open_sock = []  

def Print_Figlet(text):  
    """  
    Genera arte ASCII con estilo utilizando pyfiglet y lo muestra con colores usando lolcat.  
    """  
    figlet = Figlet(font="banner3")  
    ascii_art = figlet.renderText(text)  
    lolcat_process = subprocess.Popen(["lolcat"], stdin=subprocess.PIPE)  
    lolcat_process.communicate(input=ascii_art.encode())  

def Close_Custom(sig, frame):  
    """  
    Maneja la señal de interrupción (Ctrl+C), cierra todos los sockets abiertos y finaliza el programa.  
    """  
    print(colored(f"[+] Saliendo...", "red"))  
    try:  
        for i in open_sock:  
            i.close()  
        sys.exit(1)  
    except SystemExit:  
        pass  

signal.signal(signal.SIGINT, Close_Custom)  

def get_argument():  
    """  
    Parsea los argumentos de línea de comando requeridos para el escáner.  
    """  
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")  
    parser.add_argument("-t", "--target", required=True, help="Dirección IP objetivo")  
    parser.add_argument("-p", "--port", required=True, help="Rango de puertos (Ej: 1-100)")  
    parser.add_argument("-s", "--syn", action="store_true", help="Usar escaneo SYN (sigiloso)")  
    return parser.parse_args()  

def Initial_Socket():  
    """  
    Crea y configura un nuevo socket TCP con timeout de 0.2 segundos.  
    """  
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    s.settimeout(0.2)  
    open_sock.append(s)  
    return s  

def tcp_connect_scan(port, host):  
    """  
    Realiza un escaneo de puerto mediante conexión TCP completa.  
    """  
    s = Initial_Socket()  
    try:  
        s.connect((host, port))  
        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")  
        response = s.recv(1024)  
        response = response.decode(errors="ignore").split("\n")[0]  
        if response:  
            print(colored(f"[+] Puerto {port} ABIERTO - {response}", "green"))  
        else:  
            print(colored(f"[+] Puerto {port} ABIERTO", "green"))  
    except (socket.timeout, ConnectionRefusedError, PermissionError):  
        pass  
    finally:  
        s.close()  

def syn_scan(port, host):  
    """  
    Realiza un escaneo de puerto mediante el método SYN (half-open).  
    """  
    try:   
        p = IP(dst=host) / TCP(dport=port, flags="S")  
        response = sr1(p, timeout=1, verbose=0)  

        if response:  
            if response.haslayer(TCP):  
                if response[TCP].flags == 0x12:  
                    send(IP(dst=host) / TCP(dport=port, flags="R"), verbose=0)  
                    with lock:    
                        if port not in reported_ports:  
                            reported_ports.add(port)  
                            print(colored(f"[+] Puerto {port} ABIERTO (SYN)", "green"))  
                    return True  
                elif response[TCP].flags == 0x14:  # Respuesta RST-ACK  
                    return False  
        return False  
    except Exception as e:  
        print(colored(f"Error en escaneo SYN: {e}", "red"))  
        return False  

def Parse_Port(target, str_port):  
    """  
    Procesa el string de puertos a escanear y genera un rango de números.  
    """  
    if "-" in str_port:  
        start, end = map(int, str_port.split("-"))  
        return range(start, end + 1)  
    elif "," in str_port:  
        return map(int, str_port.split(","))  
    else:  
        return (int(str_port),)  

def Scan_port(ports, target, syn_mode=False):  
    """  
    Ejecuta el escaneo de puertos según el modo seleccionado.  
    """  
    with ThreadPoolExecutor(max_workers=50) as executor:  
        if syn_mode:    
            futures = {executor.submit(syn_scan, port, target): port for port in ports}  
            for future in as_completed(futures):  
                port = futures[future]  
                try:  
                    result = future.result()  
                    if result:  
                        pass    
                except Exception as e:  
                    print(colored(f"Error en el puerto {port}: {e}", "red"))  
        else:    
            executor.map(lambda p: tcp_connect_scan(p, target), ports)  

def main():  
    Print_Figlet("LOVEHOST")  
    print("\n@puerto4444")  
    print("-" * 30)  
    args = get_argument()  
    ports = Parse_Port(args.target, args.port)  

    if args.syn:  
        if os.geteuid() != 0:  
            print(colored("ERROR: El escaneo SYN requiere permisos de root", "red"))  
            sys.exit(1)  
        print(colored("\n[*] Iniciando escaneo SYN...", "cyan"))  
        Scan_port(ports, args.target, syn_mode=True)  
    else:  
        print(colored("\n[*] Iniciando escaneo TCP Connect...", "cyan"))  
        Scan_port(ports, args.target)  

if __name__ == "__main__":  
    main()
