# geo-ps-ip.py

geo-ps-ip.py es una herramienta que he creado para mejorar mis habilidades con python.

La función de la herramienta lo que hace es representar en un mapa las IPs que obtiene a traves de: las conexiones del sistema, un archivo pcap o el esnifado de paquetes.

geo-ps-ip.py utiliza la API del servicio ip-api.com, ya que permite hacer consultas sin necesidad de un token o de registrarse, si se quiere utilizar otro servicio, el script se tendría que adaptar al servicio utilizado.

La herramienta tiene tres modos como he mencionado antes:

```bash
~/my-own-tools/net-all
❯  python3 geo-ip-conns.py
Usage: geo-ip-conns.py [OPTIONS] COMMAND [ARGS]...

  Script to represent the IPs obtained in different ways on a map.

Options:
  --help  Show this message and exit.

Commands:
  conns  Creates a map with the open connections in the system
  pcap   Creates the map from a pcap file.
  sniff  Sniff packets through the provided interface and when ctrl + c...
  ```

## Modo conn

```bash
~/.my-own-tools/net-all
❯  python3 geo-ip-conns.py conns
[*] Creating map...
[*] Saving map...
[+] Map saved successfully
[+] Map located in --> '/home/debian/.my-own-tools/net-all/map_ips.html'
```



## Modo pcap

Tienes que proporcionar el archivo pcap.

```bash
~/.my-own-tools/net-all
❯  python3 geo-ip-conns.py pcap captured_packets.pcap
[*] Creating map...
[*] Saving map...
[+] Map saved successfully
[+] Map located in --> '/home/debian/.my-own-tools/net-all/map_ips.html'
```

## Modo sniff

Tienes que proporcionar el nombre de la interfaz.

```bash
~/my-own-tools/net-all
❯  sudo python3 geo-ip-conns.py sniff -i wlo1
Empezando el sniffing
[*] Creating map...
[*] Saving map...
[+] Map saved successfully
[+] Map located in --> '/home/debian/my-own-tools/net-all/map_ips.html'

CTRL+C exiting program...

┏━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━┓
┃ IP              ┃ Count ┃ Process ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━┩
│ 13.107.43.14    │ 3     │ chrome  │
│ 172.217.17.14   │ 17    │         │
│ 23.106.37.204   │ 1     │         │
│ 151.101.134.248 │ 1     │ chrome  │
│ 239.255.255.250 │ 1     │         │
│ 96.16.84.7      │ 3     │ chrome  │
└─────────────────┴───────┴─────────┘

```
