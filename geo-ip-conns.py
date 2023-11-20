#!/usr/bin/python3

from scapy.all import *
import ipaddress
import signal
import psutil
from colorama import *
import generate_map
import click
import threading

from rich.live import Live
from rich.table import Table

init()

ip_dict = {}

pkt_num = 0

def ctrl_c(sig, frame):
    '''
    when ctrl + c is pressed, this function is called.

    '''

    generate_map.crear_mapa(ip_dict)
    print("\n" + Fore.LIGHTBLUE_EX + "CTRL+C exiting program...")
    print(Style.RESET_ALL)
    exit(sig)


signal.signal(signalnum=signal.SIGINT,handler=ctrl_c)

def is_private_ip(ip):
    '''
    Check if the ip is private

    '''
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        # Si la dirección IP no es válida, consideramos que no es privada
        return False


def get_pid_for_connection(src_ip, src_port, dst_ip, dst_port):
    connections = psutil.net_connections(kind='inet')
    for conn in connections:
        if (
                conn.laddr.ip == src_ip
                and conn.laddr.port == src_port
                and conn.raddr.ip == dst_ip
                and conn.raddr.port == dst_port
        ):
            return conn.pid
    return None


def add_packet_process_name(packet):
    '''
    Return the name of the process of the packet

    '''
    try:
        pid = get_pid_for_connection(
            packet['IP'].src, packet['TCP'].sport,
            packet['IP'].dst, packet['TCP'].dport
        ) # try to get the connection pid

        if pid is not None:
            process = psutil.Process(pid)
            return process.name()

    except psutil.NoSuchProcess:
        return "Unknown"


def process_packet(packet):
    global pkt_num

    if packet.haslayer('IP'):
        if not is_private_ip(packet['IP'].dst):
            pkt_num += 1
            ip = packet['IP'].dst

            # Evitar la modificación directa del diccionario mientras se itera
            ip_data = ip_dict.get(ip)
            if ip_data is None:
                ip_dict[ip] = [1, ""]
            else:
                ip_data[0] += 1

            if packet.haslayer('TCP'):
                process_name = add_packet_process_name(packet)
                ip_dict[ip][1] = process_name if process_name else ""

def packet_sniffer(iface):
    try:
        sniff(iface=iface, prn=process_packet)
    except PermissionError as e:
        print(f"[-] Error: {e}\nYou need to be root")
        exit(1)


@click.command()
@click.option("-i","--iface","iface",metavar="<iface>",required=True,help="Interface for sniffing.")
def fsniff(iface):
    '''
    Sniff packets through the provided interface and when ctrl + c is pressed, it finishes packet sniffing and generates the map.
    '''
    print("Sniffing started")
    try:
        t_fsniff = threading.Thread(target=packet_sniffer,args=(iface,), daemon=True)
        t_fsniff.start()

        table = Table()
        table.add_column("IP")
        table.add_column("Count")
        table.add_column("proccess name")

        with Live(table, refresh_per_second=4) as live:  # Actualiza 4 veces por segundo para sentirse fluido
            while t_fsniff.is_alive():  # Mantiene el bucle hasta que el hilo de esnifado finalice
                new_table = Table()  # Crea una nueva tabla con los datos actualizados
                new_table.add_column("IP")
                new_table.add_column("Count")
                new_table.add_column("Process")

                for ip, data in ip_dict.items():
                    new_table.add_row(ip, str(data[0]), data[1])

                live.update(new_table)  # Actualiza la tabla en tiempo real
                time.sleep(0.25)  # Ajusta el tiempo de espera según sea necesario
    except KeyboardInterrupt:
        pass

    t_fsniff.join()  # Asegura que el hilo finalice antes de salir

@click.command()
def fconns():
    '''
    Creates a map with the open connections in the system

    '''

    # get the current connections
    conns = psutil.net_connections(kind="inet4")
    for conn in conns:
        try:
            if not is_private_ip(conn.raddr.ip): # if IP is public
                if conn.raddr.ip not in ip_dict:
                    ip_dict[conn.raddr.ip] = [1, ""]

                else:
                    ip_dict[conn.raddr.ip][0] += 1
        except Exception as e:
            continue

    generate_map.crear_mapa(ip_dict)
    return

@click.command()
@click.argument('pcap',  metavar="<pcap>")
def fpcap(pcap):
    '''
    Creates the map from a pcap file.
    '''

    # saves packets in var packets
    packets = rdpcap(pcap)
    for packet in packets:
        if packet.haslayer('IP'): # if packet has layer IP
            if not is_private_ip(packet['IP'].dst): # if ip is public
                if packet['IP'].dst not in ip_dict: # if ip doesn't exist, then create
                    ip_dict[packet['IP'].dst] = [1, ""]
                else:   # if exist inc the number
                    ip_dict[packet['IP'].dst][0] += 1
            # if contains Transport Layer (Layer 4)
            # if packet.haslayer('TCP'):
            #     ip_dict[packet['IP'].dst][1] = add_packet_process_name(packet)

    generate_map.crear_mapa(ip_dict)
    return



@click.group()
def main():
    '''
    Script to represent the IPs obtained in different ways on a map.

    '''
    return

main.add_command(fsniff, name="sniff")
main.add_command(fconns, name="conns")
main.add_command(fpcap, name="pcap")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"{colorama.Fore.RED}[-]An error has occurred: {e}{colorama.Style.RESET_ALL}")


