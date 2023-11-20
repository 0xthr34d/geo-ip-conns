import os.path
import folium
import requests
from colorama import *
import subprocess

def get_ip_json(ip_list):
    # consulta a la API
    rs = []
    ip_copy = list(ip_list.keys())  # Crear una copia de las claves del diccionario

    for ip in ip_copy:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,isp,org,proxy,hosting,query")

        if r.status_code == 429:
            print(f"{Fore.YELLOW}[!] Too Many queries, the map is going to be created with {len(rs)} IPs.\n[!] Try later for more queries or purchase the API at ip-api.com")
            print(Style.RESET_ALL)
            return rs
        elif r.status_code != 200:
            print(f"{Fore.RED}[-] Error, status code: {r.status_code}")
            print(Style.RESET_ALL)
            return rs

        rs.append(r.json())

    return rs

def crear_mapa(ip_list):
    NAME_HTML_MAP = "map_ips.html"

    ips = get_ip_json(ip_list)
    # if some query has a fail status, then doesn't save
    ips = [elemento for elemento in ips if elemento.get("status") != "fail"]

    print(f"{Fore.BLUE}[*] Creating map...")
    # create the map
    map_object = folium.Map()
    # add groups
    np = folium.FeatureGroup(name="No proxys", show=True).add_to(map_object)
    p = folium.FeatureGroup(name="Proxys, vpns or tor exits", show=True).add_to(map_object)


    for ip in ips:
        #create the popup with html
        popup = f"""
            <h2 style='font-size: 18px;'>IP: {ip['query']}</h2>
            <p style='font-size: 15px;'>
            lat: {ip['lat']}<br><br>
            lon: {ip['lon']}<br><br>
            city: {ip['city']}<br><br>
            org name: {ip['org']}<br><br>
            proxy,vpn or tor exit: {ip['proxy']}
            </p>
        """

        # if is a proxy, then add the ip to group proxy
        if ip['proxy']:
            icon = folium.Icon(prefix='fa',icon='server', color='green')
            folium.Marker([ip['lat'], ip['lon']],icon=icon, popup=popup).add_to(map_object).add_to(p)
        else:
            folium.Marker([ip['lat'], ip['lon']], popup=popup).add_to(map_object).add_to(np)

    folium.LayerControl().add_to(map_object)

    try:
        # Save the map
        print(f"{Fore.BLUE}[*] Saving map...")
        map_object.save(NAME_HTML_MAP)
        print(f"{Fore.GREEN}[+] Map saved successfully")
        print(f"{Fore.GREEN}[+] Map located in --> '{os.path.abspath(NAME_HTML_MAP)}'")

        # Cambiar el propietario del archivo guardado
        subprocess.run(["sudo", "chown", f"{os.getlogin()}:{os.getlogin()}", NAME_HTML_MAP])

    except Exception as e:
        print(f"{Fore.RED}[!] An error ocurred...")
        print(f"Error: {e}")
