import os
import re
import csv
import requests
import matplotlib.pyplot as plt
from collections import defaultdict
import networkx as nx
import pyshark

# Configuración
DEST_IPS = [
    "185.131.204.20",
    "5.161.76.19",
    "80.77.4.60",
    "130.104.228.159"
]

RESULTADOS_DIR = "resultados"  # Directorio donde se encuentran los archivos .txt y el pcap
ANALISIS_DIR = "analice"        # Directorio donde se almacenarán los análisis
PCAP_FILE = os.path.join(RESULTADOS_DIR, "captura_general.pcap")

API_TOKEN = "33fe5453699ceb"  # Reemplazar con tu token real de ipinfo.io

# Crear directorios principales si no existen
os.makedirs(RESULTADOS_DIR, exist_ok=True)
os.makedirs(ANALISIS_DIR, exist_ok=True)

# Crear subdirectorios para cada DEST_IP en analice
for dest_ip in DEST_IPS:
    analisis_dest_dir = os.path.join(ANALISIS_DIR, dest_ip)
    os.makedirs(analisis_dest_dir, exist_ok=True)

def fetch_metadata(ip, metadata_cache={}):
    """
    Obtiene metadata para una IP utilizando la API de ipinfo.io con caching.
    """
    if ip in metadata_cache:
        return metadata_cache[ip]
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={API_TOKEN}")
        if response.status_code == 200:
            data = response.json()
            metadata1 = f"Geo: {data.get('loc', 'N/A')}"
            metadata2 = f"rDNS: {data.get('hostname', 'N/A')}"
            metadata3 = f"ISP: {data.get('org', 'N/A')}"
            metadata_cache[ip] = (metadata1, metadata2, metadata3)
            return metadata1, metadata2, metadata3
        else:
            metadata_cache[ip] = ("N/A", "N/A", "N/A")
            return "N/A", "N/A", "N/A"
    except Exception as e:
        print(f"Error al obtener metadata para {ip}: {e}")
        metadata_cache[ip] = ("N/A", "N/A", "N/A")
        return "N/A", "N/A", "N/A"

def parse_as_map_file(as_map_file):
    """
    Parsea un archivo as_map_file y devuelve una lista de tuplas (hop_number, ip, asn).
    """
    hops = []
    try:
        with open(as_map_file, "r") as f:
            lines = f.readlines()[1:]  # Omitir la cabecera
            for line in lines:
                parts = line.strip().split("\t")
                if len(parts) == 3:
                    hop, ip, asn = parts
                    try:
                        hop_num = int(hop)
                    except ValueError:
                        hop_num = None
                    if ip != "*" and ip != "":
                        hops.append((hop_num, ip, asn))
                    else:
                        hops.append((hop_num, None, asn))  # None indica no respuesta
        return hops
    except FileNotFoundError:
        print(f"Archivo {as_map_file} no encontrado.")
        return []
    except Exception as e:
        print(f"Error al parsear {as_map_file}: {e}")
        return []

def gather_routes_for_dest(dest_ip):
    """
    Recolecta todas las rutas para una IP de destino específica desde los archivos as_map_file.
    Devuelve un diccionario: método -> lista de hops (hop_number, ip, asn)
    """
    routes = {}
    pattern_trace = re.compile(rf"trace_{re.escape(dest_ip)}_.+_as\.txt")
    pattern_tracelb = re.compile(rf"tracelb_{re.escape(dest_ip)}_as\.txt")
    
    for filename in os.listdir(RESULTADOS_DIR):
        filepath = os.path.join(RESULTADOS_DIR, filename)
        if pattern_trace.match(filename) or pattern_tracelb.match(filename):
            parts = filename.split("_")
            if filename.startswith("trace_"):
                # Formato: trace_{dest}_{method}_as.txt
                if len(parts) >= 4:
                    method = "_".join(parts[2:-1])  # En caso de que el método contenga guiones
                else:
                    continue
            elif filename.startswith("tracelb_"):
                # Formato: tracelb_{dest}_as.txt
                if len(parts) >= 3:
                    method = "tracelb"
                else:
                    continue
            else:
                continue
            
            as_map_file = os.path.join(RESULTADOS_DIR, filename)
            hops = parse_as_map_file(as_map_file)
            if hops:
                routes[method] = hops
    return routes

def load_merged_traceroute(dest_ip):
    """
    Carga merged_traceroute.txt para un dest_ip, retorna una lista de (hop_num, ip_merged)
    """
    merged_file = os.path.join(ANALISIS_DIR, dest_ip, "merged_traceroute.txt")
    if not os.path.exists(merged_file):
        return []
    hops = []
    with open(merged_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
        # Saltar las primeras líneas de encabezado
        start = 0
        for i, line in enumerate(lines):
            if re.match(r"^\d+\s+\S+", line):
                start = i
                break
        for line in lines[start:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) == 2:
                hop_num, merged_ip = parts
                try:
                    hop_num = int(hop_num)
                except:
                    continue
                hops.append((hop_num, merged_ip))
    return hops

def analyze_pcap_for_patterns(pcap_file, dest_ip):
    """
    Analiza el pcap para confirmar patrones de tráfico por método para un DEST_IP específico.
    Filtra el tráfico relevante para el dest_ip.
    """
    if not os.path.exists(pcap_file):
        print("No se encontró el archivo pcap, se omite análisis.")
        return {}, set()
    
    # Filtrar tráfico dirigido al dest_ip
    display_filter = f"ip.dst == {dest_ip} or ip.src == {dest_ip}"
    cap = pyshark.FileCapture(pcap_file, display_filter=display_filter, use_json=True, include_raw=False)
    
    protocol_count = defaultdict(int)
    endpoints = set()
    
    try:
        for pkt in cap:
            try:
                proto = pkt.highest_layer.lower()
                src = pkt.ip.src
                dst = pkt.ip.dst
                if src and dst:
                    endpoints.add(src)
                    endpoints.add(dst)
                protocol_count[proto] += 1
            except AttributeError:
                # Manejar paquetes que no tienen capa IP
                continue
    except Exception as e:
        print(f"Error al analizar el pcap para {dest_ip}: {e}")
    finally:
        cap.close()
    
    return protocol_count, endpoints

def build_network_graph(dest_ip, hops_data, inconsistent_nodes):
    """
    Construye un grafo de la red para una DEST_IP específica.
    hops_data: lista de (hop_num, ip_merged)
    inconsistent_nodes: set de IPs inconsistentes para esta DEST_IP
    """
    G = nx.DiGraph()

    # Diccionario para guardar metadata: ip -> {metadata}
    ip_info_cache = {}

    prev_ips = None
    for (hop_num, merged_ip) in sorted(hops_data, key=lambda x: x[0]):
        # merged_ip puede ser "*", un IP o "ip1-ip2-ip3"
        if merged_ip == "*":
            # sin respuesta, no creamos nodo
            current_ips = []
        else:
            current_ips = merged_ip.split("-")
        
        # Crear nodos en el grafo
        for ip in current_ips:
            if ip not in G and ip != "*":
                # Obtener metadata IP si no se tiene
                if ip not in ip_info_cache:
                    m1, m2, m3 = fetch_metadata(ip)
                    ip_info_cache[ip] = {"metadata": [m1, m2, m3]}
                G.add_node(ip, metadata=ip_info_cache[ip]["metadata"])
        
        # Crear aristas entre hops
        if prev_ips is not None and current_ips:
            for prev_ip in prev_ips:
                for curr_ip in current_ips:
                    G.add_edge(prev_ip, curr_ip)
        
        # Actualizar prev_ips
        prev_ips = current_ips if current_ips else prev_ips
    
    # Colorear nodos inconsistentes
    for ip in G.nodes():
        if ip in inconsistent_nodes:
            G.nodes[ip]['color'] = 'red'
        else:
            G.nodes[ip]['color'] = 'green'
    
    return G

def draw_graph(G, output_file, dest_ip):
    """
    Dibuja el grafo en output_file (png).
    """
    pos = nx.spring_layout(G, k=0.5, iterations=50)
    colors = [G.nodes[n].get('color', 'blue') for n in G.nodes()]
    labels = {}
    for n in G.nodes():
        # Incluir IP y metadata
        meta = G.nodes[n].get('metadata', ['N/A', 'N/A', 'N/A'])
        labels[n] = f"{n}\n{meta[0]}\n{meta[1]}"
    
    plt.figure(figsize=(20, 15))
    nx.draw_networkx_nodes(G, pos, node_color=colors, node_size=1000, alpha=0.8)
    nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=20, edge_color='gray')
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)
    
    # Crear una leyenda
    import matplotlib.patches as mpatches
    red_patch = mpatches.Patch(color='red', label='Nodo Inconsistente')
    green_patch = mpatches.Patch(color='green', label='Nodo Consistente')
    plt.legend(handles=[red_patch, green_patch], loc='best')
    
    plt.axis('off')
    plt.title(f"Topología Inferida de la Infraestructura para {dest_ip}", fontsize=20)
    plt.tight_layout()
    plt.savefig(output_file, dpi=300)
    plt.close()
    print(f"Grafo generado en {output_file}")

def main():
    # Analizar el archivo pcap y extraer información por DEST_IP
    pcap_protocols = {}
    pcap_endpoints = {}
    for dest_ip in DEST_IPS:
        protocol_count, endpoints = analyze_pcap_for_patterns(PCAP_FILE, dest_ip)
        pcap_protocols[dest_ip] = protocol_count
        pcap_endpoints[dest_ip] = endpoints
        print(f"\n=== DEST_IP: {dest_ip} ===")
        print(f"Protocolos detectados en el pcap para {dest_ip}: {dict(protocol_count)}")
        print(f"Endpoints detectados en el pcap para {dest_ip}: {endpoints}")
    
    # Para cada DEST_IP, generar un grafo separado
    for dest_ip in DEST_IPS:
        print(f"\n=== Generando grafo para DEST_IP: {dest_ip} ===")
        
        # Cargar merged_traceroute.txt
        hops_data = load_merged_traceroute(dest_ip)
        if not hops_data:
            print(f"No se encontraron datos merged para {dest_ip}.")
            continue
        
        # Detectar inconsistencias desde analisis_global.txt
        analisis_global_file = os.path.join(ANALISIS_DIR, dest_ip, "analisis_global.txt")
        inconsistent_nodes = set()
        if os.path.exists(analisis_global_file):
            with open(analisis_global_file, "r") as f:
                content = f.read()
                # Buscar todas las inconsistencias
                matches = re.findall(r"- HOP: (\d+)\n\s+IP: ([\d\.]+)", content)
                for match in matches:
                    hop_num, ip_inconsistent = match
                    inconsistent_nodes.add(ip_inconsistent)
        
        # Construir el grafo para este DEST_IP
        G = build_network_graph(dest_ip, hops_data, inconsistent_nodes)
        
        # Dibujar y guardar el grafo
        grafo_output_file = os.path.join(ANALISIS_DIR, dest_ip, f"grafo_{dest_ip}.png")
        draw_graph(G, grafo_output_file, dest_ip)
    
    print("\nProceso completado. Grafos generados para cada DEST_IP en el directorio 'analice/'.")
    
if __name__ == "__main__":
    main()
