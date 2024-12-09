import os
import re
import csv
import requests
import matplotlib.pyplot as plt
from collections import defaultdict

# Configuración
DEST_IPS = [
    "185.131.204.20",
    "5.161.76.19",
    "80.77.4.60",
    "130.104.228.159"
]

RESULTADOS_DIR = "resultados"  # Directorio donde se encuentran los archivos .txt generados
ANALISIS_DIR = "analice"        # Directorio donde se almacenarán los análisis
METADATA_DIR = "metadata"      # Directorio donde se almacenarán los metadatos y las imágenes

API_TOKEN_IPINFO = "33fe5453699ceb"  # Token para ipinfo.io

# Crear directorios principales
os.makedirs(RESULTADOS_DIR, exist_ok=True)
os.makedirs(ANALISIS_DIR, exist_ok=True)
os.makedirs(METADATA_DIR, exist_ok=True)

# Crear subdirectorios para cada DEST_IP en resultados, analice y metadata
for dest_ip in DEST_IPS:
    resultados_dest_dir = os.path.join(RESULTADOS_DIR, dest_ip)
    analisis_dest_dir = os.path.join(ANALISIS_DIR, dest_ip)
    metadata_dest_dir = os.path.join(METADATA_DIR, dest_ip)
    os.makedirs(resultados_dest_dir, exist_ok=True)
    os.makedirs(analisis_dest_dir, exist_ok=True)
    os.makedirs(metadata_dest_dir, exist_ok=True)

def fetch_metadata(ip):
    """
    Obtiene metadata para una IP utilizando las APIs de ipinfo.io, ip-api.com y ipapi.co.
    """
    metadata = {
        "Geo": "N/A",
        "rDNS": "N/A",
        "ISP": "N/A",
        "Country": "N/A",
        "Region": "N/A",
        "City": "N/A",
        "Timezone": "N/A",
        "ASN_Info": "N/A"
    }
    
    # API 1: ipinfo.io
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json?token={API_TOKEN_IPINFO}")
        if response.status_code == 200:
            data = response.json()
            metadata["Geo"] = data.get("loc", "N/A")
            metadata["rDNS"] = data.get("hostname", "N/A")
            metadata["ISP"] = data.get("org", "N/A")
    except Exception as e:
        print(f"Error al obtener metadata de ipinfo.io para {ip}: {e}")
    
    # API 2: ip-api.com
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                metadata["Country"] = data.get("country", "N/A")
                metadata["Region"] = data.get("regionName", "N/A")
                metadata["City"] = data.get("city", "N/A")
    except Exception as e:
        print(f"Error al obtener metadata de ip-api.com para {ip}: {e}")
    
    # API 3: ipapi.co
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/")
        if response.status_code == 200:
            data = response.json()
            metadata["Timezone"] = data.get("timezone", "N/A")
            metadata["ASN_Info"] = data.get("asn", "N/A")
    except Exception as e:
        print(f"Error al obtener metadata de ipapi.co para {ip}: {e}")
    
    return metadata

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

def find_route_with_most_hops(routes):
    """
    Encuentra la ruta con la mayor cantidad de hops.
    """
    max_hops = -1
    selected_method = None
    selected_hops = []
    for method, hops in routes.items():
        num_hops = len([hop for hop in hops if hop[1] is not None])
        if num_hops > max_hops:
            max_hops = num_hops
            selected_method = method
            selected_hops = hops
    if selected_method:
        return selected_method, selected_hops
    else:
        return None, []

def generate_metadata_table(dest_ip, method, hops):
    """
    Genera la tabla de metadata para la ruta seleccionada y crea una representación gráfica.
    """
    print(f"Generando tabla de metadata para la ruta hacia {dest_ip} usando el método {method} con {len(hops)} hops.")

    # Directorio específico para la DEST_IP en metadata
    metadata_dest_dir = os.path.join(METADATA_DIR, dest_ip)
    
    # Archivos de salida
    metadata_csv = os.path.join(metadata_dest_dir, f"tabla_metadata_{method}.csv")
    metadata_graph = os.path.join(metadata_dest_dir, f"tabla_metadata_{method}.png")
    
    # Preparar los datos para la tabla
    table_data = []
    for hop_num, ip, asn in hops:
        if ip is not None:
            metadata = fetch_metadata(ip)
            geo = metadata.get("Geo", "N/A")
            rdns = metadata.get("rDNS", "N/A")
            isp = metadata.get("ISP", "N/A")
            country = metadata.get("Country", "N/A")
            region = metadata.get("Region", "N/A")
            city = metadata.get("City", "N/A")
            timezone = metadata.get("Timezone", "N/A")
            asn_info = metadata.get("ASN_Info", "N/A")
        else:
            geo = rdns = isp = country = region = city = timezone = asn_info = "No response"
        table_data.append({
            "IP": ip if ip else "*",
            "HOP": hop_num,
            "AS": asn,
            "Geo": geo,
            "rDNS": rdns,
            "ISP": isp,
            "Country": country,
            "Region": region,
            "City": city,
            "Timezone": timezone,
            "ASN_Info": asn_info
        })
    
    # Escribir la tabla en un archivo CSV
    with open(metadata_csv, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["IP", "HOP", "AS", "Geo", "rDNS", "ISP", "Country", "Region", "City", "Timezone", "ASN_Info"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in table_data:
            writer.writerow(row)
    
    print(f"Tabla de metadata generada en {metadata_csv}")

    # Generar una representación gráfica de la tabla utilizando matplotlib
    generate_graphic_table(table_data, dest_ip, method, metadata_graph)

def generate_graphic_table(table_data, dest_ip, method, output_file):
    """
    Genera una representación gráfica de la tabla de metadata utilizando matplotlib.
    """
    # Limitar la cantidad de filas para la visualización gráfica
    max_rows = 20  # Ajusta según sea necesario
    display_data = table_data[:max_rows]
    
    if not display_data:
        print(f"No hay datos para generar la tabla gráfica para {dest_ip} usando {method}.")
        return
    
    # Preparar los datos para la tabla gráfica
    column_labels = ["IP", "HOP", "AS", "Geo", "rDNS", "ISP", "Country", "Region", "City", "Timezone", "ASN_Info"]
    cell_text = []
    for row in display_data:
        cell_text.append([
            row["IP"],
            row["HOP"],
            row["AS"],
            row["Geo"],
            row["rDNS"],
            row["ISP"],
            row["Country"],
            row["Region"],
            row["City"],
            row["Timezone"],
            row["ASN_Info"]
        ])
    
    # Crear la figura
    fig, ax = plt.subplots(figsize=(20, 1 + 0.5 * len(cell_text)))  # Ajustar tamaño según filas
    
    # Ocultar ejes
    ax.axis('off')
    ax.axis('tight')
    
    # Crear la tabla
    table = ax.table(cellText=cell_text,
                     colLabels=column_labels,
                     loc='center',
                     cellLoc='left',
                     colLoc='center')
    
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1, 1.5)
    
    plt.title(f"Tabla de Metadata para {dest_ip} usando {method}", fontsize=14, pad=20)
    
    # Guardar la tabla como imagen
    plt.savefig(output_file, bbox_inches='tight')
    plt.close()
    print(f"Tabla gráfica generada en {output_file}")
    print(f"Nota: Solo se muestran las primeras {max_rows} filas en la representación gráfica.")

def plot_hops_per_method(dest_ip, routes):
    """
    Genera un gráfico de barras que muestra la cantidad de hops por método para una DEST_IP específica.
    """
    methods = []
    hops_counts = []
    for method, hops in routes.items():
        methods.append(method)
        hops_counts.append(len([hop for hop in hops if hop[1] is not None]))
    
    if not methods:
        print(f"No hay métodos para generar el gráfico de hops por método para {dest_ip}.")
        return
    
    plt.figure(figsize=(10, 6))
    bars = plt.bar(methods, hops_counts, color='skyblue')
    plt.xlabel('Método de Traceroute')
    plt.ylabel('Cantidad de Hops')
    plt.title(f'Cantidad de Hops por Método de Traceroute para {dest_ip}')
    plt.xticks(rotation=45, ha='right')
    
    # Añadir etiquetas a las barras
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2, yval + 0.5, yval, ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    hops_graph_file = os.path.join(METADATA_DIR, dest_ip, f"hops_por_metodo_{dest_ip}.png")
    plt.savefig(hops_graph_file)
    plt.close()
    print(f"Gráfico de hops por método generado en {hops_graph_file}")

def plot_as_distribution(dest_ip, method, hops):
    """
    Genera un gráfico de torta que muestra la distribución de AS en la ruta seleccionada.
    """
    as_counts = defaultdict(int)
    for _, _, asn in hops:
        if asn != "*":
            as_counts[asn] += 1
    
    if not as_counts:
        print(f"No hay AS para generar el gráfico de distribución de AS para {dest_ip} usando {method}.")
        return
    
    labels = list(as_counts.keys())
    sizes = list(as_counts.values())
    
    plt.figure(figsize=(8, 8))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title(f"Distribución de AS en la Ruta hacia {dest_ip} usando {method}")
    
    plt.axis('equal')  # Igualar aspecto para que el pastel sea circular
    as_graph_file = os.path.join(METADATA_DIR, dest_ip, f"distribucion_as_{dest_ip}.png")
    plt.savefig(as_graph_file)
    plt.close()
    print(f"Gráfico de distribución de AS generado en {as_graph_file}")

def analyze_inconsistent_responses(dest_ip, routes, report_file):
    """
    A partir de los resultados, indicar al menos una IP que no responda a un tipo de solicitud de
    las evidenciadas y a qué tipo de solicitud sí responde.
    Además, crea una versión global del traceroute combinando los distintos métodos.
    """
    # Definir los métodos y sus tipos de solicitud
    method_types = {
        "icmp-paris": "ICMP Echo Request (Paris)",
        "icmp": "ICMP Echo Request",
        "udp-paris": "UDP Datagram (Paris)",
        "udp": "UDP Datagram",
        "tcp": "TCP SYN",
        "tcp-ack": "TCP ACK",
        "tracelb": "Traceroute with Load Balancing"
    }
    
    # Construir un mapeo hop_number -> método -> IP
    hop_method_ip = defaultdict(dict)
    for method, hops in routes.items():
        for hop_num, ip, _ in hops:
            hop_method_ip[hop_num][method] = ip  # ip puede ser None si no respondió
    
    # Identificar hops con respuestas inconsistentes
    inconsistent_hops = {}
    for hop_num, methods in hop_method_ip.items():
        present_methods = {m for m, ip in methods.items() if ip is not None}
        missing_methods = {m for m, ip in methods.items() if ip is None}
        if present_methods and missing_methods:
            inconsistent_hops[hop_num] = {
                "present_methods": present_methods,
                "missing_methods": missing_methods
            }
    
    # Crear el archivo de análisis por DEST_IP en analice
    analisis_dest_dir = os.path.join(ANALISIS_DIR, dest_ip)
    analisis_global_file = os.path.join(analisis_dest_dir, "analisis_global.txt")
    merged_traceroute_file = os.path.join(analisis_dest_dir, "merged_traceroute.txt")
    
    with open(analisis_global_file, "w", encoding="utf-8") as analisis_txt:
        analisis_txt.write(f"Informe de Análisis Global de Traceroute para {dest_ip}\n")
        analisis_txt.write("="*60 + "\n\n")
        
        # Crear una versión global del traceroute combinando los distintos métodos
        # Primero, determinar el número máximo de hops
        max_hop = max(hop_method_ip.keys())
        
        analisis_txt.write(f"Versión Global del Traceroute para {dest_ip}:\n")
        analisis_txt.write("-"*60 + "\n")
        header = "HOP".ljust(5)
        for method in routes.keys():
            header += f"{method_types.get(method, method):30}"
        analisis_txt.write(header + "\n")
        analisis_txt.write("-"*60 + "\n")
        
        for hop_num in range(1, max_hop + 1):
            line = str(hop_num).ljust(5)
            for method in routes.keys():
                ip = hop_method_ip.get(hop_num, {}).get(method, None)
                if ip:
                    line += f"{ip:30}"
                else:
                    line += f"{'*':30}"
            analisis_txt.write(line + "\n")
        
        analisis_txt.write("\n")
        
        # Reportar inconsistencias
        if inconsistent_hops:
            analisis_txt.write(f"=== Hops con Respuestas Inconsistentes para {dest_ip} ===\n")
            for hop_num, info in inconsistent_hops.items():
                # Obtener la IP si está presente en al menos un método
                ip_present = None
                for method in info["present_methods"]:
                    ip_present = hop_method_ip[hop_num][method]
                    if ip_present:
                        break
                analisis_txt.write(f"- HOP: {hop_num}\n")
                analisis_txt.write(f"  IP: {ip_present}\n")
                missing = ', '.join([method_types.get(m, m) for m in info["missing_methods"]])
                present = ', '.join([method_types.get(m, m) for m in info["present_methods"]])
                analisis_txt.write(f"  No responde a: {missing}\n")
                analisis_txt.write(f"  Sí responde a: {present}\n\n")
                # Solo indicar la primera encontrada
                break
        else:
            analisis_txt.write(f"=== No se encontraron Hops con respuestas inconsistentes para {dest_ip}. ===\n\n")
        
        print(f"Análisis global generado en {analisis_global_file}")
    
    # Generar el archivo merged_traceroute.txt
    with open(merged_traceroute_file, "w", encoding="utf-8") as merged_txt:
        merged_txt.write(f"Traceroute Merge para {dest_ip}\n")
        merged_txt.write("="*50 + "\n\n")
        
        # Determinar el número máximo de hops
        max_hop = max(hop_method_ip.keys())
        
        for hop_num in range(1, max_hop + 1):
            ips = []
            for method in routes.keys():
                ip = hop_method_ip.get(hop_num, {}).get(method, None)
                if ip:
                    ips.append(ip)
            unique_ips = list(set(ips))
            if not unique_ips:
                merged_ip = "*"
            elif len(unique_ips) == 1:
                merged_ip = unique_ips[0]
            else:
                merged_ip = "-".join(unique_ips)
            merged_txt.write(f"{hop_num}\t{merged_ip}\n")
        
        print(f"Traceroute fusionado generado en {merged_traceroute_file}")

def main():
    # Ruta del informe global
    report_path = os.path.join(ANALISIS_DIR, "informe_analisis.txt")
    
    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write("Informe de Análisis de Infraestructura de Internet\n")
        report_file.write("="*60 + "\n\n")
        
        for dest_ip in DEST_IPS:
            print(f"\n=== Procesando DEST_IP: {dest_ip} ===")
            report_file.write(f"=== DEST_IP: {dest_ip} ===\n")
            
            routes = gather_routes_for_dest(dest_ip)
            if not routes:
                print(f"No se encontraron rutas para {dest_ip}.")
                report_file.write("No se encontraron rutas para esta DEST_IP.\n\n")
                continue
            
            # Generar gráfico de hops por método
            plot_hops_per_method(dest_ip, routes)
            
            # Encontrar la ruta con más hops
            method, hops = find_route_with_most_hops(routes)
            if not method:
                print(f"No se pudo determinar la ruta con mayor cantidad de hops para {dest_ip}.")
                report_file.write("No se pudo determinar la ruta con mayor cantidad de hops para esta DEST_IP.\n\n")
                continue
            
            # Generar la tabla de metadata y su representación gráfica
            generate_metadata_table(dest_ip, method, hops)
            
            # Generar gráfico de distribución de AS para la ruta seleccionada
            plot_as_distribution(dest_ip, method, hops)
            
            # Agregar información al informe global
            report_file.write(f"Ruta seleccionada:\n")
            report_file.write(f"- Método: {method}\n")
            report_file.write(f"- Cantidad de hops: {len([hop for hop in hops if hop[1] is not None])}\n")
            report_file.write(f"- Referencia CSV: {os.path.join('metadata', dest_ip, f'tabla_metadata_{method}.csv')}\n")
            report_file.write(f"- Referencia Gráfica de Tabla: {os.path.join('metadata', dest_ip, f'tabla_metadata_{method}.png')}\n")
            report_file.write(f"- Referencia Gráfico de Hops por Método: {os.path.join('metadata', dest_ip, f'hops_por_metodo_{dest_ip}.png')}\n")
            report_file.write(f"- Referencia Gráfico de Distribución de AS: {os.path.join('metadata', dest_ip, f'distribucion_as_{dest_ip}.png')}\n\n")
            
            # Analizar respuestas inconsistentes y generar archivos en analice/
            analyze_inconsistent_responses(dest_ip, routes, report_file)
        
        report_file.write("="*60 + "\n")
        report_file.write("Fin del Informe\n")
    
    print(f"\nInforme de análisis global generado en {report_path}")

if __name__ == "__main__":
    main()
