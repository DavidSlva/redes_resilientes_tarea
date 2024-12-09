import os
import re
import matplotlib.pyplot as plt
import pandas as pd

# Definir las IPs de destino y los métodos disponibles
DEST_IPS = [
    "185.131.204.20",
    "5.161.76.19",
    "80.77.4.60",
    "130.104.228.159"
]

TR_METHODS = [
    "icmp-paris",
    "udp-paris",
    "tcp",
    "icmp",
    "udp",
    "tcp-ack"
]

# Mapeo de métodos a los nombres en el archivo de análisis
METHODS_MAPPING = {
    "icmp-paris": "ICMP Echo Request (Paris)",
    "udp-paris": "UDP Datagram (Paris)",
    "tcp": "TCP SYN",
    "icmp": "ICMP Echo Request",
    "udp": "UDP Datagram",
    "tcp-ack": "TCP ACK"
}

# Ruta base donde se encuentra la carpeta 'analice'
BASE_DIR = "analice"

def parse_analysis_file(file_path):
    """
    Parse the analisis_global.txt file and return a dictionary
    with method counts of found and not found responses.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    # Inicializar contadores
    method_counts = {method: {'found': 0, 'not_found': 0} for method in TR_METHODS}

    # Encontrar la línea de encabezado que contiene los métodos
    header_start = False
    headers = []
    for i, line in enumerate(lines):
        if "HOP" in line and any(m in line for m in METHODS_MAPPING.values()):
            header_line = line
            data_start_line = i + 2  # Asumiendo que los datos empiezan dos líneas después del encabezado
            break
    else:
        print(f"No se encontró la línea de encabezado en {file_path}")
        return method_counts

    # Usar expresiones regulares para dividir el encabezado en columnas
    header_columns = re.split(r'\s{2,}', header_line.strip())
    
    # Verificar que los métodos mapeados están en el encabezado
    for method_key, method_name in METHODS_MAPPING.items():
        if method_name not in header_columns:
            print(f"Advertencia: El método '{method_name}' no se encontró en el encabezado de {file_path}")
    
    # Crear un índice para cada método basado en el encabezado
    method_indices = {method_key: header_columns.index(method_name) for method_key, method_name in METHODS_MAPPING.items() if method_name in header_columns}
    
    # Procesar cada línea de hop
    for line in lines[data_start_line:]:
        line = line.strip()
        if not line or line.startswith("==="):
            continue  # Saltar líneas vacías o finales
        # Dividir la línea en columnas usando múltiples espacios como separador
        hop_columns = re.split(r'\s{2,}', line)
        if len(hop_columns) < len(header_columns):
            # Si la línea tiene menos columnas de lo esperado, puede que tenga algún formato inconsistente
            print(f"Advertencia: Línea con formato inconsistente en {file_path}: '{line}'")
            continue
        for method_key, index in method_indices.items():
            response = hop_columns[index]
            if response == "*":
                method_counts[method_key]['not_found'] += 1
            else:
                method_counts[method_key]['found'] += 1

    return method_counts

def generate_plot(dest_ip, counts):
    """
    Generate and save a bar plot for the given destination IP and counts.
    """
    methods = TR_METHODS
    found = [counts[method]['found'] for method in methods]
    not_found = [counts[method]['not_found'] for method in methods]

    x = range(len(methods))
    width = 0.6  # Ancho de las barras

    fig, ax = plt.subplots(figsize=(12, 7))
    bars1 = ax.bar(x, found, width, label='Encontrado', color='skyblue')
    bars2 = ax.bar(x, not_found, width, bottom=found, label='No Encontrado', color='salmon')

    # Etiquetas y título
    ax.set_xlabel('Métodos', fontsize=14)
    ax.set_ylabel('Número de Respuestas', fontsize=14)
    ax.set_title(f'Comparación de Métodos para {dest_ip}', fontsize=16)
    ax.set_xticks(x)
    ax.set_xticklabels([METHODS_MAPPING[m] for m in methods], rotation=45, ha='right', fontsize=12)
    ax.legend(fontsize=12)

    # Añadir etiquetas de valor encima de las barras
    for bar in bars1 + bars2:
        height = bar.get_height()
        if height > 0:
            ax.annotate('{}'.format(height),
                        xy=(bar.get_x() + bar.get_width() / 2, bar.get_y() + height / 2),
                        xytext=(0, 0),  # No desplazamiento
                        textcoords="offset points",
                        ha='center', va='center', fontsize=10, color='black')

    plt.tight_layout()
    # Guardar el gráfico como una imagen PNG
    output_dir = "graficos"
    os.makedirs(output_dir, exist_ok=True)
    plt.savefig(os.path.join(output_dir, f"{dest_ip}.png"))
    plt.close()
    print(f"Gráfico guardado para {dest_ip} en {output_dir}/{dest_ip}.png")

def main():
    for dest_ip in DEST_IPS:
        print(f"Procesando {dest_ip}...")
        dest_dir = os.path.join(BASE_DIR, dest_ip)
        analysis_file = os.path.join(dest_dir, "analisis_global.txt")
        
        if not os.path.exists(analysis_file):
            print(f"Archivo {analysis_file} no encontrado. Saltando {dest_ip}.")
            continue
        
        counts = parse_analysis_file(analysis_file)
        generate_plot(dest_ip, counts)

if __name__ == "__main__":
    main()
