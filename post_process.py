import os
import re
import subprocess
from threading import Lock

RESULTS_DIR = "resultados"
as_cache = {}
cache_lock = Lock()

def get_as_info(ip):
    if ip in ["*", ""]:  # No responder o IP vacía
        return "Unknown"

    with cache_lock:
        if ip in as_cache:
            return as_cache[ip]

    try:
        # Consultar el AS usando whois de Team Cymru
        # "-h whois.cymru.com" indica que se use ese servidor whois
        # Team Cymru devuelve información en un formato parseable.
        whois_cmd = ["whois", "-h", "whois.cymru.com", ip]
        result = subprocess.check_output(whois_cmd, universal_newlines=True, stderr=subprocess.DEVNULL)

        # El resultado suele incluir un encabezado. Por ejemplo:
        # AS      | IP               | AS Name
        # 15169   | 8.8.8.8          | GOOGLE - Google LLC, US
        # Debemos saltar la primera línea (encabezado) y parsear la segunda.
        lines = result.strip().split("\n")
        if len(lines) > 1:
            data_line = lines[-1]  # Tomamos la última línea de datos
            parts = [p.strip() for p in data_line.split("|")]
            # parts[0] suele ser el número de AS (por ej. "15169")
            # Si es un dígito, construimos el AS. De lo contrario, Unknown
            if len(parts) >= 1 and parts[0].isdigit():
                asn = "AS" + parts[0]
            else:
                asn = "Unknown"
        else:
            asn = "Unknown"
    except Exception:
        asn = "Unknown"

    with cache_lock:
        as_cache[ip] = asn

    return asn

def analyze_traceroute_txt(txt_file, as_map_file):
    """Analiza el archivo txt del traceroute y obtiene el AS de cada hop."""
    if not os.path.exists(txt_file):
        print(f"Archivo {txt_file} no encontrado.")
        return

    hops_info = []
    with open(txt_file, "r") as f:
        for line in f:
            line = line.strip()
            # Ignorar líneas vacías o la línea que empieza con 'traceroute'
            if not line or line.startswith("traceroute"):
                continue

            # Esperamos un formato como:
            # <hop_num> <ip> <tiempo> ms
            parts = line.split()
            if len(parts) < 2:
                continue

            hop_num = parts[0]
            # Verificar que hop_num sea un número
            if not hop_num.isdigit():
                continue

            ip_candidate = parts[1]
            # Verificar si es una IP válida
            if re.match(r"\d+\.\d+\.\d+\.\d+", ip_candidate):
                asn = get_as_info(ip_candidate)
                hops_info.append((hop_num, ip_candidate, asn))
            # Si es "*", se ignora ese salto

    # Escribir resultado
    with open(as_map_file, "w") as f:
        f.write("Hop\tIP\tAS\n")
        for hop_num, ip, asn in hops_info:
            f.write(f"{hop_num}\t{ip}\t{asn}\n")

    print(f"Análisis completado: {as_map_file}")

def main():
    # Procesar todos los archivos .txt en el directorio de resultados que tengan el formato trace_..._method.txt
    for filename in os.listdir(RESULTS_DIR):
        if filename.endswith(".txt") and "_as.txt" not in filename and filename.startswith("trace_"):
            txt_file = os.path.join(RESULTS_DIR, filename)
            # Construir nombre del archivo _as correspondiente
            base_name = filename[:-4]  # remover .txt
            as_map_file = os.path.join(RESULTS_DIR, f"{base_name}_as.txt")

            # Analizar el archivo
            analyze_traceroute_txt(txt_file, as_map_file)

if __name__ == "__main__":
    main()
