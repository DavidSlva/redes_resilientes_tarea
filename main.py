import subprocess
import time
import os
import re
import concurrent.futures
from tqdm import tqdm
from threading import Lock

# IPs destino
DEST_IPS = [
    "185.131.204.20",
    "5.161.76.19",
    "80.77.4.60",
    "130.104.228.159"
]

# Métodos disponibles en scamper (asegúrate que tu versión los soporte)
TR_METHODS = [
    "icmp-paris",
    "udp-paris",
    "tcp",
    "icmp",
    "udp",
    "tcp-ack"
]

# Interfaz de red a capturar (ajustar según tu sistema)
NETWORK_INTERFACE = "eth0"

# Directorio de salida
OUTPUT_DIR = "resultados"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Cache para información AS
as_cache = {}
cache_lock = Lock()

def run_tshark_capture(output_file):
    """Inicia una captura de tráfico con tshark en un proceso separado."""
    cmd = ["tshark", "-i", NETWORK_INTERFACE, "-f", "icmp or tcp or udp", "-w", output_file]
    print(f"Iniciando captura con tshark en {NETWORK_INTERFACE}...")
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return p

def stop_tshark_capture(proc):
    """Detiene la captura tshark."""
    print("Deteniendo captura con tshark...")
    proc.terminate()
    proc.wait()

def run_scamper_trace(dest_ip, method, output_file):
    """Ejecuta scamper con el método especificado contra la IP destino."""
    cmd = f"scamper -O warts -o {output_file} -c 'trace -P {method}' -i {dest_ip}"
    print(f"Ejecutando scamper: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Scamper trace completado para {dest_ip} con método {method}.")
        return True, ""
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar scamper trace para {dest_ip} con método {method}:")
        print(f"Comando ejecutado: {cmd}")
        print(f"Error: {e.stderr.decode()}")
        return False, e.stderr.decode()

def parse_warts_to_text(warts_file, txt_file):
    """Convierte el archivo warts a texto con sc_warts2text para su análisis."""
    cmd = ["sc_warts2text", warts_file]
    try:
        print(f"Convirtiendo {warts_file} a texto...")
        with open(txt_file, "w") as f:
            subprocess.run(cmd, stdout=f, check=True)
        print(f"Conversión completada: {txt_file}")
        return True, ""
    except subprocess.CalledProcessError as e:
        print(f"Error al convertir {warts_file} a texto:")
        print(f"Comando ejecutado: {' '.join(cmd)}")
        print(f"Error: {e.stderr.decode()}")
        return False, e.stderr.decode()

def get_as_info(ip):
    """Obtiene información de AS a partir de la IP, utilizando whois con caching."""
    if ip in ["*", ""]:  # No responder o IP vacía
        return "Unknown"

    with cache_lock:
        if ip in as_cache:
            return as_cache[ip]

    try:
        result = subprocess.check_output(["whois", ip], universal_newlines=True, stderr=subprocess.DEVNULL)
        match = re.search(r"AS\d+", result, re.IGNORECASE)
        asn = match.group(0).upper() if match else "Unknown"
    except Exception:
        asn = "Unknown"

    with cache_lock:
        as_cache[ip] = asn

    return asn

def analyze_traceroute_txt(txt_file, as_map_file):
    """Lee el archivo de texto del traceroute, extrae las IPs por hop y obtiene su AS."""
    try:
        with open(txt_file, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"Archivo {txt_file} no encontrado.")
        return False, f"Archivo {txt_file} no encontrado."

    hops_info = []
    for line in lines:
        line = line.strip()
        if line.startswith("hop"):
            parts = line.split()
            if len(parts) > 2:
                hop_ip = next((p for p in parts[2:] if re.match(r"\d+\.\d+\.\d+\.\d+", p)), None)
                if hop_ip:
                    asn = get_as_info(hop_ip)
                    hops_info.append((parts[1], hop_ip, asn))

    try:
        with open(as_map_file, "w") as f:
            f.write("Hop\tIP\tAS\n")
            for hop_num, ip, asn in hops_info:
                f.write(f"{hop_num}\t{ip}\t{asn}\n")
        print(f"Análisis completado: {as_map_file}")
        return True, ""
    except Exception as e:
        print(f"Error al escribir en {as_map_file}: {str(e)}")
        return False, str(e)

def run_tracelb(dest_ip, output_file):
    """Ejecuta scamper con opción tracelb."""
    cmd = [
        "scamper",
        "-O", "warts",
        "-o", output_file,
        "-c", "tracelb",
        "-i", dest_ip
    ]
    try:
        print(f"Ejecutando scamper tracelb: {' '.join(cmd)}")
        result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Scamper tracelb completado para {dest_ip}.")
        return True, ""
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar scamper tracelb para {dest_ip}:")
        print(f"Comando ejecutado: {' '.join(cmd)}")
        print(f"Error: {e.stderr.decode()}")
        return False, e.stderr.decode()

def process_trace(dest_ip, method):
    """Procesa una única tarea de traceroute."""
    warts_output = os.path.join(OUTPUT_DIR, f"trace_{dest_ip}_{method}.warts")
    txt_output = os.path.join(OUTPUT_DIR, f"trace_{dest_ip}_{method}.txt")
    as_output = os.path.join(OUTPUT_DIR, f"trace_{dest_ip}_{method}_as.txt")

    # Ejecutar scamper trace
    success, error = run_scamper_trace(dest_ip, method, warts_output)
    if not success:
        return f"Error en scamper trace hacia {dest_ip} con método {method}: {error}"

    # Verificar si el archivo warts contiene datos
    if os.path.getsize(warts_output) == 0:
        return f"Archivo warts vacío para {dest_ip} con método {method}."

    # Convertir warts a texto
    success, error = parse_warts_to_text(warts_output, txt_output)
    if not success:
        return f"Error al convertir {warts_output} a texto: {error}"

    # Verificar si el archivo txt contiene datos
    if os.path.getsize(txt_output) == 0:
        return f"Archivo txt vacío después de la conversión para {warts_output}."

    # Analizar traceroute
    success, error = analyze_traceroute_txt(txt_output, as_output)
    if not success:
        return f"Error al analizar {txt_output}: {error}"

    # Verificar si as_map_file contiene datos
    if os.path.getsize(as_output) <= len("Hop\tIP\tAS\n"):
        return f"Archivo as_map_file vacío para {as_output}."

    return None  # Sin errores

def process_tracelb(dest_ip):
    """Procesa una única tarea de tracelb."""
    warts_output = os.path.join(OUTPUT_DIR, f"tracelb_{dest_ip}.warts")
    txt_output = os.path.join(OUTPUT_DIR, f"tracelb_{dest_ip}.txt")
    as_output = os.path.join(OUTPUT_DIR, f"tracelb_{dest_ip}_as.txt")

    # Ejecutar tracelb
    success, error = run_tracelb(dest_ip, warts_output)
    if not success:
        return f"Error en scamper tracelb hacia {dest_ip}: {error}"

    # Verificar si el archivo warts contiene datos
    if os.path.getsize(warts_output) == 0:
        return f"Archivo warts vacío para tracelb hacia {dest_ip}."

    # Convertir warts a texto
    success, error = parse_warts_to_text(warts_output, txt_output)
    if not success:
        return f"Error al convertir {warts_output} a texto: {error}"

    # Verificar si el archivo txt contiene datos
    if os.path.getsize(txt_output) == 0:
        return f"Archivo txt vacío después de la conversión para {warts_output}."

    # Analizar traceroute
    success, error = analyze_traceroute_txt(txt_output, as_output)
    if not success:
        return f"Error al analizar {txt_output}: {error}"

    # Verificar si as_map_file contiene datos
    if os.path.getsize(as_output) <= len("Hop\tIP\tAS\n"):
        return f"Archivo as_map_file vacío para {as_output}."

    return None  # Sin errores

def main():
    # Iniciar captura de tráfico con tshark
    pcap_file = os.path.join(OUTPUT_DIR, "captura_general.pcap")
    tshark_proc = run_tshark_capture(pcap_file)

    time.sleep(5)  # Esperar a que la captura se estabilice

    try:
        tasks = []
        errors = []

        # Preparar todas las tareas de traceroute
        for dest in DEST_IPS:
            for method in TR_METHODS:
                tasks.append((dest, method))

        total_tasks = len(tasks) + len(DEST_IPS)  # Incluir tracelb

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            with tqdm(total=total_tasks, desc="Procesando Tareas") as pbar:
                # Enviar tareas de traceroute
                future_to_task = {
                    executor.submit(process_trace, dest, method): (dest, method)
                    for dest, method in tasks
                }

                for future in concurrent.futures.as_completed(future_to_task):
                    task = future_to_task[future]
                    error = future.result()
                    if error:
                        errors.append(error)
                    pbar.update(1)

                # Enviar tareas de tracelb
                future_to_tracelb = {
                    executor.submit(process_tracelb, dest): dest
                    for dest in DEST_IPS
                }

                for future in concurrent.futures.as_completed(future_to_tracelb):
                    dest = future_to_tracelb[future]
                    error = future.result()
                    if error:
                        errors.append(error)
                    pbar.update(1)

        if errors:
            print("\nSe encontraron los siguientes errores durante la ejecución:")
            for err in errors:
                print(f"- {err}")
        else:
            print("\nTodas las tareas se completaron exitosamente.")

    finally:
        # Detener la captura de tráfico
        stop_tshark_capture(tshark_proc)

    print("Proceso completado. Archivos generados en:", OUTPUT_DIR)

if __name__ == "__main__":
    main()
