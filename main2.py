import subprocess
import time
import os
import re
import concurrent.futures
from tqdm import tqdm
from threading import Lock
from collections import defaultdict
import post_process

# IPs destino
DEST_IPS = [
    "185.131.204.20",
    "5.161.76.19",
    "80.77.4.60",
    "130.104.228.159"
]

# Métodos disponibles en scamper
TR_METHODS = [
    "icmp-paris",
    "udp-paris",
    "tcp",
    "icmp",
    "udp",
    "tcp-ack"
]

NETWORK_INTERFACE = "eth0"
OUTPUT_DIR = "resultados"
os.makedirs(OUTPUT_DIR, exist_ok=True)

as_cache = {}
cache_lock = Lock()

def run_tshark_capture(output_file):
    """Inicia una captura con tshark."""
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
    """Obtiene información de AS a partir de la IP usando whois de Team Cymru."""
    if ip in ["*", ""]:
        return "Unknown"

    with cache_lock:
        if ip in as_cache:
            return as_cache[ip]

    try:
        whois_cmd = ["whois", "-h", "whois.cymru.com", ip]
        result = subprocess.check_output(whois_cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
        lines = result.strip().split("\n")
        if len(lines) > 1:
            data_line = lines[-1]
            parts = [p.strip() for p in data_line.split("|")]
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
    """Analiza el archivo texto del traceroute con formato hop-based (sc_warts2text) y extrae IPs y AS."""
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
            # formato esperado: hop <num> <ip> ...
            if len(parts) > 2:
                hop_ip = next((p for p in parts[2:] if re.match(r"\d+\.\d+\.\d+\.\d+", p)), None)
                hop_num = parts[1]
                if hop_ip:
                    asn = get_as_info(hop_ip)
                    hops_info.append((hop_num, hop_ip, asn))

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
    warts_output = os.path.join(OUTPUT_DIR, f"trace_{dest_ip}_{method}.warts")
    txt_output = os.path.join(OUTPUT_DIR, f"trace_{dest_ip}_{method}.txt")
    as_output = os.path.join(OUTPUT_DIR, f"trace_{dest_ip}_{method}_as.txt")

    success, error = run_scamper_trace(dest_ip, method, warts_output)
    if not success:
        return f"Error en scamper trace hacia {dest_ip} con método {method}: {error}"

    if os.path.getsize(warts_output) == 0:
        return f"Archivo warts vacío para {dest_ip} con método {method}."

    success, error = parse_warts_to_text(warts_output, txt_output)
    if not success:
        return f"Error al convertir {warts_output} a texto: {error}"

    if os.path.getsize(txt_output) == 0:
        return f"Archivo txt vacío después de la conversión para {warts_output}."

    success, error = analyze_traceroute_txt(txt_output, as_output)
    if not success:
        return f"Error al analizar {txt_output}: {error}"

    if os.path.getsize(as_output) <= len("Hop\tIP\tAS\n"):
        return f"Archivo as_map_file vacío para {as_output}."

    return None

def process_tracelb(dest_ip):
    warts_output = os.path.join(OUTPUT_DIR, f"tracelb_{dest_ip}.warts")
    txt_output = os.path.join(OUTPUT_DIR, f"tracelb_{dest_ip}.txt")
    as_output = os.path.join(OUTPUT_DIR, f"tracelb_{dest_ip}_as.txt")

    success, error = run_tracelb(dest_ip, warts_output)
    if not success:
        return f"Error en scamper tracelb hacia {dest_ip}: {error}"

    if os.path.getsize(warts_output) == 0:
        return f"Archivo warts vacío para tracelb hacia {dest_ip}."

    success, error = parse_warts_to_text(warts_output, txt_output)
    if not success:
        return f"Error al convertir {warts_output} a texto: {error}"

    if os.path.getsize(txt_output) == 0:
        return f"Archivo txt vacío después de la conversión para {warts_output}."

    success, error = analyze_traceroute_txt(txt_output, as_output)
    if not success:
        return f"Error al analizar {txt_output}: {error}"

    if os.path.getsize(as_output) <= len("Hop\tIP\tAS\n"):
        return f"Archivo as_map_file vacío para {as_output}."

    return None

def analyze_methods_results():
    """
    Analiza los resultados obtenidos por cada método para cada IP.
    - Compara número de hops respondidos por cada método.
    - Identifica una IP que no responda con un método pero sí con otro.
    - Analiza tracelb y lo compara con los 6 métodos.
    """
    # Estructura:
    # results[(dest_ip, method)] = {"hops": int, "ips": int, "responded_hops":[(hop, ip, as), ...]}
    results = {}
    for dest in DEST_IPS:
        for method in TR_METHODS:
            as_file = os.path.join(OUTPUT_DIR, f"trace_{dest}_{method}_as.txt")
            if os.path.exists(as_file):
                responded = []
                with open(as_file, "r") as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines:
                        parts = line.strip().split("\t")
                        if len(parts) == 3:
                            hop, ip, asn = parts
                            responded.append((hop, ip, asn))
                results[(dest, method)] = {
                    "hops": len(responded),
                    "ips": len(set(r[1] for r in responded)),
                    "responded_hops": responded
                }

    # Buscar el método que da más información (más hops respondidos) para cada IP
    print("\nComparación entre los 6 métodos para determinar el más informativo:")
    for dest in DEST_IPS:
        method_info = [(m, results.get((dest, m), {"hops":0})["hops"]) for m in TR_METHODS if (dest, m) in results]
        if not method_info:
            continue
        method_info.sort(key=lambda x: x[1], reverse=True)
        best_method = method_info[0]
        print(f"- Para {dest}, el método con más hops respondidos es {best_method[0]} con {best_method[1]} hops.")

    # Identificar una IP que no responda a un método pero sí a otro
    print("\nBuscando una IP que no responda a un método pero sí a otro:")
    for dest in DEST_IPS:
        # Contar cuántos métodos obtuvieron 0 hops respondidos
        zero_methods = [(m, results.get((dest,m),{"hops":0})["hops"]) for m in TR_METHODS if (dest,m) in results]
        if not zero_methods:
            continue
        # Ver si al menos un método tiene 0 y otro >0
        non_responding = [m for (m,h) in zero_methods if h == 0]
        responding = [m for (m,h) in zero_methods if h > 0]
        if non_responding and responding:
            print(f"- La IP destino {dest} no responde a {non_responding} pero sí responde a {responding}.")
            print("  Esto sugiere una posible regla de filtrado. Por ejemplo, filtra ICMP pero no TCP.")
            print("  Un atacante podría usar el método que sí responde para saltarse el filtrado.\n")

    # Comparar tracelb con los 6 métodos
    print("\nComparando tracelb con los 6 métodos:")
    for dest in DEST_IPS:
        tracelb_as = os.path.join(OUTPUT_DIR, f"tracelb_{dest}_as.txt")
        if not os.path.exists(tracelb_as):
            continue
        with open(tracelb_as, "r") as f:
            tlb_lines = f.readlines()[1:]
            tracelb_ips = set(line.strip().split("\t")[1] for line in tlb_lines if line.strip())

        # Unir todos los IPs obtenidos por los 6 métodos
        all_methods_ips = set()
        for m in TR_METHODS:
            val = results.get((dest,m))
            if val:
                for h in val["responded_hops"]:
                    all_methods_ips.add(h[1])

        extra_in_tracelb = tracelb_ips - all_methods_ips
        if extra_in_tracelb:
            print(f"- Para {dest}, tracelb obtuvo IPs adicionales no vistas en los 6 métodos: {extra_in_tracelb}")
            print("  Esto muestra que tracelb puede revelar rutas adicionales, brindando resiliencia.\n")
        else:
            print(f"- Para {dest}, tracelb no obtuvo IPs adicionales a las vistas en los 6 métodos.\n")

def analyze_pcap(pcap_file):
    """
    Analiza el tráfico capturado para intentar caracterizar el patrón de tráfico.
    Se usará tshark para contar paquetes ICMP, TCP, UDP.
    """
    print("\nAnalizando el tráfico capturado para caracterizar patrones de tráfico:")
    # Contar paquetes ICMP, TCP, UDP en el pcap
    # Ejemplo: tshark -r file -Y "icmp" -> contar lineas
    def count_packets(filter_exp):
        cmd = ["tshark", "-r", pcap_file, "-Y", filter_exp, "-q", "-z", "io,phs"]
        # io,phs imprime estadísticas. Aunque su salida es compleja, aquí contaremos con grep.
        # Alternativamente, se puede usar -T fields -e frame.number y contar líneas.
        # Lo más sencillo: tshark -r file -Y "proto" -T fields -e frame.number | wc -l (si wc está disponible)
        # Aquí asumiendo entorno linux:
        try:
            result = subprocess.check_output(["tshark", "-r", pcap_file, "-Y", filter_exp, "-T", "fields", "-e", "frame.number"], universal_newlines=True)
            lines = result.strip().split("\n")
            lines = [l for l in lines if l.strip()]
            return len(lines)
        except:
            return 0

    icmp_count = count_packets("icmp")
    tcp_count = count_packets("tcp")
    udp_count = count_packets("udp")

    print(f"- Paquetes ICMP capturados: {icmp_count}")
    print(f"- Paquetes TCP capturados: {tcp_count}")
    print(f"- Paquetes UDP capturados: {udp_count}")
    print("Patrón general: cada método genera un tipo distinto de tráfico. Por ejemplo:")
    print("  - icmp-paris e icmp generan ICMP echo requests.")
    print("  - udp-paris y udp generan datagramas UDP a puertos incrementales.")
    print("  - tcp y tcp-ack generan paquetes TCP con banderas específicas (SYN, ACK).")
    print("Esta distinción de tipos de tráfico y puertos involucrados permitiría a un analista identificar el método usado.\n")

def main():
    # Iniciar captura de tráfico
    pcap_file = os.path.join(OUTPUT_DIR, "captura_general.pcap")
    tshark_proc = run_tshark_capture(pcap_file)

    time.sleep(5)  # Esperar para estabilizar la captura

    try:
        tasks = []
        errors = []

        # Preparar tareas
        for dest in DEST_IPS:
            for method in TR_METHODS:
                tasks.append((dest, method))

        total_tasks = len(tasks) + len(DEST_IPS)  # Para incluir tracelb

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            with tqdm(total=total_tasks, desc="Procesando Tareas") as pbar:
                # Ejecutar traceroutes con métodos
                future_to_task = {
                    executor.submit(process_trace, dest, method): (dest, method)
                    for dest, method in tasks
                }

                for future in concurrent.futures.as_completed(future_to_task):
                    error = future.result()
                    if error:
                        errors.append(error)
                    pbar.update(1)

                # Ejecutar tracelb
                future_to_tracelb = {
                    executor.submit(process_tracelb, dest): dest
                    for dest in DEST_IPS
                }

                for future in concurrent.futures.as_completed(future_to_tracelb):
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
        # Detener captura
        stop_tshark_capture(tshark_proc)

    print("Proceso de obtención de rutas completado. Archivos generados en:", OUTPUT_DIR)
    # EL postProcess lo unico que hace es obtener y validar
    post_process.main()
    # Ahora que tenemos todos los resultados, realizamos el análisis solicitado

    analyze_methods_results()
    analyze_pcap(pcap_file)
    print("Análisis finalizado.")

if __name__ == "__main__":
    main()
