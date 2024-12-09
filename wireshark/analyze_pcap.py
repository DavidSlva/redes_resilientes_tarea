import os
import pyshark
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import pandas as pd

# Configuración
PCAP_FILE = os.path.join("wireshark", "captura_general.pcap")

# Directorios para almacenar resultados y gráficos
RESULTADOS_DIR = "resultados"
ANALISIS_DIR = "analice"

os.makedirs(RESULTADOS_DIR, exist_ok=True)
os.makedirs(ANALISIS_DIR, exist_ok=True)

# Diccionario para almacenar información por flujo
flows = defaultdict(list)

def classify_packet(pkt):
    """
    Clasifica el tipo de paquete y extrae información clave.
    """
    info = {
        "ttl": None,
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "icmp_type": None,
        "udp_dstport": None,
        "tcp_flags": None,
        "ip_id": None,
        "direction": None  # "outbound" (solicitud) o "inbound" (respuesta)
    }

    if hasattr(pkt, 'ip'):
        info["ttl"] = int(pkt.ip.ttl)
        info["src_ip"] = pkt.ip.src
        info["dst_ip"] = pkt.ip.dst
        if hasattr(pkt.ip, 'id'):
            info["ip_id"] = pkt.ip.id

        if hasattr(pkt, 'icmp'):
            info["protocol"] = "ICMP"
            if hasattr(pkt.icmp, 'type'):
                info["icmp_type"] = pkt.icmp.type
        elif hasattr(pkt, 'udp'):
            info["protocol"] = "UDP"
            if hasattr(pkt.udp, 'dstport'):
                info["udp_dstport"] = pkt.udp.dstport
        elif hasattr(pkt, 'tcp'):
            info["protocol"] = "TCP"
            if hasattr(pkt.tcp, 'flags'):
                info["tcp_flags"] = pkt.tcp.flags
        else:
            info["protocol"] = "OTHER"
    else:
        return None

    return info

def identify_all_flows(all_flows):
    """
    Identifica y analiza todos los flujos presentes en el pcap.
    """
    results = []

    for key, packets in all_flows.items():
        origin_ip, dest_ip = key
        traffic_type = analyze_flow(packets, origin_ip, dest_ip)
        results.append((key, traffic_type))
    return results

def analyze_flow(flow_packets, origin_ip, dest_ip):
    """
    Analiza un flujo específico y determina su tipo de traceroute.
    """
    # Separar outbound e inbound
    out_packets = [p for p in flow_packets if p["src_ip"] == origin_ip and p["dst_ip"] == dest_ip]
    in_packets = [p for p in flow_packets if p["dst_ip"] == origin_ip and p["src_ip"] != origin_ip]

    # Asignar direcciones
    for p in out_packets:
        p["direction"] = "outbound"
    for p in in_packets:
        p["direction"] = "inbound"

    # Análisis de protocolos en outbound
    icmp_requests = [p for p in out_packets if p["protocol"] == "ICMP" and p["icmp_type"] == '8']
    udp_out = [p for p in out_packets if p["protocol"] == "UDP"]
    tcp_out = [p for p in out_packets if p["protocol"] == "TCP"]

    # Análisis de respuestas inbound
    icmp_replies = [p for p in in_packets if p["protocol"] == "ICMP" and p["icmp_type"] == '0']
    icmp_timeex = [p for p in in_packets if p["protocol"] == "ICMP" and p["icmp_type"] == '11']
    icmp_unreach = [p for p in in_packets if p["protocol"] == "ICMP" and p["icmp_type"] == '3']
    tcp_in_rst = [p for p in in_packets if p["protocol"] == "TCP" and p["tcp_flags"] and "0x004" in p["tcp_flags"]]

    # Determinar tipo base
    traffic_type = "Unknown"

    if icmp_requests:
        if icmp_replies:
            traffic_type = "ICMP traceroute"
        else:
            traffic_type = "ICMP traceroute (incompleto)"
    elif udp_out:
        if icmp_unreach:
            traffic_type = "UDP traceroute"
        else:
            traffic_type = "UDP traceroute (incompleto)"
    elif tcp_out:
        tcp_syn = any('0x002' in p["tcp_flags"] for p in tcp_out if p["tcp_flags"])
        tcp_ack = any('0x010' in p["tcp_flags"] for p in tcp_out if p["tcp_flags"])
        if tcp_in_rst:
            if tcp_syn:
                traffic_type = "TCP SYN traceroute"
            elif tcp_ack:
                traffic_type = "TCP ACK traceroute"
            else:
                traffic_type = "TCP traceroute"
        else:
            traffic_type = "TCP traceroute (incompleto)"

    # Detectar tracelb
    ttl_map = defaultdict(set)
    for p in in_packets:
        if p["protocol"] == "ICMP" and p["icmp_type"] == '11':
            ttl_map[p["ttl"]].add(p["src_ip"])
    multiple_paths = any(len(ips) > 1 for ips in ttl_map.values())
    if multiple_paths:
        traffic_type += " (posible tracelb)"

    # Detectar métodos Paris
    if traffic_type.startswith("ICMP") or traffic_type.startswith("UDP"):
        ip_ids = [p["ip_id"] for p in out_packets if p["ip_id"] is not None]
        if ip_ids:
            unique_ids = set(ip_ids)
            variability = len(unique_ids) / len(ip_ids)
            if variability < 0.3:  # Umbral de variabilidad baja
                traffic_type = traffic_type.replace("traceroute", "Paris-traceroute")

    return traffic_type

def plot_ttl_responses(flow_packets, origin_ip, dest_ip):
    """
    Genera gráficos de TTL vs. Número de Respuestas y Tipo de Respuesta por TTL.
    """
    # Separar outbound e inbound
    out_packets = [p for p in flow_packets if p["src_ip"] == origin_ip and p["dst_ip"] == dest_ip]
    in_packets = [p for p in flow_packets if p["dst_ip"] == origin_ip and p["src_ip"] != origin_ip]

    # Contar respuestas por TTL
    ttl_responses = defaultdict(list)
    for p in in_packets:
        if p["protocol"] == "ICMP":
            ttl_responses[p["ttl"]].append(p["icmp_type"])

    if not ttl_responses:
        print(f"No se encontraron respuestas inbound para el flujo {origin_ip} -> {dest_ip}.")
        return

    # Datos para gráficos
    ttl = sorted(ttl_responses.keys())
    num_responses = [len(ttl_responses[t]) for t in ttl]
    response_types = [Counter(ttl_responses[t]) for t in ttl]

    # Gráfico 1: TTL vs. Número de Respuestas
    plt.figure(figsize=(10, 6))
    plt.bar(ttl, num_responses, color='skyblue')
    plt.xlabel('TTL')
    plt.ylabel('Número de Respuestas')
    plt.title(f'TTL vs. Número de Respuestas para {origin_ip} -> {dest_ip}')
    plt.xticks(ttl)
    plt.savefig(os.path.join(ANALISIS_DIR, f"{dest_ip}_ttl_responses.png"))
    plt.close()

    # Gráfico 2: Tipo de Respuesta por TTL
    plt.figure(figsize=(12, 8))
    for t, counter in zip(ttl, response_types):
        labels = counter.keys()
        sizes = counter.values()
        plt.bar(t, sizes, label=f'TTL {t}', alpha=0.7)

    plt.xlabel('TTL')
    plt.ylabel('Número de Tipos de Respuestas')
    plt.title(f'Tipo de Respuesta por TTL para {origin_ip} -> {dest_ip}')
    plt.legend(title="TTL")
    plt.savefig(os.path.join(ANALISIS_DIR, f"{dest_ip}_response_types.png"))
    plt.close()

def main():
    if not os.path.exists(PCAP_FILE):
        print(f"No se encontró el archivo pcap en {PCAP_FILE}")
        return

    print("Cargando pcap, esto puede tardar...")
    cap = pyshark.FileCapture(PCAP_FILE, keep_packets=False)

    print("Clasificando paquetes...")
    for pkt in cap:
        info = classify_packet(pkt)
        if info:
            key = (info["src_ip"], info["dst_ip"])
            flows[key].append(info)
    cap.close()

    if not flows:
        print("No se encontraron paquetes relevantes.")
        return

    # Analizar todos los flujos
    results = identify_all_flows(flows)

    if not results:
        print("No se identificaron flujos principales.")
        return

    print("\nResultados del análisis de todos los flujos:")
    for (origin_ip, dest_ip), traffic_type in results:
        print(f"\nFlujo: {origin_ip} -> {dest_ip}")
        print(f"Tipo de traceroute detectado: {traffic_type}")

        # Obtener paquetes del flujo
        flow_packets = flows[(origin_ip, dest_ip)]

        # Asignar direcciones
        for p in flow_packets:
            if p["src_ip"] == origin_ip and p["dst_ip"] == dest_ip:
                p["direction"] = "outbound"
            elif p["dst_ip"] == origin_ip and p["src_ip"] != origin_ip:
                p["direction"] = "inbound"
            else:
                p["direction"] = "unknown"

        # Filtrar solo paquetes outbound e inbound
        flow_clean = [p for p in flow_packets if p["direction"] in ("outbound", "inbound")]

        # Generar reportes
        report_file = os.path.join(ANALISIS_DIR, f"{dest_ip}_analysis.txt")
        with open(report_file, "w", encoding="utf-8") as rf:
            rf.write(f"Análisis de Traceroute para {origin_ip} -> {dest_ip}\n")
            rf.write("="*60 + "\n\n")
            rf.write(f"Tipo de traceroute detectado: {traffic_type}\n\n")
            rf.write("Resumen de paquetes outbound:\n")
            df_out = pd.DataFrame([p for p in flow_clean if p["direction"] == "outbound"])
            rf.write(df_out.to_string(index=False))
            rf.write("\n\nResumen de paquetes inbound:\n")
            df_in = pd.DataFrame([p for p in flow_clean if p["direction"] == "inbound"])
            rf.write(df_in.to_string(index=False))
            rf.write("\n")

        print(f"Reporte de análisis generado en {report_file}")

        # Generar gráficos si hay respuestas inbound
        if any(p["direction"] == "inbound" for p in flow_clean):
            plot_ttl_responses(flow_clean, origin_ip, dest_ip)
            print(f"Gráficos generados en el directorio '{ANALISIS_DIR}'.")
        else:
            print(f"No se generaron gráficos para el flujo {origin_ip} -> {dest_ip} debido a la ausencia de respuestas inbound.")

if __name__ == "__main__":
    main()
