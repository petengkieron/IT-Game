import logging
from scapy.all import rdpcap, IP
from collections import Counter
import json
from virustotal import check_ip_reputation
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logger = logging.getLogger(__name__)

def analyze_pcap(filepath):
    logger.info(f"Starting analysis of {filepath}")
    packets = rdpcap(filepath)
    
    # Initialize analysis results
    results = {
        'total_packets': len(packets),
        'ip_sources': Counter(),
        'ip_destinations': Counter(),
        'protocols': Counter(),
        'suspicious_ips': []
    }
    
    # Parallel packet processing
    with ThreadPoolExecutor(max_workers=4) as executor:
        packet_futures = {executor.submit(process_packet, packet): packet for packet in packets}
        for future in as_completed(packet_futures):
            if future.result():
                src, dst, proto = future.result()
                results['ip_sources'][src] += 1
                results['ip_destinations'][dst] += 1
                results['protocols'][proto] += 1

    # Convert Counters to dict
    results['ip_sources'] = dict(results['ip_sources'])
    results['ip_destinations'] = dict(results['ip_destinations'])
    results['protocols'] = dict(results['protocols'])
    
    # Parallel threat analysis
    unique_ips = set(results['ip_sources'].keys()) | set(results['ip_destinations'].keys())
    threat_analysis = parallel_threat_analysis(unique_ips)
    results['threat_analysis'] = threat_analysis

    # Parallel connection analysis
    infection_data = analyze_suspicious_connections(packets)
    results['infection_analysis'] = infection_data

    # Add user behavior analysis
    user_data = parallel_user_analysis(packets)
    results['user_analysis'] = user_data

    return results

def process_packet(packet):
    if IP in packet:
        return packet[IP].src, packet[IP].dst, packet[IP].proto
    return None

def parallel_threat_analysis(unique_ips):
    threat_analysis = {
        'high_risk': [], 'medium_risk': [], 
        'low_risk': [], 'unknown': []
    }
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_ip = {
            executor.submit(check_ip_reputation, ip): ip 
            for ip in unique_ips
        }
        
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                threat_data = future.result()
                if not threat_data.get('error'):
                    threat_level = threat_data.get('threat_level', 'Unknown')
                    if threat_level == 'High':
                        threat_analysis['high_risk'].append(threat_data)
                    elif threat_level == 'Medium':
                        threat_analysis['medium_risk'].append(threat_data)
                    elif threat_level == 'Low':
                        threat_analysis['low_risk'].append(threat_data)
                    else:
                        threat_analysis['unknown'].append(threat_data)
            except Exception as e:
                logger.error(f"Error analyzing IP {ip}: {e}")
    
    return threat_analysis

def parallel_user_analysis(packets):
    time.sleep(0.1)  # Reduced sleep time
    return analyze_user_behavior(packets)

def analyze_suspicious_connections(packets):
    infection_data = {
        'infected_machines': [],
        'malicious_sources': [],
        'suspicious_patterns': [],
        'potential_flag': None  # Pour stocker la machine flag
    }

    # Analyse approfondie des connexions
    connection_pairs = {}
    connection_sequences = {}
    
    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            key = f"{src}->{dst}"
            
            # Analyser les séquences de connexions
            if src not in connection_sequences:
                connection_sequences[src] = {
                    'destinations': [],
                    'timestamps': [],
                    'connection_count': 0,
                    'data_transferred': 0
                }
            
            connection_sequences[src]['destinations'].append(dst)
            connection_sequences[src]['timestamps'].append(packet.time)
            connection_sequences[src]['connection_count'] += 1
            if hasattr(packet, 'len'):
                connection_sequences[src]['data_transferred'] += packet.len

            # Stocker les paires de connexions
            if key not in connection_pairs:
                connection_pairs[key] = {
                    'count': 0,
                    'source': src,
                    'destination': dst,
                    'timestamps': [],
                    'intervals': [],
                    'data_size': []
                }
            
            connection_pairs[key]['count'] += 1
            connection_pairs[key]['timestamps'].append(packet.time)
            if hasattr(packet, 'len'):
                connection_pairs[key]['data_size'].append(packet.len)

    # Analyser les modèles de comportement suspects
    for src, data in connection_sequences.items():
        # Détecter les modèles de Command & Control (C&C)
        if (len(set(data['destinations'])) < 3 and 
            data['connection_count'] > 50 and 
            data['data_transferred'] > 1000):
            infection_data['potential_flag'] = src
            infection_data['suspicious_patterns'].append({
                'type': 'potential_flag_found',
                'ip': src,
                'connections': data['connection_count'],
                'data_transferred': data['data_transferred'],
                'evidence': 'Modèle de trafic correspondant à une infection'
            })

    # Identifier les machines infectées
    for pair, data in connection_pairs.items():
        if data['count'] > 10:
            # Calculer les intervalles entre les connexions
            intervals = [data['timestamps'][i+1] - data['timestamps'][i] 
                       for i in range(len(data['timestamps'])-1)]
            
            if intervals and sum(intervals)/len(intervals) < 0.1:
                infection_data['suspicious_patterns'].append({
                    'type': 'repetitive_connection',
                    'source': data['source'],
                    'destination': data['destination'],
                    'count': data['count'],
                    'avg_interval': sum(intervals)/len(intervals)
                })
                
                if data['source'] == infection_data['potential_flag']:
                    infection_data['infected_machines'].append(data['destination'])
                    infection_data['malicious_sources'].append(data['source'])

    return infection_data

def analyze_user_behavior(packets):
    user_data = {
        'legitimate_users': [],
        'suspicious_users': [],
        'behavior_patterns': []
    }
    
    # Analyse par IP
    ip_behavior = {}
    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            if src not in ip_behavior:
                ip_behavior[src] = {
                    'ip': src,
                    'packet_count': 0,
                    'destinations': set(),
                    'protocols': set(),
                    'timestamps': [],
                    'avg_interval': 0
                }
            
            ip_behavior[src]['packet_count'] += 1
            ip_behavior[src]['destinations'].add(packet[IP].dst)
            ip_behavior[src]['protocols'].add(packet[IP].proto)
            ip_behavior[src]['timestamps'].append(packet.time)

    # Analyser chaque IP pour déterminer si c'est un vrai utilisateur
    for ip, data in ip_behavior.items():
        # Calculer l'intervalle moyen entre les paquets
        if len(data['timestamps']) > 1:
            intervals = [data['timestamps'][i+1] - data['timestamps'][i] 
                       for i in range(len(data['timestamps'])-1)]
            data['avg_interval'] = sum(intervals) / len(intervals)

        # Critères de détection des vrais utilisateurs
        is_legitimate = True
        reasons = []

        # 1. Trop de paquets en peu de temps
        if data['packet_count'] > 1000 and data['avg_interval'] < 0.1:
            is_legitimate = False
            reasons.append('Trafic anormalement élevé')

        # 2. Trop de destinations différentes
        if len(data['destinations']) > 100:
            is_legitimate = False
            reasons.append('Nombre suspect de destinations')

        # 3. Comportement trop régulier (bot)
        if data['avg_interval'] > 0 and data['avg_interval'] < 0.01:
            is_legitimate = False
            reasons.append('Modèle de trafic automatisé')

        behavior_data = {
            'ip': ip,
            'packet_count': data['packet_count'],
            'unique_destinations': len(data['destinations']),
            'protocols_used': len(data['protocols']),
            'avg_interval': data['avg_interval'],
            'reasons': reasons
        }

        if is_legitimate:
            user_data['legitimate_users'].append(behavior_data)
        else:
            user_data['suspicious_users'].append(behavior_data)
            user_data['behavior_patterns'].append({
                'ip': ip,
                'type': 'suspicious_behavior',
                'reasons': reasons
            })

    return user_data
