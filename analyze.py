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
        'potential_flag': None,
        'infection_details': {}  # Nouveau dictionnaire pour les détails
    }

    # Analyse des connexions
    connection_pairs = {}
    first_seen = {}
    last_seen = {}
    geo_data = {}

    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            timestamp = packet.time
            
            # Enregistrer les timestamps pour chaque IP
            for ip in [src, dst]:
                if ip not in first_seen:
                    first_seen[ip] = timestamp
                last_seen[ip] = timestamp

            # Stocker les paires de connexions
            key = f"{src}->{dst}"
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

    # Pour chaque machine infectée, collecter les détails
    for ip in infection_data['infected_machines']:
        infection_data['infection_details'][ip] = {
            'first_seen': first_seen.get(ip),
            'last_seen': last_seen.get(ip),
            'infection_duration': last_seen.get(ip) - first_seen.get(ip) if first_seen.get(ip) else 0,
            'attacker': next((s for s in infection_data['malicious_sources'] 
                            if any(p['source'] == s and p['destination'] == ip 
                                for p in infection_data['suspicious_patterns'])), 'Unknown'),
            'country': get_ip_country(ip),
            'total_connections': sum(1 for p in infection_data['suspicious_patterns'] 
                                   if p['destination'] == ip),
            'attack_pattern': analyze_attack_pattern(ip, infection_data['suspicious_patterns'])
        }

    # Analyse approfondie pour trouver le flag
    potential_flags = {}
    for packet in packets:
        if IP in packet:
            src = packet[IP].src
            if src not in potential_flags:
                potential_flags[src] = {
                    'packet_count': 0,
                    'unique_dst': set(),
                    'timestamps': [],
                    'data_size': 0,
                    'port_patterns': Counter()
                }
            
            potential_flags[src]['packet_count'] += 1
            potential_flags[src]['unique_dst'].add(packet[IP].dst)
            potential_flags[src]['timestamps'].append(packet.time)
            if hasattr(packet, 'len'):
                potential_flags[src]['data_size'] += packet.len
            if hasattr(packet, 'dport'):
                potential_flags[src]['port_patterns'][packet.dport] += 1

    # Identifier le flag en utilisant des critères spécifiques
    for ip, data in potential_flags.items():
        score = 0
        reasons = []

        # Critère 1: Beaucoup de connexions vers peu de destinations
        if len(data['unique_dst']) < 3 and data['packet_count'] > 50:
            score += 3
            reasons.append("Connexions répétitives vers destinations limitées")

        # Critère 2: Modèle de ports suspects (ex: ports communs de malware)
        suspicious_ports = [445, 135, 3389, 22, 4444, 8080]
        if any(port in data['port_patterns'] for port in suspicious_ports):
            score += 2
            reasons.append("Utilisation de ports suspects")

        # Critère 3: Intervalle régulier entre les paquets (bot-like)
        if len(data['timestamps']) > 2:
            intervals = [data['timestamps'][i+1] - data['timestamps'][i] 
                        for i in range(len(data['timestamps'])-1)]
            avg_interval = sum(intervals) / len(intervals)
            if 0.1 < avg_interval < 1.0:  # Intervalle suspect
                score += 2
                reasons.append("Intervalle régulier entre les paquets")

        # Si le score est suffisamment élevé, c'est probablement notre flag
        if score >= 5:
            infection_data['potential_flag'] = ip
            infection_data['flag_evidence'] = {
                'score': score,
                'reasons': reasons,
                'data_transferred': data['data_size'],
                'connection_count': data['packet_count'],
                'unique_destinations': len(data['unique_dst']),
                'timestamp_first': min(data['timestamps']),
                'timestamp_last': max(data['timestamps']),
                'duration': max(data['timestamps']) - min(data['timestamps'])
            }

    return infection_data

def get_ip_country(ip):
    try:
        from geoip2 import database
        reader = database.Reader('GeoLite2-Country.mmdb')
        response = reader.country(ip)
        return response.country.name
    except:
        return "Pays inconnu"

def analyze_attack_pattern(ip, patterns):
    relevant_patterns = [p for p in patterns if p['destination'] == ip]
    if not relevant_patterns:
        return "Inconnu"
    
    # Analyser le type d'attaque basé sur les modèles
    if any(p['count'] > 100 for p in relevant_patterns):
        return "Attaque par force brute"
    elif any(p.get('data_transferred', 0) > 10000 for p in relevant_patterns):
        return "Exfiltration de données"
    else:
        return "Connexions suspectes"

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
