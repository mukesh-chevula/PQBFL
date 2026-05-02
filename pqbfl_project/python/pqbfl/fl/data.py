import numpy as np
import pandas as pd
from typing import Tuple, List, Dict
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split
from dataclasses import dataclass

@dataclass(frozen=True)
class ClientDataset:
    x: np.ndarray
    y: np.ndarray

@dataclass(frozen=True)
class FederatedDataset:
    clients: list[ClientDataset]
    x_test: np.ndarray
    y_test: np.ndarray
# This matches the mapping in binary.py
dict_2classes = {
    'DDoS-RSTFINFlood': 'attack',
    'DDoS-PSHACK_Flood': 'attack',
    'DDoS-SYN_Flood': 'attack',
    'DDoS-UDP_Flood': 'attack',
    'DDoS-TCP_Flood': 'attack',
    'DDoS-ICMP_Flood': 'attack',
    'DDoS-SynonymousIP_Flood': 'attack',
    'DDoS-ACK_Fragmentation': 'attack',
    'DDoS-UDP_Fragmentation': 'attack',
    'DDoS-ICMP_Fragmentation': 'attack',
    'DDoS-SlowLoris': 'attack',
    'DDoS-HTTP_Flood': 'attack',
    'DoS-UDP_Flood': 'attack',
    'DoS-SYN_Flood': 'attack',
    'DoS-TCP_Flood': 'attack',
    'DoS-HTTP_Flood': 'attack',
    'Mirai-greeth_flood': 'attack',
    'Mirai-greip_flood': 'attack',
    'Mirai-udpplain': 'attack',
    'Recon-PingSweep': 'attack',
    'Recon-OSScan': 'attack',
    'Recon-PortScan': 'attack',
    'VulnerabilityScan': 'attack',
    'Recon-HostDiscovery': 'attack',
    'DNS_Spoofing': 'attack',
    'MITM-ArpSpoofing': 'attack',
    'BenignTraffic': 'Notattack',
    'BrowserHijacking': 'attack',
    'Backdoor_Malware': 'attack',
    'XSS': 'attack',
    'Uploading_Attack': 'attack',
    'SqlInjection': 'attack',
    'CommandInjection': 'attack',
    'DictionaryBruteForce': 'attack'
}

X_columns = [
    'flow_duration', 'Header_Length', 'Protocol Type', 'Duration',
    'Rate', 'Srate', 'Drate', 'fin_flag_number', 'syn_flag_number',
    'rst_flag_number', 'psh_flag_number', 'ack_flag_number',
    'ece_flag_number', 'cwr_flag_number', 'ack_count',
    'syn_count', 'fin_count', 'urg_count', 'rst_count',
    'HTTP', 'HTTPS', 'DNS', 'Telnet', 'SMTP', 'SSH', 'IRC', 'TCP',
    'UDP', 'DHCP', 'ARP', 'ICMP', 'IPv', 'LLC', 'Tot sum', 'Min',
    'Max', 'AVG', 'Std', 'Tot size', 'IAT', 'Number', 'Magnitue',
    'Radius', 'Covariance', 'Variance', 'Weight',
]

def load_and_preprocess_dataset(csv_path: str, n_clients: int, seed: int = 42) -> FederatedDataset:
    print(f"Loading dataset from {csv_path}...")
    # Load dataset
    df = pd.read_csv(csv_path)
    
    # Fast Logistic Regression allows us to use the full dataset instantly
    
    # Map labels to binary (attack / Notattack)
    print("Mapping labels...")
    y_raw = df['label']
    new_y = [dict_2classes.get(k, 'attack') for k in y_raw] # Default to attack if unknown
    
    # Extract features
    print("Extracting features...")
    X = df[X_columns].values.astype(np.float32)
    
    y = np.array([1 if label == 'attack' else 0 for label in new_y]).astype(np.int64)
    
    print(f"Total samples: {len(X)}")
    print(f"Class distribution: {np.bincount(y)}")

    # Train/Test Split (80/20)
    print("Splitting train/test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=seed, stratify=y
    )
    
    # Scale features
    print("Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Partition data among clients
    print(f"Partitioning data among {n_clients} clients...")
    
    # For simplicity, we randomly partition the data equally among clients
    # In a real FL scenario, this could be non-IID
    indices = np.arange(len(X_train_scaled))
    np.random.seed(seed)
    np.random.shuffle(indices)
    
    splits = np.array_split(indices, n_clients)
    
    clients = []
    for i, split_indices in enumerate(splits):
        c_x = X_train_scaled[split_indices]
        c_y = y_train[split_indices]
        class_dist = np.bincount(c_y, minlength=2)
        print(f"      -> Client {i+1}/{n_clients} receives {len(c_x)} samples (0s: {class_dist[0]}, 1s: {class_dist[1]})")
        clients.append(ClientDataset(
            x=c_x,
            y=c_y
        ))
        
    return FederatedDataset(
        clients=clients,
        x_test=X_test_scaled,
        y_test=y_test
    )
