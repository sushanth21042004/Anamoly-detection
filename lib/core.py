import threading
import numpy as np
import uuid
import sys
import pickle
import os
import time
import random
from collections import deque
from flask import Flask, jsonify, render_template_string

# --- ML IMPORTS ---
try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
except ImportError:
    pass

# --- SCAPY IMPORTS ---
# Optimization: Skip Scapy entirely on Vercel to save memory/time
if os.environ.get('VERCEL'):
    SCAPY_AVAILABLE = False
else:
    try:
        from scapy.all import sniff, IP, TCP, UDP, DNS, conf
        SCAPY_AVAILABLE = True
    except Exception:
        SCAPY_AVAILABLE = False

# --- CONFIGURATION ---
MAX_HISTORY = 100

# --- GLOBAL STATE ---
class AppState:
    def __init__(self):
        self.status = "IDLE" 
        self.mode = "REAL" 
        self.training_progress = 100 
        self.traffic_data = deque(maxlen=MAX_HISTORY)
        self.recent_packets = deque(maxlen=15)
        self.alerts = deque(maxlen=20)
        self.model = None
        self.scaler = None
        self.lock = threading.Lock()
        self.stop_signal = False
        self.packet_count = 0
        self.threat_count = 0

state = AppState()
app = Flask(__name__)

# --- INTERNAL TRAINING ENGINE (Tiny Init) ---
def train_tiny_model():
    """Trains a tiny Random Forest on startup to ensure no crashes."""
    print("--- 🧠 INITIALIZING AI (Tiny Mode) ---")
    
    # Tiny dataset (50 samples) -> <0.1s training time
    # This ensures "Random Forest" structure exists without timeout
    X = []
    y = []
    
    for i in range(50):
        # Fake Normal
        X.append([random.randint(60, 1500), 6, 0, 100])
        y.append(0)
        # Fake Attack
        X.append([random.randint(20, 1000), 17, 0, 50])
        y.append(1)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    clf = RandomForestClassifier(n_estimators=10, max_depth=5, random_state=42)
    clf.fit(X_scaled, y)
    
    print("[✓] AI Model Initialized (Serverless Safe).")
    return clf, scaler

# --- INITIALIZE ON IMPORT ---
try:
    state.model, state.scaler = train_tiny_model()
    state.status = "ACTIVE"
except Exception as e:
    print(f"[!] Init Failed: {e}")
    state.status = "ERROR"

# --- FEATURE ENGINEERING ---
def extract_features(packet):
    try:
        if IP not in packet: return None
        pkt_len = len(packet)
        proto = packet[IP].proto
        is_dns = 1 if packet.haslayer(DNS) else 0
        payload_len = 0
        if packet.haslayer(TCP): payload_len = len(packet[TCP].payload)
        elif packet.haslayer(UDP): payload_len = len(packet[UDP].payload)
        return [pkt_len, proto, is_dns, payload_len]
    except: return None

# --- PROCESSOR ---
def process_data(features, summary_info):
    if state.stop_signal or state.status != "ACTIVE": return
    if state.model is None or state.scaler is None: return

    with state.lock:
        state.packet_count += 1

    X_input = np.array([features])
    X_scaled = state.scaler.transform(X_input)
    probs = state.model.predict_proba(X_scaled)[0]
    risk_score = probs[1] 
    is_anomaly = bool(risk_score > 0.85)

    summary_info["is_risk"] = is_anomaly
    
    with state.lock:
        state.recent_packets.appendleft(summary_info)
        state.traffic_data.append({
            "time": summary_info["time"],
            "score": round(float(risk_score), 2),
            "is_anomaly": is_anomaly
        })

        if is_anomaly:
            state.threat_count += 1
            alert = {
                "id": str(uuid.uuid4())[:8],
                "time": summary_info["time"],
                "score": round(float(risk_score), 2),
                "details": f"Anomaly Detected | Size: {features[0]}B | Proto: {features[1]}"
            }
            if not state.alerts or state.alerts[0]['details'] != alert['details']:
                state.alerts.appendleft(alert)

# --- THREADS ---
def sniffer_thread():
    if not SCAPY_AVAILABLE:
        print("Scapy not available. Sniffer cannot start.")
        state.status = "MISSING_DEPS"
        return

    try:
        print(f"--- 🕵️ SENTINEL ACTIVE ON: {conf.iface} ---")
        sniff(prn=real_packet_callback, store=0)
    except Exception as e:
        print(f"Sniffer failed: {e}")
        state.status = "SNIFFER_ERROR"

def real_packet_callback(packet):
    features = extract_features(packet)
    if not features: return
    
    proto_str = "TCP" if packet[IP].proto == 6 else "UDP" if packet[IP].proto == 17 else "ICMP"
    summary = {
        "time": time.strftime("%H:%M:%S"),
        "src": str(packet[IP].src),
        "dst": str(packet[IP].dst),
        "proto": proto_str,
        "size": len(packet),
    }
    process_data(features, summary)


# --- ROUTES ---
from lib.templates import HTML_DASHBOARD

@app.route('/')
def index():
    return render_template_string(HTML_DASHBOARD)

@app.route('/api/start', methods=['POST'])
def start():
    if not any(t.name == "Worker" for t in threading.enumerate()):
        t = threading.Thread(target=sniffer_thread, daemon=True, name="Worker")
        t.start()
        return jsonify({"msg": "Started", "mode": state.mode})
    return jsonify({"msg": "Already Running", "mode": state.mode})

@app.route('/api/stats')
def stats():
    with state.lock:
        return jsonify({
            "status": state.status,
            "mode": state.mode,
            "count": state.packet_count,
            "threats": state.threat_count,
            "data": list(state.traffic_data),
            "packets": list(state.recent_packets),
            "alerts": list(state.alerts)
        })

# Initialize Model on Import
load_ai_model()
