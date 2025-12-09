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
# Look for bundled model first, fall back to tmp only if needed
BUNDLED_MODEL = os.path.join(os.path.dirname(__file__), "model.pkl")
MODEL_FILE = "/tmp/netguard_model.pkl" 
MAX_HISTORY = 100

# --- GLOBAL STATE ---
class AppState:
    def __init__(self):
        self.status = "IDLE" 
        self.mode = "REAL" # or "DEMO"
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

# --- DUMMY MODEL (FALLBACK) ---
class DummyModel:
    def predict_proba(self, X):
        return [[0.1, 0.9]] if random.random() < 0.1 else [[0.9, 0.1]]

class DummyScaler:
    def transform(self, X):
        return X

# --- LOAD MODEL ---
def load_ai_model():
    # 1. Try Bundled Model
    if os.path.exists(BUNDLED_MODEL):
        try:
            with open(BUNDLED_MODEL, "rb") as f:
                data = pickle.load(f)
                state.model = data["model"]
                state.scaler = data["scaler"]
                state.status = "ACTIVE"
                print("[✓] Bundled AI Model Loaded.")
                return
        except Exception as e:
            print(f"[!] Bundled model error: {e}")

    # 2. Try /tmp Model (Previous runs)
    if os.path.exists(MODEL_FILE):
        try:
            with open(MODEL_FILE, "rb") as f:
                data = pickle.load(f)
                state.model = data["model"]
                state.scaler = data["scaler"]
                state.status = "ACTIVE"
                print("[✓] Cached AI Model Loaded.")
                return
        except: pass
    
    # 3. Last Resort: Dummy Model (Prevent Crash on Read-Only/Timeout)
    print("[!] Using Dummy Model (Fallback)")
    state.model = DummyModel()
    state.scaler = DummyScaler()
    state.status = "ACTIVE"

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
        print("Scapy not found. Switching to DEMO mode.")
        simulation_thread()
        return

    try:
        print(f"--- 🕵️ SENTINEL ACTIVE ON: {conf.iface} ---")
        sniff(prn=real_packet_callback, store=0)
    except Exception as e:
        print(f"Sniffer failed ({e}). Switching to DEMO mode.")
        simulation_thread()

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

def simulation_thread():
    state.mode = "DEMO"
    print("--- 🎮 DEMO MODE ACTIVE ---")
    while not state.stop_signal:
        time.sleep(random.uniform(0.1, 0.5))
        
        # Generate Fake Features
        is_attack = random.random() < 0.1
        if is_attack:
             pkt_len = int(random.uniform(200, 1100))
             proto = 17; is_dns = 0
        else:
             pkt_len = int(random.normalvariate(800, 200)) + 54
             proto = 6; is_dns = 0
        
        features = [pkt_len, proto, is_dns, max(0, pkt_len - 54)]
        
        summary = {
            "time": time.strftime("%H:%M:%S"),
            "src": f"192.168.1.{random.randint(2, 254)}",
            "dst": f"10.0.0.{random.randint(2, 254)}",
            "proto": "UDP" if proto == 17 else "TCP",
            "size": int(pkt_len)
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
