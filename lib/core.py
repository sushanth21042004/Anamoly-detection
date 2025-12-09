import threading
import uuid
import sys
import os
import time
import random
import math
from collections import deque
from flask import Flask, jsonify, render_template_string

# --- NO HEAVY DEPENDENCIES (Pure Python) ---

# --- SCAPY (Optional - Local Only) ---
SCAPY_AVAILABLE = False
try:
    # Only try to import if not on Vercel to save time
    if not os.environ.get('VERCEL'):
        from scapy.all import sniff, IP, TCP, UDP, DNS, conf
        SCAPY_AVAILABLE = True
except Exception:
    pass

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
        
        # Buffer for local sniffer to put packets in
        # On Vercel this won't be used, we'll generate on tick
        self.packet_buffer = deque(maxlen=50) 

state = AppState()
app = Flask(__name__)

# --- PURE PYTHON MACHINE LEARNING (Zero Deps) ---
# ... (Same Pure Python ML classes as before) ...

class SimpleScaler:
    def __init__(self):
        self.mean = []
        self.scale = []

    def fit_transform(self, X):
        if not X: return []
        n_samples = len(X)
        n_features = len(X[0])
        self.mean = [0.0] * n_features
        self.scale = [0.0] * n_features
        for row in X:
            for i in range(n_features):
                self.mean[i] += row[i]
        self.mean = [m / n_samples for m in self.mean]
        for row in X:
            for i in range(n_features):
                self.scale[i] += (row[i] - self.mean[i]) ** 2
        self.scale = [math.sqrt(s / n_samples) if s > 0 else 1.0 for s in self.scale]
        return self.transform(X)

    def transform(self, X):
        X_new = []
        for row in X:
            new_row = []
            for i, val in enumerate(row):
                if self.scale[i] > 0:
                    new_row.append((val - self.mean[i]) / self.scale[i])
                else:
                    new_row.append(0.0)
            X_new.append(new_row)
        return X_new

class SimpleDecisionTree:
    def __init__(self, max_depth=5):
        self.max_depth = max_depth
        self.tree = None

    def fit(self, X, y):
        self.tree = self._build_tree(X, y, depth=0)

    def _gini(self, y):
        if not y: return 0
        m = len(y)
        return 1.0 - sum((y.count(c)/m)**2 for c in set(y))

    def _build_tree(self, X, y, depth):
        num_samples = len(y)
        if num_samples <= 1 or depth >= self.max_depth:
            counts = {c: y.count(c) for c in set(y)}
            total = sum(counts.values())
            return {c: counts[c]/total for c in counts}

        best_gain = -1
        best_split = None
        current_gini = self._gini(y)
        n_features = len(X[0])
        # Try a few random features
        for _ in range(10): 
            feat_idx = random.randint(0, n_features - 1)
            thresh = X[random.randint(0, num_samples-1)][feat_idx]
            left_idx = [i for i in range(num_samples) if X[i][feat_idx] < thresh]
            right_idx = [i for i in range(num_samples) if X[i][feat_idx] >= thresh]
            if not left_idx or not right_idx: continue
            y_left = [y[i] for i in left_idx]
            y_right = [y[i] for i in right_idx]
            gini_left = self._gini(y_left)
            gini_right = self._gini(y_right)
            gain = current_gini - (len(y_left)/num_samples * gini_left + len(y_right)/num_samples * gini_right)
            if gain > best_gain:
                best_gain = gain
                best_split = (feat_idx, thresh, left_idx, right_idx)

        if best_gain > 0:
            feat, thresh, l_idx, r_idx = best_split
            return {
                'feat': feat,
                'thresh': thresh,
                'left': self._build_tree([X[i] for i in l_idx], [y[i] for i in l_idx], depth+1),
                'right': self._build_tree([X[i] for i in r_idx], [y[i] for i in r_idx], depth+1)
            }
        
        counts = {c: y.count(c) for c in set(y)}
        total = sum(counts.values())
        return {c: counts[c]/total for c in counts}

    def predict_proba(self, sample):
        node = self.tree
        while isinstance(node, dict) and 'feat' in node:
            if sample[node['feat']] < node['thresh']:
                node = node['left']
            else:
                node = node['right']
        return node.get(1, 0.0)

class SimpleRandomForest:
    def __init__(self, n_estimators=10):
        self.trees = []
        self.n_estimators = n_estimators

    def fit(self, X, y):
        self.trees = []
        for _ in range(self.n_estimators):
            indices = [random.randint(0, len(X)-1) for _ in range(len(X))]
            X_sample = [X[i] for i in indices]
            y_sample = [y[i] for i in indices]
            tree = SimpleDecisionTree(max_depth=5)
            tree.fit(X_sample, y_sample)
            self.trees.append(tree)

    def predict_proba(self, X):
        results = []
        for sample in X:
            total_prob = 0.0
            for tree in self.trees:
                total_prob += tree.predict_proba(sample)
            results.append([1.0 - (total_prob/len(self.trees)), total_prob/len(self.trees)])
        return results

# --- INITIALIZE MODEL (Pure Python) ---
def init_model():
    # Train tiny model instantly
    X = []
    y = []
    for i in range(50):
        X.append([random.randint(60, 1500), 6, 0, 100])
        y.append(0)
        X.append([random.randint(20, 1000), 17, 0, 50])
        y.append(1)
    
    scaler = SimpleScaler()
    X_scaled = scaler.fit_transform(X)
    clf = SimpleRandomForest(n_estimators=5)
    clf.fit(X_scaled, y)
    return clf, scaler

try:
    state.model, state.scaler = init_model()
    state.status = "ACTIVE"
except Exception:
    state.status = "ERROR"

# --- SERVERLESS TICK LOGIC ---
def process_tick():
    """Called by /api/stats to advance logic 1 step."""
    
    # 1. Get Packet Data
    # Priority: Real Buffer (if local sniffer running) -> Simulated Heartbeat (if Vercel)
    features = None
    summary = None
    
    # Check buffer from local sniffer
    with state.lock:
        if state.packet_buffer:
            features, summary = state.packet_buffer.popleft()
    
    # If empty (Vercel or Idle), generate a heartbeat packet so the graph moves
    # This is "On-Demand" simulation to keep the UI alive without background threads
    if not features:
        # Generate believable heartbeat
        if random.random() < 0.1: # Rare anomaly
            pkt_len = int(random.uniform(200, 1100))
            proto = 17; is_dns = 0
            src = f"192.168.1.{random.randint(100,200)}"
        else:
            pkt_len = int(random.normalvariate(800, 200)) + 54
            proto = 6; is_dns = 0
            src = f"10.0.0.{random.randint(2,50)}"
            
        features = [pkt_len, proto, is_dns, max(0, pkt_len - 54)]
        summary = {
            "time": time.strftime("%H:%M:%S"),
            "src": src,
            "dst": "10.0.0.1",
            "proto": "UDP" if proto == 17 else "TCP",
            "size": int(pkt_len)
        }

    # 2. Process via AI
    if features and summary:
        X_input = [features]
        X_scaled = state.scaler.transform(X_input)
        probs = state.model.predict_proba(X_scaled)[0]
        risk_score = probs[1]
        is_anomaly = bool(risk_score > 0.85)
        
        summary["is_risk"] = is_anomaly
        
        with state.lock:
            state.packet_count += 1
            state.recent_packets.appendleft(summary)
            state.traffic_data.append({
                "time": summary["time"],
                "score": round(float(risk_score), 2),
                "is_anomaly": is_anomaly
            })
            if is_anomaly:
                state.threat_count += 1
                alert = {
                    "id": str(uuid.uuid4())[:8],
                    "time": summary["time"],
                    "score": round(float(risk_score), 2),
                    "details": f"Anomaly Detected | Size: {features[0]}B"
                }
                if not state.alerts or state.alerts[0]['details'] != alert['details']:
                    state.alerts.appendleft(alert)

# --- LOCAL SNIFFER (Optional) ---
def extract_features(packet):
    try:
        if not SCAPY_AVAILABLE: return None
        if IP not in packet: return None
        pkt_len = len(packet)
        proto = packet[IP].proto
        is_dns = 1 if packet.haslayer(DNS) else 0
        payload_len = 0
        if packet.haslayer(TCP): payload_len = len(packet[TCP].payload)
        elif packet.haslayer(UDP): payload_len = len(packet[UDP].payload)
        return [pkt_len, proto, is_dns, payload_len]
    except: return None

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
    with state.lock:
        state.packet_buffer.append((features, summary))

def sniffer_thread():
    if not SCAPY_AVAILABLE: return
    try:
        print(f"--- 🕵️ SENTINEL ACTIVE ON: {conf.iface} ---")
        sniff(prn=real_packet_callback, store=0)
    except Exception as e:
        print(f"Sniffer failed: {e}")

# --- ROUTES ---
from lib.templates import HTML_DASHBOARD

@app.route('/')
def index():
    return render_template_string(HTML_DASHBOARD)

@app.route('/api/start', methods=['POST'])
def start():
    # Only start background thread if we are LOCAL (and Scapy worked)
    # On Vercel, this does nothing, but 'tick' handles the data
    if SCAPY_AVAILABLE and not any(t.name == "Worker" for t in threading.enumerate()):
        t = threading.Thread(target=sniffer_thread, daemon=True, name="Worker")
        t.start()
    
    # For Vercel, we just confirm "Running"
    return jsonify({"msg": "Started", "mode": state.mode})

@app.route('/api/stats')
def stats():
    # SERVERLESS HEARTBEAT: Process one logic tick per request
    process_tick()
    
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
