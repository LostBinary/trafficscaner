import pyshark
import pandas as pd
import os
from datetime import datetime
from sklearn.ensemble import IsolationForest
import numpy as np

CAPTURE_DIR = r"C:\Caps"
MODEL_FILE = os.path.join(CAPTURE_DIR, "ia_modelo.pkl")
REPORT_FILE = os.path.join(CAPTURE_DIR, "analisispcapS_x_ia.csv")

# ----------------------------------------------------
def extract_features(pcap_file):
    cap = pyshark.FileCapture(pcap_file, display_filter="ip")
    sizes, protos, src_ips, dst_ips = [], [], set(), set()

    for pkt in cap:
        try:
            sizes.append(int(pkt.length))
            protos.append(pkt.highest_layer)
            src_ips.add(pkt.ip.src)
            dst_ips.add(pkt.ip.dst)
        except AttributeError:
            continue
    cap.close()

    if not sizes:
        return None

    features = {
        "media_tamaño": np.mean(sizes),
        "maxima_tamaño": np.max(sizes),
        "emisores": len(src_ips),
        "receptores": len(dst_ips),
        "ratio_TCP": protos.count("TCP") / len(protos),
        "ratio_UDP": protos.count("UDP") / len(protos),
        "otros": 1 - ((protos.count("TCP") + protos.count("UDP")) / len(protos))
    }
    return features

# ----------------------------------------------------
def build_dataset():
    all_pcaps = [f for f in os.listdir(CAPTURE_DIR) if f.endswith(".pcapng")]
    data = []
    for p in all_pcaps:
        feats = extract_features(os.path.join(CAPTURE_DIR, p))
        if feats:
            feats["archivo"] = p
            data.append(feats)
    return pd.DataFrame(data)

# ----------------------------------------------------
def detect_anomalies(df):
    X = df[["media_tamaño", "maxima_tamaño", "emisores", "receptores", "ratio_TCP", "ratio_UDP", "otros"]]
    model = IsolationForest(contamination=0.15, random_state=42)
    model.fit(X)
    df["anomalia"] = model.predict(X)  # 1 = normal, -1 = anómalo
    return df

# ----------------------------------------------------
def main():
    if not os.path.exists(CAPTURE_DIR):
        print(f"❌ No se encuentra el directorio {CAPTURE_DIR}")
        return

    df = build_dataset()
    if df.empty:
        print("No hay datos suficientes para analizar aún.")
        return

    result = detect_anomalies(df)

    result["fecha"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result.to_csv(REPORT_FILE, index=False)
    anomalous = result[result["anomalia"] == -1]

    print("\n✅ Análisis completado. Resultados en:", REPORT_FILE)
    if not anomalous.empty:
        print(f"\n⚠️  Se detectaron {len(anomalous)} archivos con patrones anómalos:")
        for f in anomalous["file"]:
            print("   -", f)
    else:
        print("\n🟢 No se detectaron anomalías.")

if __name__ == "__main__":
    main()
