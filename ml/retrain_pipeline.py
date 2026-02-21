# Model Retraining Pipeline (Placeholder)
# Extend this script to automate model retraining with new data.

def retrain_model():
    import pandas as pd
    import joblib
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest

    # Load latest enriched features
    try:
        df = pd.read_csv("../feature_engineering/outputs/flow_features_enriched.csv")
    except Exception as e:
        print(f"[ERROR] Could not load features: {e}")
        return

    FEATURES = [
        "packet_count", "duration", "total_bytes", "avg_packet_size", "min_iat", "max_iat", "mean_iat", "std_iat",
        "bytes_per_second", "packets_per_second", "avg_bytes_per_packet", "dns_query_length", "dns_subdomain_depth", "dns_entropy"
    ]
    X = df[FEATURES]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso_forest = IsolationForest(n_estimators=200, contamination=0.05, random_state=42, n_jobs=-1)
    iso_forest.fit(X_scaled)

    joblib.dump(iso_forest, "../ml/models/isolation_forest.pkl")
    joblib.dump(scaler, "../ml/models/scaler.pkl")
    print("[+] Model and scaler retrained and saved.")

if __name__ == "__main__":
    retrain_model()
    print("Retraining completed.")
