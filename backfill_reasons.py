import requests
import time

BASE_URL = "http://127.0.0.1:8000/api"

def main():
    print("Fetching scans...")
    try:
        resp = requests.get(f"{BASE_URL}/scans")
        resp.raise_for_status()
        scans = resp.json()
    except Exception as e:
        print(f"Failed to fetch scans: {e}")
        return

    print(f"Found {len(scans)} total scans.")
    
    analyzed_scans = [s for s in scans if s.get("score_total") is not None and s.get("score_total") > 0]
    print(f"Found {len(analyzed_scans)} previously analyzed scans to backfill.")

    for i, scan in enumerate(analyzed_scans):
        scan_id = scan.get("id")
        print(f"[{i+1}/{len(analyzed_scans)}] Backfilling scan_id: {scan_id}")
        
        try:
            analyze_resp = requests.post(
                f"{BASE_URL}/policies/analyze",
                json={"scan_id": scan_id}
            )
            print(f"  -> status_code: {analyze_resp.status_code}")
            
            if analyze_resp.status_code != 200:
                print(f"  -> error data: {analyze_resp.text}")
                
        except Exception as e:
            print(f"  -> request failed: {e}")
            
        time.sleep(0.2)
        
    print("Backfill complete.")

if __name__ == "__main__":
    main()
