import os
import joblib
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(BASE_DIR, "ml", "artifacts")
MODEL_PATH = os.path.join(ARTIFACTS_DIR, "policy_clf.joblib")

def _load_model():
    if not os.path.exists(MODEL_PATH):
        return None
    try:
        model = joblib.load(MODEL_PATH)
        return model
    except Exception:
        return None

def _chunk_text(text: str) -> list:
    raw_paras = re.split(r"\n\s*\n+", text)
    chunks = []
    
    for p in raw_paras:
        p_clean = re.sub(r"\s+", " ", p).strip()
        if not p_clean:
            continue
            
        if len(p_clean) > 500:
            sentences = re.split(r"(?<=[.?!])\s+", p_clean)
            current_chunk = []
            current_length = 0
            
            for s in sentences:
                if current_length + len(s) > 350 and current_chunk:
                    joined = " ".join(current_chunk)
                    if len(joined) >= 80:
                        chunks.append(joined)
                    current_chunk = [s]
                    current_length = len(s)
                else:
                    current_chunk.append(s)
                    current_length += len(s)
            
            if current_chunk:
                joined = " ".join(current_chunk)
                if len(joined) >= 80:
                    chunks.append(joined)
        else:
            if len(p_clean) >= 80:
                chunks.append(p_clean)
            
    final_chunks = []
    for c in chunks:
        lower_c = c.lower()
        if lower_c.startswith("last updated") or "jump to" in lower_c or "table of contents" in lower_c:
            continue
        final_chunks.append(c)
        
    return final_chunks

def run_ml_predictions(extracted_text: str) -> dict:
    empty_res = {"ml_enabled": False, "ml_summary": {}, "ml_predictions": []}
    if not extracted_text:
        return empty_res

    model = _load_model()
    if not model:
        return empty_res

    paragraphs = _chunk_text(extracted_text)

    if not paragraphs:
        return empty_res

    try:
        probs = model.predict_proba(paragraphs)
        classes = model.classes_
    except Exception as e:
        print(f"Prediction failed: {e}")
        return empty_res

    predictions = []
    summary_counts = {}

    for i, p_text in enumerate(paragraphs):
        class_probs = probs[i]
        top_idx = class_probs.argmax()
        top_label = classes[top_idx]
        top_conf = float(class_probs[top_idx])

        if top_label == "other":
            continue

        if top_conf < 0.35:
            continue

        summary_counts[top_label] = summary_counts.get(top_label, 0) + 1

        snip = p_text if len(p_text) <= 160 else p_text[:160].strip() + "..."
        predictions.append({
            "label": top_label,
            "confidence": round(top_conf, 4),
            "text_snippet": snip
        })

    predictions.sort(key=lambda x: x["confidence"], reverse=True)
    predictions = predictions[:5]

    return {
        "ml_enabled": True,
        "ml_summary": summary_counts,
        "ml_predictions": predictions
    }
