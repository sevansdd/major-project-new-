import pandas as pd
import sys

# Force UTF-8 for stdout on Windows
try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    # For older Python versions
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.detach(), encoding='utf-8')

def safe_print(text):
    """Print text without breaking on Unicode errors."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode('ascii', 'ignore').decode())

df = pd.read_csv("processed_data/scored_processes.csv")

df['risk_score'] = df['cpu_percent'].apply(lambda x: 3 if x > 90 else (2 if x > 50 else 1))
df.to_csv("processed_data/final_scored.csv", index=False)
safe_print("✅ Risk Scoring Complete.")
