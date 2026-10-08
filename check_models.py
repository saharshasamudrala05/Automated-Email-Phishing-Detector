import requests
import os
from dotenv import load_dotenv

load_dotenv()

key = os.getenv("GROQ_API_KEY", "")
if not key:
    print("ERROR: GROQ_API_KEY not found in .env file")
    exit(1)

r = requests.get(
    "https://api.groq.com/openai/v1/models",
    headers={"Authorization": "Bearer " + key}
)

if r.status_code != 200:
    print("HTTP Error:", r.status_code, r.text)
    exit(1)

models = [m["id"] for m in r.json().get("data", [])]
print("Available models on your Groq key:")
for m in sorted(models):
    print("  ", m)