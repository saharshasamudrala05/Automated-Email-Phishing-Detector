"""
run.py — PhishGuard Entry Point

Development : python run.py
Production  : gunicorn run:app --workers 1 --threads 4 --bind 0.0.0.0:$PORT

Single worker is intentional — APScheduler runs in-process.
Multiple workers would cause duplicate polling. For horizontal scale,
extract the poller into a separate Celery worker.
"""
import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(
        host  = "0.0.0.0",
        port  = port,
        debug = False,   # Never True in production
    )
