#!/usr/bin/env python
"""
Start Celery worker for security analysis platform.
Usage:
    python -m security.workers.start_worker [worker|beat|flower]
"""
import sys
import os

from security.workers.celery_app import celery_app


def start_worker():
    celery_app.worker_main([
        "worker",
        "--loglevel=INFO",
        "--concurrency=4",
        "--queues=analysis,graph,regression,severity,default",
    ])


def start_beat():
    celery_app.worker_main([
        "beat",
        "--loglevel=INFO",
        "--scheduler=celery.beat.PersistentScheduler",
    ])


def start_flower():
    celery_app.worker_main([
        "flower",
        "--port=5555",
        "--broker=redis://localhost:6379/1",
    ])


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else "worker"

    if command == "worker":
        start_worker()
    elif command == "beat":
        start_beat()
    elif command == "flower":
        start_flower()
    else:
        print(f"Unknown command: {command}")
        print("Usage: python -m security.workers.start_worker [worker|beat|flower]")
        sys.exit(1)