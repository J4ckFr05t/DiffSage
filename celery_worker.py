from celery import Celery
import os
from dotenv import load_dotenv

load_dotenv()

env_broker = os.getenv("CELERY_BROKER_URL")
broker_url = env_broker if env_broker else "redis://redis:6379/0"

env_backend = os.getenv("CELERY_RESULT_BACKEND")
result_backend = env_backend if env_backend else "redis://redis:6379/0"

def make_celery(app_name=__name__):
    return Celery(
        app_name,
        broker=broker_url,
        backend=result_backend
    )

celery = make_celery()

# 👇 Import your task to ensure it's registered
import tasks  # This line is critical!