FROM python:3.10-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir flask google-generativeai unidiff python-dotenv gunicorn

EXPOSE 8080

CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:8081", "main:app"]