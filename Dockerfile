FROM python:3.10-slim

WORKDIR /app
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port Flask will run on
EXPOSE 8080

# Default port env for Flask
ENV PORT=8080

CMD ["python", "app.py"]