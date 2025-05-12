FROM python:3.10-slim

WORKDIR /app
COPY . /app

# Install Python dependencies (including Gunicorn)
RUN pip install --no-cache-dir -r requirements.txt gunicorn

# Expose the port Flask will run on
EXPOSE 8080

# Environment variable for Flask (optional)
ENV PORT=8080

# Run the app with Gunicorn
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8080", "app:app"]