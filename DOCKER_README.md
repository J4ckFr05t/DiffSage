# Docker Setup for DiffSage

This directory contains the minimal Docker setup to run the DiffSage application.

## Quick Start

1. **Copy environment file:**
   ```bash
   cp env.example .env
   ```

2. **Edit the .env file** with your actual values:
   - Set your Gmail credentials for email functionality
   - Set a strong SECRET_KEY for Flask sessions
   - Adjust other settings as needed

3. **Build and run all services:**
   ```bash
   docker-compose up --build
   ```

4. **Access the application:**
   - Main app: http://localhost:8080
   - Task service: http://localhost:8081
   - PostgreSQL: localhost:5432
   - Redis: localhost:6379

## Services

- **app**: Main Flask application (port 8080)
- **task-service**: Cloud Run task service (port 8081)
- **postgres**: PostgreSQL database (port 5432)
- **redis**: Redis cache (port 6379)

## Environment Variables

The application requires these environment variables in your `.env` file:

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `SECRET_KEY`: Flask secret key
- `MAIL_USERNAME`: Gmail username for email
- `MAIL_PASSWORD`: Gmail app password
- `MAIL_DEFAULT_SENDER`: Email sender address

## Database Migration

After starting the services, run database migrations:

```bash
docker-compose exec app flask db upgrade
```

## Stopping Services

```bash
docker-compose down
```

To also remove volumes (database data):
```bash
docker-compose down -v
```
