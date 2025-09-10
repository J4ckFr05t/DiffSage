# DiffSage Docker Setup

This document explains how to run DiffSage using Docker and Docker Compose.

## Prerequisites

- Docker
- Docker Compose
- Your existing `.env` file

## Quick Start

1. **Ensure your `.env` file is present** in the root directory with the following variables:
   ```env
   # Database Configuration
   DATABASE_URL=postgresql://diffsage:diffsage_password@postgres:5432/diffsage
   
   # Redis Configuration
   REDIS_URL=redis://redis:6379/0
   
   # Flask Configuration
   SECRET_KEY=your-secret-key-here
   FLASK_ENV=production
   
   # Email Configuration
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password
   MAIL_DEFAULT_SENDER=your-email@gmail.com
   
   # CloudRun Task Service URLs (for local development)
   CLOUDRUN_ANALYZE_URL=http://task-service:8081/analyze
   CLOUDRUN_STATUS_URL=http://task-service:8081/status
   
   # Port Configuration
   PORT=8080
   ```

2. **Build and start all services:**
   ```bash
   docker-compose up --build
   ```

3. **Access the application:**
   - Main application: http://localhost:8080
   - Task service: http://localhost:8081
   - Redis: localhost:6379
   - PostgreSQL: localhost:5432

## Services

### Main Application (web)
- **Port:** 8080
- **Purpose:** Flask web application with user authentication and PR analysis
- **Dependencies:** Redis, PostgreSQL

### Task Service (task-service)
- **Port:** 8081
- **Purpose:** Background task processing for PR analysis
- **Dependencies:** None (standalone service)

### Redis (redis)
- **Port:** 6379
- **Purpose:** Rate limiting and caching
- **Data:** Persisted in `redis_data` volume

### PostgreSQL (postgres)
- **Port:** 5432
- **Purpose:** User data and application state
- **Credentials:** diffsage / diffsage_password
- **Database:** diffsage
- **Data:** Persisted in `postgres_data` volume

## Development Commands

### Start services in background:
```bash
docker-compose up -d
```

### View logs:
```bash
# All services
docker-compose logs

# Specific service
docker-compose logs web
docker-compose logs task-service
```

### Stop services:
```bash
docker-compose down
```

### Stop and remove volumes (WARNING: This will delete all data):
```bash
docker-compose down -v
```

### Rebuild specific service:
```bash
docker-compose build web
docker-compose up -d web
```

## Database Migrations

The application will automatically create tables on first run. If you need to run migrations manually:

```bash
# Access the web container
docker-compose exec web bash

# Run migrations
flask db upgrade
```

## Troubleshooting

### Port conflicts
If you have port conflicts, modify the ports in `docker-compose.yml`:
```yaml
ports:
  - "8081:8080"  # Map host port 8081 to container port 8080
```

### Environment variables
Ensure your `.env` file contains all required variables. The application will fail to start if critical variables like `REDIS_URL` or `DATABASE_URL` are missing.

### Database connection issues
- Ensure PostgreSQL is running: `docker-compose ps`
- Check database logs: `docker-compose logs postgres`
- Verify connection string in `.env` file

### Redis connection issues
- Ensure Redis is running: `docker-compose ps`
- Check Redis logs: `docker-compose logs redis`
- Verify Redis URL in `.env` file

## Production Considerations

For production deployment:

1. **Security:**
   - Use strong, unique passwords
   - Generate a secure `SECRET_KEY`
   - Use environment-specific database credentials

2. **Performance:**
   - Consider using external Redis and PostgreSQL instances
   - Configure resource limits in docker-compose.yml
   - Use production-ready WSGI server (gunicorn)

3. **Monitoring:**
   - Add health checks to services
   - Configure log aggregation
   - Set up monitoring and alerting

## External Services

If you prefer to use external Redis and PostgreSQL services instead of the containerized ones:

1. **Comment out the redis and postgres services** in `docker-compose.yml`
2. **Update your `.env` file** with external service URLs:
   ```env
   DATABASE_URL=postgresql://user:password@your-postgres-host:5432/database
   REDIS_URL=redis://your-redis-host:6379/0
   ```
3. **Remove the depends_on sections** from the web service
