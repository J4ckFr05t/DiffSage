#!/bin/bash

# DiffSage Docker Management Scripts

case "$1" in
    "start")
        echo "Starting DiffSage services..."
        docker compose up -d
        echo "Services started. Access the app at http://localhost:8080"
        ;;
    "stop")
        echo "Stopping DiffSage services..."
        docker-compose down
        echo "Services stopped."
        ;;
    "restart")
        echo "Restarting DiffSage services..."
        docker compose down
        docker compose up -d
        echo "Services restarted."
        ;;
    "logs")
        echo "Showing logs for all services..."
        docker compose logs -f
        ;;
    "logs-web")
        echo "Showing logs for web service..."
        docker compose logs -f web
        ;;
    "logs-task")
        echo "Showing logs for task service..."
        docker compose logs -f task-service
        ;;
    "build")
        echo "Building DiffSage services..."
        docker compose build
        echo "Build completed."
        ;;
    "rebuild")
        echo "Rebuilding DiffSage services..."
        docker compose down
        docker compose build --no-cache
        docker compose up -d
        echo "Rebuild completed."
        ;;
    "status")
        echo "Checking service status..."
        docker compose ps
        ;;
    "shell-web")
        echo "Opening shell in web container..."
        docker compose exec web bash
        ;;
    "shell-task")
        echo "Opening shell in task service container..."
        docker compose exec task-service bash
        ;;
    "clean")
        echo "Cleaning up containers and volumes..."
        docker compose down -v
        docker system prune -f
        echo "Cleanup completed."
        ;;
    *)
        echo "DiffSage Docker Management Script"
        echo ""
        echo "Usage: $0 {start|stop|restart|logs|logs-web|logs-task|build|rebuild|status|shell-web|shell-task|clean}"
        echo ""
        echo "Commands:"
        echo "  start      - Start all services in background"
        echo "  stop       - Stop all services"
        echo "  restart    - Restart all services"
        echo "  logs       - Show logs for all services"
        echo "  logs-web   - Show logs for web service only"
        echo "  logs-task  - Show logs for task service only"
        echo "  build      - Build all services"
        echo "  rebuild    - Rebuild all services from scratch"
        echo "  status     - Show status of all services"
        echo "  shell-web  - Open shell in web container"
        echo "  shell-task - Open shell in task service container"
        echo "  clean      - Remove all containers and volumes (WARNING: deletes data)"
        ;;
esac
