# Productos API

A RESTful API built with Spring Boot following Domain-Driven Design (DDD) principles, providing CRUD operations for products and clients.

## Requirements

- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

## Deploy with Docker

```bash
docker compose up -d --build
```

| Service  | Host port | Container port | URL                    |
|----------|-----------|----------------|------------------------|
| API      | 8080      | 8000           | http://localhost:8080  |
| Postgres | 5433      | 5432           | —                      |
| PgAdmin  | 5050      | 80             | http://localhost:5050  |

**PgAdmin credentials:** `admin@example.com` / `admin`

## Database Migrations

Migrations run automatically via Flyway on application startup — no manual step required.

Migration files are located at:

```
src/main/resources/db/migration/
```

## API Testing (Insomnia)

An Insomnia collection is included at the project root:

```
insomnia-collection.json
```

To import it:

1. Open Insomnia.
2. Go to **File → Import**.
3. Select `insomnia-collection.json`.

## API Endpoints

### Productos — `/api/productos`

| Method | Path                  | Description        |
|--------|-----------------------|--------------------|
| GET    | `/api/productos`      | List all products  |
| GET    | `/api/productos/{id}` | Get product by ID  |
| POST   | `/api/productos`      | Create product     |
| PUT    | `/api/productos/{id}` | Update product     |
| DELETE | `/api/productos/{id}` | Delete product     |

### Clientes — `/api/clientes`

| Method | Path                  | Description       |
|--------|-----------------------|-------------------|
| GET    | `/api/clientes`       | List all clients  |
| GET    | `/api/clientes/{id}`  | Get client by ID  |
| POST   | `/api/clientes`       | Create client     |
| PUT    | `/api/clientes/{id}`  | Update client     |
| DELETE | `/api/clientes/{id}`  | Delete client     |
