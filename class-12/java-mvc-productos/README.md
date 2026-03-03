# MVC Productos

Spring Boot MVC application with PostgreSQL for product and brand management.

## Tech stack

- Java 21
- Spring Boot 2.7.9 (Web, Data JPA, Thymeleaf, Validation)
- PostgreSQL
- Maven

## Local setup

### 1. Prerequisites

- Java 21+
- Maven 3.6+
- PostgreSQL running locally

### 2. Create the database

Connect to your PostgreSQL instance and run:

```sql
CREATE DATABASE class_12_products;
```

An initial schema reference is available at `src/main/resources/db.sql`. You can use it to manually seed data if needed.

### 3. Configure environment variables

Copy the example file and adjust the values to match your local PostgreSQL setup:

```bash
cp .env.example .env
```

Edit `.env`:

```env
DB_URL=jdbc:postgresql://localhost:5432/class_12_products
DB_USERNAME=postgres
DB_PASSWORD=your_password
```

> `.env` is git-ignored and never committed.

### 4. Run the application

The application reads environment variables at startup. Export them before running:

```bash
export $(cat .env | xargs) && ./mvnw spring-boot:run
```

Or pass them inline:

```bash
DB_URL=jdbc:postgresql://localhost:5432/class_12_products \
DB_USERNAME=postgres \
DB_PASSWORD=your_password \
./mvnw spring-boot:run
```

The app will be available at `http://localhost:9000`.

## Schema migrations

This project uses **Hibernate DDL auto** (`spring.jpa.hibernate.ddl-auto=update`).

On startup, Hibernate automatically:
- Creates any tables that do not exist yet.
- Adds missing columns to existing tables.

No manual migration step is required. Simply start the application and the schema will be up to date.

> If you are starting from scratch, you can also run `src/main/resources/db.sql` against your database to create the initial `productos` table and load sample data before the first boot.
