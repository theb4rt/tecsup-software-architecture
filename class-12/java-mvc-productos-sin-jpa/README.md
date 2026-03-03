# Java MVC Product Management (sin JPA)

Spring Boot MVC CRUD app for managing products and brands using plain JDBC (no JPA/Hibernate).

## Requirements

- Java 21
- Maven 3.8+
- PostgreSQL running locally

## Local Setup

### 1. Clone the repository

```bash
git clone <repo-url>
cd java-mvc-productos-sin-jpa
```

### 2. Configure environment variables

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:

```env
DB_URL=jdbc:postgresql://localhost:5432/tecsupweek3ejm1
DB_USERNAME=postgres
DB_PASSWORD=your_password
```

### 3. Create the database

```bash
psql -U postgres -c "CREATE DATABASE tecsupweek3ejm1;"
```

### 4. Run the application

```bash
# Export env vars and run
export $(cat .env | xargs) && ./mvnw spring-boot:run
```

Or build and run the JAR:

```bash
export $(cat .env | xargs) && ./mvnw clean package
java -jar target/*.jar
```

The app will be available at `http://localhost:3000`.

## Database Migrations

This project uses Spring's built-in SQL initialization (`spring.sql.init.mode=always`).

On every startup, `src/main/resources/schema.sql` is executed automatically. It:

- Drops and recreates the `marcas` and `productos` tables
- Seeds both tables with sample data

> **Note:** Since `schema.sql` drops and recreates tables on each run, all data is reset on restart. This is intentional for development/demo purposes.
