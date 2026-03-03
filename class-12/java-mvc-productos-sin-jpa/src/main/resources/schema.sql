-- Drop tables if exist
DROP TABLE IF EXISTS marcas;
DROP TABLE IF EXISTS productos;

-- Create table marcas
CREATE TABLE marcas (
                        id SERIAL PRIMARY KEY,
                        nombre VARCHAR(255) NOT NULL,
                        precio NUMERIC(10, 2) NOT NULL
);

-- Insert some sample data for marcas
INSERT INTO marcas (nombre, precio)
VALUES
    ('Nike', 99.99),
    ('Adidas', 89.99),
    ('Samsung', 499.99),
    ('Apple', 999.99);

-- Create table productos
CREATE TABLE productos (
                           id SERIAL PRIMARY KEY,
                           nombre VARCHAR(255) NOT NULL,
                           descripcion TEXT,
                           precio NUMERIC(10, 2) NOT NULL,
                           stock INTEGER DEFAULT 0
);

-- Insert some sample data
INSERT INTO productos (nombre, descripcion, precio, stock)
VALUES
    ('Laptop Dell XPS 13', 'Portátil de alta gama con procesador i7', 1299.99, 10),
    ('Monitor LG 27"', 'Monitor UltraHD con tecnología IPS', 349.99, 15),
    ('Teclado Mecánico', 'Teclado mecánico con retroiluminación RGB', 89.99, 20),
    ('Mouse Inalámbrico', 'Mouse ergonómico inalámbrico', 29.99, 30);