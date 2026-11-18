
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(200) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS roles (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(100) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    permission_id SERIAL PRIMARY KEY,
    action_name VARCHAR(150) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id INT REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id INT REFERENCES permissions(permission_id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
    role_id INT REFERENCES roles(role_id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS user_attributes (
    attribute_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
    attribute_name VARCHAR(100) NOT NULL,
    attribute_value VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS olap_dimensions (
    dimension_id SERIAL PRIMARY KEY,
    dimension_name VARCHAR(100) NOT NULL,
    table_reference VARCHAR(200) NOT NULL
);

CREATE TABLE IF NOT EXISTS access_policies (
    policy_id SERIAL PRIMARY KEY,
    role_id INT REFERENCES roles(role_id) ON DELETE CASCADE,
    dimension_id INT REFERENCES olap_dimensions(dimension_id) ON DELETE CASCADE,
    required_attribute VARCHAR(100) NOT NULL
);

CREATE TABLE IF NOT EXISTS security_logs (
    log_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    username VARCHAR(100),
    requested_resource VARCHAR(100),
    action_status VARCHAR(50),
    details TEXT
);

CREATE TABLE IF NOT EXISTS sales_data (
    id SERIAL PRIMARY KEY,
    region VARCHAR(50),
    sprzedaz NUMERIC,
    kwartal VARCHAR(10),
    kwartal_status VARCHAR(20) DEFAULT 'CLOSED'
);


INSERT INTO sales_data (region, sprzedaz, kwartal, kwartal_status) VALUES
('Rzeszów', 150000, 'Q3', 'CLOSED'),
('Rzeszów', 180000, 'Q4', 'OPEN'),
('Lublin', 210000, 'Q3', 'CLOSED'),
('Lublin', 190000, 'Q4', 'OPEN'),
('Warszawa', 450000, 'Q4', 'CLOSED'),
('Kraków', 320000, 'Q4', 'CLOSED');

INSERT INTO roles (role_name) VALUES ('Global_Director'), ('Regional_Director');
INSERT INTO permissions (action_name) VALUES ('READ_OLAP_CUBE'), ('DRILL_DOWN_GEOGRAPHY');
INSERT INTO role_permissions (role_id, permission_id) VALUES (1, 1), (1, 2), (2, 1), (2, 2);

INSERT INTO users (username, email) VALUES
('Jan (Dyrektor Rzeszów)', 'jan@firma.pl'),
('Adam (Zastępstwo: Rzeszów+Lublin)', 'adam@firma.pl'),
('Piotr (Brak Regionu - Błąd)', 'piotr@firma.pl'),
('Elżbieta (Zarząd / Globalny)', 'elzbieta@firma.pl');

INSERT INTO user_roles (user_id, role_id) VALUES 
(1, 2), 
(2, 2), 
(3, 2), 
(4, 1); 

INSERT INTO user_attributes (user_id, attribute_name, attribute_value) VALUES
(1, 'Region', 'Rzeszów'),
(2, 'Region', 'Rzeszów,Lublin'),
(3, 'Region', NULL),
(4, 'Region', 'ALL');


DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_user') THEN
        CREATE ROLE app_user WITH LOGIN PASSWORD 'app_password';
    END IF;
END
$$;

GRANT SELECT ON ALL TABLES IN SCHEMA public TO app_user;
GRANT INSERT ON security_logs TO app_user;

ALTER TABLE sales_data ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS rls_sales_policy ON sales_data;
CREATE POLICY rls_sales_policy ON sales_data
    FOR SELECT
    TO app_user
    USING (
        -- Dyrektor Globalny
        current_setting('app.current_user_role', true) = 'Global_Director'
        OR (
            -- Zasada Default Deny 
            current_setting('app.current_user_region', true) IS NOT NULL 
            AND current_setting('app.current_user_region', true) <> ''
            AND current_setting('app.current_user_region', true) <> 'NULL'
            -- Sprawdzanie dopasowania regionu 
            AND string_to_array(current_setting('app.current_user_region', true), ',') @> ARRAY[region::text]
            -- Opcjonalne filtrowanie po dodatkowym atrybucie
            AND (
                current_setting('app.current_quarter_filter', true) IS NULL
                OR current_setting('app.current_quarter_filter', true) = ''
                OR kwartal_status = current_setting('app.current_quarter_filter', true)
            )
        )
    );

-- Widok Podatny 
CREATE OR REPLACE VIEW v_sales_report_vulnerable AS
SELECT region, kwartal, sprzedaz, kwartal_status FROM sales_data;

-- Widok Zabezpieczony 
CREATE OR REPLACE VIEW v_sales_report_secured 
WITH (security_invoker = true) AS 
SELECT region, kwartal, sprzedaz, kwartal_status FROM sales_data;

-- Procedura Zabezpieczona
CREATE OR REPLACE FUNCTION get_regional_sales()
RETURNS TABLE(region VARCHAR, kwartal VARCHAR, sprzedaz NUMERIC, kwartal_status VARCHAR) 
LANGUAGE plpgsql
SECURITY INVOKER
AS $$
BEGIN
    RETURN QUERY SELECT s.region, s.kwartal, s.sprzedaz, s.kwartal_status FROM sales_data s;
END;
$$;

GRANT SELECT ON v_sales_report_vulnerable TO app_user;
GRANT SELECT ON v_sales_report_secured TO app_user;
GRANT EXECUTE ON FUNCTION get_regional_sales() TO app_user;