import psycopg2
import pandas as pd
import streamlit as st
import os

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "postgres")

def get_app_connection():
    return psycopg2.connect(
        dbname=DB_NAME,
        user="app_user",
        password="app_password",
        host=DB_HOST,
        port=DB_PORT
    )

def get_admin_connection():
    return psycopg2.connect(
        dbname=DB_NAME,
        user="postgres",
        password="postgres",
        host=DB_HOST,
        port=DB_PORT
    )

def load_user_profiles():
    """Pobiera użytkowników, ich role i atrybuty bezpośrednio z bazy danych (zgodnie z ERD)."""
    conn = get_admin_connection()
    query = """
        SELECT u.username, r.role_name, ua.attribute_value as region_attr
        FROM users u
        LEFT JOIN user_roles ur ON u.user_id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.role_id
        LEFT JOIN user_attributes ua ON u.user_id = ua.user_id AND ua.attribute_name = 'Region'
    """
    df = pd.read_sql(query, conn)
    conn.close()
    return df

st.set_page_config(page_title="OLAP RBAC + ABAC Demo", layout="wide")
st.title("System Raportowy OLAP: RBAC + ABAC Security Control")


users_df = load_user_profiles()

st.sidebar.header("1. Wybór Kontekstu Użytkownika")
selected_username = st.sidebar.selectbox("Konto użytkownika (z bazy ERD):", users_df['username'].tolist())

user_row = users_df[users_df['username'] == selected_username].iloc[0]
role = user_row['role_name']
region = user_row['region_attr'] if pd.notnull(user_row['region_attr']) else "NULL"

st.sidebar.header("2. Scenariusz UML & Obiekt SQL")
scenario_mode = st.sidebar.radio(
    "Wybierz testowany przypadek:",
    [
        "Podstawowy filtr ABAC (Tabela)",
        "Dostęp Wieloregionowy (Zastępstwo)",
        "Brak atrybutu (Zasada Default Deny)",
        "Dyrektor Globalny (Zarząd)",
        "Filtr Wieloatrybutowy (Region + Status Kwartału)",
        "Luka w Widoku (Eskalacja Uprawnień)",
        "Widok Zabezpieczony (Security Invoker)",
        "Procedura (SECURITY INVOKER)",
        "Symulacja Ataku & Audyt Security"
    ]
)

quarter_filter = ""
if scenario_mode == "Filtr Wieloatrybutowy (Region + Status Kwartału)":
    quarter_filter = st.sidebar.selectbox("Status Kwartału:", ["CLOSED", "OPEN"])

col1, col2, col3 = st.columns(3)
with col1:
    st.info(f"**Użytkownik:** `{selected_username}`")
with col2:
    st.success(f"**Rola (RBAC):** `{role}`")
with col3:
    st.warning(f"**Atrybuty ABAC (`Region`):** `{region}`")

st.divider()

if st.button("Uruchom Zapytanie z Kontekstem Sesji", type="primary"):
    try:
        conn = get_app_connection()
        cursor = conn.cursor()
        
        cursor.execute(f"SET app.current_user_role = '{role}';")
        cursor.execute(f"SET app.current_user_region = '{region}';")
        cursor.execute(f"SET app.current_quarter_filter = '{quarter_filter}';")
        
        if scenario_mode == "Luka w Widoku (Eskalacja Uprawnień)":
            query = "SELECT region, kwartal, sprzedaz, kwartal_status FROM v_sales_report_vulnerable;"
        elif scenario_mode == "Widok Zabezpieczony (Security Invoker)":
            query = "SELECT region, kwartal, sprzedaz, kwartal_status FROM v_sales_report_secured;"
        elif scenario_mode == "Procedura (SECURITY INVOKER)":
            query = "SELECT region, kwartal, sprzedaz, kwartal_status FROM get_regional_sales();"
        elif scenario_mode == "Symulacja Ataku & Audyt Security":
            # Wykrywanie nieautoryzowanej próby odczytu danych spoza regionu w warstwie logicznej
            requested_region = "Warszawa"
            if role != "Global_Director" and (region == "NULL" or requested_region not in region.split(',')):
                # Zapis próby do logów audytowych
                log_cursor = conn.cursor()
                log_cursor.execute(
                    "INSERT INTO security_logs (username, requested_resource, action_status, details) VALUES (%s, %s, %s, %s)",
                    (selected_username, requested_region, "BLOCKED", "Unauthorized data access attempt detected")
                )
                conn.commit()
                st.error("HTTP 403 Forbidden: Wykryto próbę nieautoryzowanego dostępu! Zdarzenie zostało zapisane w logach bezpieczeństwa.")
            query = "SELECT region, kwartal, sprzedaz, kwartal_status FROM sales_data;"
        else:
            query = "SELECT region, kwartal, sprzedaz, kwartal_status FROM sales_data;"
            
        cursor.execute(query)
        rows = cursor.fetchall()
        colnames = [desc[0] for desc in cursor.description]
        
        df = pd.DataFrame(rows, columns=colnames)
        
        st.subheader(f"Wyniki Zapytania – Scenariusz: {scenario_mode}")
        
        if df.empty:
            st.warning("Baza zwróciła 0 wierszy. (Zasada Default Deny lub brak pasujących danych)")
        else:
            st.dataframe(df, use_container_width=True)
            
        if scenario_mode == "Luka w Widoku (Eskalacja Uprawnień)" and len(df) > 2 and role != "Global_Director":
            st.error("UWAGA! Wyciek danych! Widok wykonał się z prawami właściciela (postgres), ignorując polisy RLS tabeli.")
            
        st.subheader("Wykonana sekwencja SQL w sesji PostgreSQL")
        st.code(f"""
-- Ustawienie zmiennych kontekstu sesji
SET app.current_user_role = '{role}';
SET app.current_user_region = '{region}';
SET app.current_quarter_filter = '{quarter_filter}';

-- Testowana instrukcja:
{query}
        """, language="sql")
        
        conn.close()
    except Exception as e:
        st.error(f"Błąd zapytania: {e}")

st.divider()

with st.expander("Podgląd Tabeli Audytowej (Security Logs)"):
    if st.button("Odśwież Logi Audytowe"):
        conn_admin = get_admin_connection()
        logs_df = pd.read_sql("SELECT * FROM security_logs ORDER BY timestamp DESC;", conn_admin)
        conn_admin.close()
        st.dataframe(logs_df, use_container_width=True)