import os
import time
import json
import hashlib
from datetime import datetime, timedelta
import streamlit as st
import pandas as pd
import psycopg2
import psycopg2.extras
from cryptography.fernet import Fernet
import plotly.express as px

# ---------- Config ----------
DEFAULT_DB_URL = "postgresql://postgres:Aakhan25@db.voprcjrogydljhcbjcqq.supabase.co:5432/postgres"
DATABASE_URL = os.getenv("DATABASE_URL", DEFAULT_DB_URL)
FERNET_KEY_ENV = "FERNET_KEY"
APP_START = time.time()
DATA_RETENTION_DAYS = 90  # GDPR compliance: keep logs for 90 days
PAGE_ICON = "🏥"

# ---------- Helpers ----------
def do_rerun():
    """Try various Streamlit rerun functions without raising if unavailable."""
    try:
        st.experimental_rerun()
    except Exception:
        try:
            st.rerun()
        except Exception:
            pass

# ---------- DB helpers ----------
def get_conn():
    # Return a connection whose cursors produce dict-like rows
    return psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)

def init_db_from_file(schema_path="schema_postgres.sql"):
    with open(schema_path, "r", encoding="utf-8") as f:
        sql = f.read()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    cur.close()
    conn.close()

# ---------- Utils ----------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def mask_name(name: str) -> str:
    if not name:
        return ""
    short = sha256_hex(name)[:8]
    return f"ANON_{short}"

def mask_contact(contact: str) -> str:
    digits = [c for c in contact if c.isdigit()]
    if len(digits) >= 4:
        suffix = "".join(digits[-4:])
        return "XXX-XXX-" + suffix
    return "XXX-XXX-XXXX"

def get_fernet():
    """Get Fernet cipher if key is configured, None otherwise."""
    key = os.getenv(FERNET_KEY_ENV)
    if key:
        try:
            if isinstance(key, str):
                key_bytes = key.encode()
            else:
                key_bytes = key
            return Fernet(key_bytes)
        except Exception:
            return None
    return None

def safe_to_display(df: pd.DataFrame, hide_binary=True) -> pd.DataFrame:
    """Safely convert DataFrame for display, handling binary and datetime values."""
    if df.empty:
        return df
    
    df2 = df.copy()
    if hide_binary:
        for c in df2.columns:
            # Replace bytea/binary-like values with placeholder to avoid display issues
            if df2[c].dtype == object:
                df2[c] = df2[c].apply(lambda x: "<binary>" if isinstance(x, (bytes, bytearray, memoryview)) else (str(x) if pd.notnull(x) else ""))
    
    # Convert datetimes to isoformat for stable rendering
    for c in df2.select_dtypes(include=["datetime", "datetimetz"]).columns:
        df2[c] = df2[c].apply(lambda x: x.isoformat() if pd.notnull(x) else "")
    
    return df2

def log_action(user_id, role, action, details=""):
    """Log user action to database."""
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO logs (user_id, role, action, details) VALUES (%s,%s,%s,%s)",
            (user_id, role, action, details)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        # Avoid raising in production UI logging to keep UX smooth
        try:
            st.error(f"⚠️ Failed to log action: {str(e)}")
        except Exception:
            pass

# ---------- GDPR: Data Retention ----------
def cleanup_old_logs():
    """Delete logs older than DATA_RETENTION_DAYS."""
    try:
        conn = get_conn()
        cur = conn.cursor()
        cutoff_date = datetime.now() - timedelta(days=DATA_RETENTION_DAYS)
        cur.execute(
            "DELETE FROM logs WHERE timestamp < %s",
            (cutoff_date,)
        )
        deleted = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        return deleted
    except Exception as e:
        st.error(f"⚠️ Failed to cleanup old logs: {str(e)}")
        return 0

def check_gdpr_consent():
    """Check if user has given GDPR consent."""
    if 'gdpr_consent' not in st.session_state:
        st.session_state.gdpr_consent = False
    return st.session_state.gdpr_consent

def save_consent(consent_given):
    """Save user's GDPR consent to database."""
    try:
        conn = get_conn()
        cur = conn.cursor()
        # Create consent table if not exists (safe idempotent)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_consents (
                consent_id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(user_id),
                consent_given BOOLEAN NOT NULL,
                consent_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(50)
            )
        """)
        if st.session_state.get('user'):
            user_id = st.session_state.user.get('user_id')
            cur.execute(
                "INSERT INTO user_consents (user_id, consent_given) VALUES (%s, %s)",
                (user_id, consent_given)
            )
            conn.commit()
        cur.close()
        conn.close()
        st.session_state.gdpr_consent = consent_given
    except Exception as e:
        st.error(f"⚠️ Failed to save consent: {str(e)}")

# ---------- Auth ----------
def verify_login(username, password):
    """Verify user credentials and return user info."""
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT user_id, username, password_hash, role FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()
        if row:
            stored_hash = row['password_hash']
            if sha256_hex(password) == stored_hash:
                return {
                    "user_id": row['user_id'],
                    "username": row['username'],
                    "role": row['role']
                }
    except Exception as e:
        st.error(f"❌ Login error: {e}")
    return None

# ---------- RBAC Helpers ----------
def require_session():
    """Initialize session state for user."""
    if "user" not in st.session_state:
        st.session_state.user = None

def is_admin():
    return st.session_state.user and st.session_state.user.get("role") == "admin"

def is_doctor():
    return st.session_state.user and st.session_state.user.get("role") == "doctor"

def is_receptionist():
    return st.session_state.user and st.session_state.user.get("role") == "receptionist"

# ---------- Patient Operations ----------
def add_patient(name, contact, diagnosis, dob):
    """Add new patient to database."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO patients (name, contact, diagnosis, date_of_birth) VALUES (%s,%s,%s,%s) RETURNING patient_id",
        (name, contact, diagnosis, dob)
    )
    result = cur.fetchone()
    pid = result['patient_id']
    conn.commit()
    cur.close()
    conn.close()
    return pid

def fetch_patients_df(limit=1000):
    """Fetch all patients as DataFrame - FIXED to prevent header duplication."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM patients ORDER BY date_added DESC LIMIT %s", (limit,))
    rows = cur.fetchall()
    
    # Convert RealDictCursor rows to proper DataFrame
    if rows:
        df = pd.DataFrame([dict(row) for row in rows])
    else:
        df = pd.DataFrame()
    
    cur.close()
    conn.close()
    return df

def anonymize_all(use_fernet=False):
    """Anonymize all patient records with optional Fernet encryption."""
    if not is_admin():
        st.error("🚫 Only admin can anonymize.")
        return
    
    f = get_fernet() if use_fernet else None
    
    if use_fernet and not f:
        st.error("❌ Fernet encryption requested but FERNET_KEY not configured!")
        return
    
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM patients")
    rows = cur.fetchall()
    count = 0
    
    for r in rows:
        anon_name = mask_name(r["name"])
        anon_contact = mask_contact(r["contact"])
        enc = None
        
        if f:
            payload = json.dumps({
                "name": r["name"], 
                "contact": r["contact"], 
                "diagnosis": r.get("diagnosis")
            }).encode()
            enc = psycopg2.Binary(f.encrypt(payload))
        
        cur.execute(
            "UPDATE patients SET anonymized_name=%s, anonymized_contact=%s, encrypted_payload=%s, is_anonymized=%s WHERE patient_id=%s",
            (anon_name, anon_contact, enc, True, r["patient_id"])
        )
        count += 1
    
    conn.commit()
    cur.close()
    conn.close()
    
    user_id = st.session_state.user.get("user_id") if st.session_state.get("user") else None
    log_action(user_id, st.session_state.user.get("role") if st.session_state.get("user") else None, 
               "anonymize_all", f"Anonymized {count} rows; reversible={bool(f)}")
    
    st.success(f"✅ Anonymized {count} records. Reversible: {bool(f)}")

def decrypt_patient(pid):
    """Decrypt patient data using Fernet encryption."""
    f = get_fernet()
    if not f:
        raise Exception("FERNET_KEY not configured")
    
    conn = get_conn()
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT encrypted_payload FROM patients WHERE patient_id=%s", (pid,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    
    if not row or not row.get("encrypted_payload"):
        raise Exception("No encrypted payload found for this patient")
    
    enc_payload = row["encrypted_payload"]
    # psycopg2 may return memoryview for bytea; ensure bytes
    if isinstance(enc_payload, memoryview):
        enc_payload = bytes(enc_payload)
    
    return json.loads(f.decrypt(enc_payload))

# ---------- Analytics & Graphs ----------
def get_activity_stats():
    """Get activity statistics for graphs - FIXED type conversion issues."""
    try:
        conn = get_conn()
        cur = conn.cursor()
        
        # Daily activity - Direct query with explicit integer casting
        cur.execute("""
            SELECT DATE(timestamp) AS date, COUNT(*)::INTEGER AS count
            FROM logs
            WHERE timestamp >= CURRENT_DATE - INTERVAL '30 days'
            GROUP BY DATE(timestamp)
            ORDER BY DATE(timestamp)
        """)
        rows_daily = cur.fetchall()
        df_daily = pd.DataFrame([dict(row) for row in rows_daily]) if rows_daily else pd.DataFrame()
        
        # Robust date parsing
        if not df_daily.empty:
            df_daily['date'] = pd.to_datetime(df_daily['date'], errors='coerce')
            df_daily = df_daily.dropna(subset=['date']).sort_values('date')
            df_daily['count'] = pd.to_numeric(df_daily['count'], errors='coerce').fillna(0).astype(int)
            
            # Ensure complete date range (last 30 days)
            end = pd.Timestamp.now().normalize()
            start = end - pd.Timedelta(days=29)
            full_idx = pd.date_range(start=start, end=end, freq='D')
            df_daily = df_daily.set_index('date').reindex(full_idx, fill_value=0).rename_axis('date').reset_index()

        # Actions by role
        cur.execute("""
            SELECT role, COUNT(*)::INTEGER AS count 
            FROM logs 
            WHERE role IS NOT NULL 
            GROUP BY role 
            ORDER BY count DESC
        """)
        rows_role = cur.fetchall()
        df_role = pd.DataFrame([dict(row) for row in rows_role]) if rows_role else pd.DataFrame()
        if not df_role.empty:
            df_role['count'] = pd.to_numeric(df_role['count'], errors='coerce').fillna(0).astype(int)

        # Actions by type
        cur.execute("""
            SELECT action, COUNT(*)::INTEGER AS count 
            FROM logs 
            GROUP BY action 
            ORDER BY count DESC 
            LIMIT 10
        """)
        rows_action = cur.fetchall()
        df_action = pd.DataFrame([dict(row) for row in rows_action]) if rows_action else pd.DataFrame()
        if not df_action.empty:
            df_action['count'] = pd.to_numeric(df_action['count'], errors='coerce').fillna(0).astype(int)

        # Hourly activity (last 7 days)
        cur.execute("""
            SELECT EXTRACT(HOUR FROM timestamp)::INTEGER AS hour, COUNT(*)::INTEGER AS count
            FROM logs
            WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days'
            GROUP BY EXTRACT(HOUR FROM timestamp)
            ORDER BY hour
        """)
        rows_hourly = cur.fetchall()
        df_hourly = pd.DataFrame([dict(row) for row in rows_hourly]) if rows_hourly else pd.DataFrame()
        if not df_hourly.empty:
            df_hourly['hour'] = pd.to_numeric(df_hourly['hour'], errors='coerce').fillna(0).astype(int)
            df_hourly['count'] = pd.to_numeric(df_hourly['count'], errors='coerce').fillna(0).astype(int)

        cur.close()
        conn.close()
        return df_daily, df_role, df_action, df_hourly
        
    except Exception as e:
        st.error(f"❌ Error loading activity stats: {str(e)}")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), pd.DataFrame()

def show_activity_graphs():
    """Display real-time activity graphs."""
    st.markdown("### 📊 Real-Time Activity Analytics")

    df_daily, df_role, df_action, df_hourly = get_activity_stats()

    # Row 1: Daily activity trend
    if not df_daily.empty:
        fig_daily = px.line(
            df_daily,
            x='date',
            y='count',
            title='User Actions Per Day (Last 30 Days)',
            labels={'count': 'Number of Actions', 'date': 'Date'}
        )
        fig_daily.update_xaxes(type='date', tickformat='%Y-%m-%d')
        fig_daily.update_traces(mode='lines+markers')
        fig_daily.update_layout(height=320, margin=dict(t=30, b=20, l=20, r=20))
        st.plotly_chart(fig_daily, use_container_width=True)
    else:
        st.info("ℹ️ No activity data available for the last 30 days")

    # Row 2: Role and Action distribution
    col1, col2 = st.columns(2)
    with col1:
        if not df_role.empty:
            fig_role = px.pie(df_role, values='count', names='role', title='Actions by Role')
            fig_role.update_layout(height=320, margin=dict(t=30, b=20, l=20, r=20))
            st.plotly_chart(fig_role, use_container_width=True)
        else:
            st.info("ℹ️ No role activity data available")
    
    with col2:
        if not df_action.empty:
            fig_action = px.bar(df_action, x='count', y='action', orientation='h', 
                              title='Top 10 Action Types', labels={'count':'Count','action':'Action'})
            fig_action.update_layout(height=320, margin=dict(t=30, b=20, l=20, r=20))
            st.plotly_chart(fig_action, use_container_width=True)
        else:
            st.info("ℹ️ No action data available")

    # Row 3: Hourly pattern
    if not df_hourly.empty:
        hours = pd.DataFrame({'hour': list(range(0,24))})
        df_hourly = hours.merge(df_hourly, on='hour', how='left').fillna(0)
        df_hourly['count'] = df_hourly['count'].astype(int)
        fig_hourly = px.bar(df_hourly, x='hour', y='count', title='Activity Pattern by Hour (Last 7 Days)', 
                           labels={'count':'Number of Actions','hour':'Hour of Day'})
        fig_hourly.update_layout(height=320, margin=dict(t=30, b=20, l=20, r=20))
        st.plotly_chart(fig_hourly, use_container_width=True)
    else:
        st.info("ℹ️ No hourly activity data available")

# ---------- GDPR Consent Banner ----------
def show_gdpr_banner():
    """Display GDPR consent banner."""
    st.markdown(f"""
    <div style='position: fixed; bottom: 0; left: 0; right: 0; background-color: #2c3e50; 
                color: white; padding: 20px; z-index: 999; box-shadow: 0 -2px 10px rgba(0,0,0,0.3);'>
        <div style='max-width: 1200px; margin: 0 auto;'>
            <h4 style='margin: 0 0 10px 0;'>🍪 Privacy & Data Processing Notice</h4>
            <p style='margin: 0 0 15px 0; font-size: 14px;'>
                We process your personal data in compliance with GDPR. By using this system, you consent to:
                <br>• Collection of login activity and user actions
                <br>• Storage of audit logs for security purposes
                <br>• Data retention for {DATA_RETENTION_DAYS} days (automatic deletion after)
                <br>• Processing for legitimate healthcare operations
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br><br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([2,1,1])
    with col2:
        if st.button("✅ Accept", key="accept_consent", type="primary"):
            save_consent(True)
            do_rerun()
    with col3:
        if st.button("❌ Decline", key="decline_consent"):
            save_consent(False)
            st.warning("⚠️ You must accept to use this system")
            st.stop()

# ---------- UI Pages ----------
def login_page():
    """Display login page."""
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("# 🏥 Hospital Privacy System")
        st.markdown("---")
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("👤 Username", placeholder="Enter your username")
            password = st.text_input("🔒 Password", type="password", placeholder="Enter your password")
            _, colb, _ = st.columns([1,2,1])
            with colb:
                submit = st.form_submit_button("Login")
            if submit:
                if username and password:
                    user = verify_login(username.strip(), password.strip())
                    if user:
                        st.session_state.user = user
                        log_action(user["user_id"], user["role"], "login", f"{username} logged in")
                        st.success("✅ Login successful!")
                        time.sleep(0.4)
                        do_rerun()
                    else:
                        log_action(None, None, "failed_login", f"{username}")
                        st.error("❌ Invalid credentials")
                else:
                    st.warning("⚠️ Please enter both username and password")

def logout():
    """Log out current user."""
    if st.session_state.get("user"):
        u = st.session_state.user
        log_action(u["user_id"], u["role"], "logout", f"{u['username']} logged out")
    st.session_state.user = None
    st.session_state.gdpr_consent = False
    do_rerun()

def add_patient_ui():
    """Display add patient form."""
    st.markdown("### ➕ Add New Patient")
    with st.form("add_patient", clear_on_submit=True):
        col1, col2 = st.columns(2)
        with col1:
            name = st.text_input("Full Name", placeholder="John Doe")
            contact = st.text_input("Contact Number", placeholder="+1234567890")
        with col2:
            diagnosis = st.text_input("Diagnosis", placeholder="Initial diagnosis")
            dob = st.date_input("Date of Birth", max_value=datetime.today())
        submitted = st.form_submit_button("💾 Save Patient")
        if submitted:
            if name and contact:
                try:
                    pid = add_patient(name, contact, diagnosis, dob)
                    st.success(f"✅ Patient saved successfully (ID: {pid})")
                    log_action(st.session_state.user["user_id"], st.session_state.user["role"], 
                             "add_patient", f"{name} (ID={pid})")
                except Exception as e:
                    st.error(f"❌ Failed to add patient: {str(e)}")
            else:
                st.warning("⚠️ Please fill in at least Name and Contact fields")

def view_patients_ui():
    """Display patient records with role-based access control."""
    st.markdown("### 📋 Patient Records")
    try:
        df = fetch_patients_df()
        if df.empty:
            st.info("ℹ️ No patient records found")
            return

        # Show different views based on role
        if is_admin():
            st.markdown(f"**Total Patients:** {len(df)}")
            # Prepare display DataFrame
            display_cols = ['patient_id', 'name', 'contact', 'diagnosis', 'date_of_birth', 'date_added', 'is_anonymized']
            df_display = df[[c for c in display_cols if c in df.columns]].copy()
            df_display = safe_to_display(df_display, hide_binary=True)
            st.dataframe(df_display, use_container_width=True, height=420)
        elif is_doctor():
            rows = []
            for r in df.to_dict("records"):
                name = r.get("anonymized_name") or mask_name(r.get("name"))
                contact = r.get("anonymized_contact") or mask_contact(r.get("contact"))
                rows.append({
                    "ID": r["patient_id"],
                    "Name": name,
                    "Contact": contact,
                    "Diagnosis": r.get("diagnosis"),
                    "Date Added": r.get("date_added")
                })
            st.markdown(f"**Total Patients:** {len(rows)}")
            st.dataframe(pd.DataFrame(rows), use_container_width=True, height=420)
            st.info("ℹ️ Viewing anonymized patient data")
        elif is_receptionist():
            limited_df = df[["patient_id", "date_added"]].copy()
            limited_df.columns = ["Patient ID", "Date Added"]
            st.markdown(f"**Total Patients:** {len(limited_df)}")
            st.dataframe(limited_df, use_container_width=True, height=420)
            st.info("ℹ️ Limited view - Contact admin for full access")
    except Exception as e:
        st.error(f"❌ Error loading patient records: {str(e)}")

def show_audit_logs():
    """Display audit logs - FIXED to prevent header duplication."""
    st.markdown("### 📊 Audit Logs")
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT l.log_id, l.timestamp, l.role, l.action, l.details, u.username
            FROM logs l LEFT JOIN users u ON l.user_id=u.user_id
            ORDER BY l.timestamp DESC LIMIT 1000
        """)
        rows = cur.fetchall()
        
        if rows:
            df = pd.DataFrame([dict(row) for row in rows])
        else:
            df = pd.DataFrame()
        
        cur.close()
        conn.close()
        
        df_display = safe_to_display(df)
        st.markdown(f"**Total Log Entries:** {len(df_display)}")
        st.dataframe(df_display, use_container_width=True, height=420)
        
        if st.button("📥 Export Logs to CSV"):
            csv = df.to_csv(index=False)
            st.download_button(
                "Download Audit Logs", 
                csv, 
                file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", 
                mime="text/csv"
            )
            user_id = st.session_state.user.get("user_id") if st.session_state.get("user") else None
            role = st.session_state.user.get("role") if st.session_state.get("user") else None
            log_action(user_id, role, "export_logs", "Exported logs CSV")
    except Exception as e:
        st.error(f"❌ Error loading audit logs: {str(e)}")

def export_patients_csv():
    """Export patients data to CSV."""
    try:
        df = fetch_patients_df()
        # Remove binary columns for CSV export
        export_cols = [col for col in df.columns if col not in ['encrypted_payload']]
        df_export = df[export_cols].copy()
        csv = df_export.to_csv(index=False)
        st.download_button(
            "📥 Download Patients Backup",
            csv,
            file_name=f"patients_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
        user_id = st.session_state.user.get("user_id") if st.session_state.get("user") else None
        role = st.session_state.user.get("role") if st.session_state.get("user") else None
        log_action(user_id, role, "export_patients", "Exported patients CSV")
    except Exception as e:
        st.error(f"❌ Error exporting patients: {str(e)}")

# ---------- Main ----------
def main():
    """Main application entry point."""
    st.set_page_config(
        page_title="Hospital Privacy Dashboard", 
        layout="wide", 
        page_icon=PAGE_ICON, 
        initial_sidebar_state="expanded"
    )
    require_session()

    if not st.session_state.user:
        login_page()
        return

    # GDPR Consent Check
    if not check_gdpr_consent():
        show_gdpr_banner()
        return

    user = st.session_state.user
    
    # Sidebar
    with st.sidebar:
        st.markdown("# 🏥 Hospital Privacy")
        st.markdown("---")
        st.markdown(f"**👤 User:** {user['username']}")
        st.markdown(f"**🎭 Role:** {user['role'].title()}")
        st.markdown("---")
        page = st.radio("Select Page", ["🏠 Dashboard", "👥 Patients", "🔐 Admin Panel", "👤 Profile"], index=0)
        st.markdown("---")
        uptime = int(time.time() - APP_START)
        st.markdown(f"**⏱️ Uptime:** {uptime}s")
        st.markdown(f"**🔒 GDPR Compliant**")
        st.markdown(f"**📅 Retention:** {DATA_RETENTION_DAYS} days")
        if st.button("🚪 Logout"):
            logout()

    st.title("Hospital Privacy Dashboard")

    # Dashboard Page
    if page == "🏠 Dashboard":
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("""
            <div style='padding: 20px; background-color: #e3f2fd; border-radius: 10px;'>
                <h3 style='color: #1976d2;'>🔒 RBAC</h3>
                <p>Role-Based Access Control ensures data security</p>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            st.markdown("""
            <div style='padding: 20px; background-color: #f3e5f5; border-radius: 10px;'>
                <h3 style='color: #7b1fa2;'>🕵️ Anonymization</h3>
                <p>Patient data protection with reversible encryption</p>
            </div>
            """, unsafe_allow_html=True)
        with col3:
            st.markdown("""
            <div style='padding: 20px; background-color: #e8f5e9; border-radius: 10px;'>
                <h3 style='color: #388e3c;'>📊 Audit Logs</h3>
                <p>Complete activity tracking and monitoring</p>
            </div>
            """, unsafe_allow_html=True)
        st.markdown("---")
        if is_admin():
            show_activity_graphs()
            st.markdown("---")
        if st.button("📥 Export Patients Backup (CSV)"):
            export_patients_csv()

    # Patients Page
    elif page == "👥 Patients":
        if is_admin() or is_receptionist():
            add_patient_ui()
            st.markdown("---")
        view_patients_ui()
        
        # Decryption section for admin only - FIXED messaging
        if is_admin():
            st.markdown("---")
            st.markdown("### 🔓 Reversible De-anonymization")
            
            f = get_fernet()
            
            if f:
                st.success("✅ **Fernet encryption is enabled** - Reversible decryption available")
                st.info("You can decrypt patient records that were anonymized with encryption enabled.")
                
                col1, col2 = st.columns([2,1])
                with col1:
                    pid = st.number_input("Patient ID to decrypt", min_value=1, step=1, value=1)
                with col2:
                    st.markdown("<br>", unsafe_allow_html=True)
                    if st.button("🔓 Decrypt Patient Data"):
                        try:
                            data = decrypt_patient(pid)
                            st.success("✅ Decryption successful!")
                            st.json(data)
                            log_action(user["user_id"], user["role"], "decrypt_patient", 
                                     f"Decrypted patient {pid}")
                        except Exception as e:
                            st.error(f"❌ Decrypt failed: {str(e)}")
            else:
                st.info("""
                ℹ️ **Basic Anonymization Active**
                
                The system is currently using **basic anonymization (masking)** which is working normally:
                - Patient names → `ANON_xxxxx` format
                - Contact numbers → `XXX-XXX-1234` format
                
                **Optional: Enable Reversible Encryption**
                
                To enable reversible decryption (Fernet encryption), follow these steps:
                
                1. **Generate a Fernet key** (run in terminal):
                   ```
                   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
                   ```
                
                2. **Set the environment variable**:
                   - Linux/Mac: `export FERNET_KEY=your_generated_key`
                   - Windows CMD: `set FERNET_KEY=your_generated_key`
                   - Windows PowerShell: `$env:FERNET_KEY="your_generated_key"`
                
                3. **Restart the application**
                
                **Note:** Basic anonymization works perfectly without FERNET_KEY. Encryption is only needed if you want to reverse the anonymization later.
                """)

    # Admin Panel Page
    elif page == "🔐 Admin Panel":
        if not is_admin():
            st.error("🚫 Access Denied - Admin privileges required")
        else:
            show_audit_logs()
            st.markdown("---")
            
            # GDPR Data Retention Section
            st.markdown("### ⏰ GDPR Data Retention")
            col1, col2 = st.columns([3,1])
            with col1:
                st.info(f"📅 Current retention policy: Logs older than {DATA_RETENTION_DAYS} days are automatically deleted")
            with col2:
                if st.button("🗑️ Cleanup Old Logs", type="secondary"):
                    with st.spinner("Cleaning up old logs..."):
                        deleted = cleanup_old_logs()
                        st.success(f"✅ Deleted {deleted} old log entries")
                        log_action(user["user_id"], user["role"], "cleanup_logs", 
                                 f"Deleted {deleted} logs older than {DATA_RETENTION_DAYS} days")
            
            st.markdown("---")
            
            # Anonymization Controls Section
            st.markdown("### 🕵️ Anonymization Controls")
            
            fernet_available = get_fernet() is not None
            
            if fernet_available:
                st.success("✅ Fernet encryption is configured and available")
            else:
                st.warning("⚠️ Fernet encryption not configured - Will use basic masking only")
            
            col1, col2 = st.columns([3,1])
            with col1:
                use_fernet = st.checkbox(
                    "Use reversible Fernet encryption", 
                    value=fernet_available,
                    disabled=not fernet_available,
                    help="When enabled, anonymized data can be decrypted back to original values. Requires FERNET_KEY environment variable."
                )
                
                if use_fernet and not fernet_available:
                    st.error("❌ Cannot use Fernet encryption - FERNET_KEY not configured!")
                
            with col2:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("🔒 Anonymize All Records", type="primary"):
                    with st.spinner("Anonymizing records..."):
                        anonymize_all(use_fernet)

    # Profile Page
    elif page == "👤 Profile":
        st.markdown("### 👤 User Profile")
        col1, col2 = st.columns([1,2])
        with col1:
            st.markdown(f"""
            <div style='padding: 20px; background-color: #f0f2f6; border-radius: 10px;'>
                <h4>Account Details</h4>
                <p><strong>User ID:</strong> {user['user_id']}</p>
                <p><strong>Username:</strong> {user['username']}</p>
                <p><strong>Role:</strong> {user['role'].title()}</p>
                <p><strong>GDPR Consent:</strong> ✅ Given</p>
            </div>
            """, unsafe_allow_html=True)
        with col2:
            if st.button("📜 Show Recent Activity"):
                try:
                    conn = get_conn()
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT * FROM logs WHERE user_id=%s ORDER BY timestamp DESC LIMIT 50",
                        (user["user_id"],)
                    )
                    rows = cur.fetchall()
                    
                    if rows:
                        df = pd.DataFrame([dict(row) for row in rows])
                    else:
                        df = pd.DataFrame()
                    
                    cur.close()
                    conn.close()
                    
                    df = safe_to_display(df)
                    st.dataframe(df, use_container_width=True, height=300)
                except Exception as e:
                    st.error(f"❌ Error loading activity: {str(e)}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        try:
            st.error(f"❌ Application error: {str(e)}")
        except Exception:
            pass
        try:
            log_action(None, None, "app_error", str(e))
        except:
            pass