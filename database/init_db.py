"""Database initialization for CyberSIEM."""
import logging
from database.db_manager import get_db

logger = logging.getLogger(__name__)


def init_database():
    """Create all required tables in the database."""
    try:
        with get_db() as conn:
            cursor = conn.cursor()

            # Create scan_sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    end_time TIMESTAMP,
                    status TEXT DEFAULT 'ACTIVE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Create threat_events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    module TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
                )
            """)

            # Create scan_metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    ransomware_count INTEGER DEFAULT 0,
                    portscan_count INTEGER DEFAULT 0,
                    honeypot_hits INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
                )
            """)

            # Create indexes for faster queries
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_events_session ON threat_events(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_events_timestamp ON threat_events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_metrics_session ON scan_metrics(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_metrics_timestamp ON scan_metrics(timestamp)")

            logger.info("✅ Database tables initialized successfully")

    except Exception as e:
        logger.error(f"❌ Error initializing database: {e}")
        raise
