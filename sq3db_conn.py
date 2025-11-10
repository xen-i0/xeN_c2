import sqlite3
import uuid
import datetime

DB_NAME = 'server_config.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        uuid TEXT PRIMARY KEY,
        name TEXT,
        initial_conn TEXT,
        mtls INTEGER,
        check_in TEXT
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS listeners (
        listener_id TEXT PRIMARY KEY,
        lhost TEXT,
        lport INTEGER,
        created_at TEXT
    )
    ''')

    conn.commit()
    cursor.close()
    conn.close()


def get_port(default_port=8080):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM config WHERE key = "port"')
    row = cursor.fetchone()
    if row:
        port = int(row[0])
    else:
        port = default_port
        cursor.execute('INSERT INTO config (key, value) VALUES ("port", ?)', (str(port),))
        conn.commit()
    cursor.close()
    conn.close()
    return port


def add_session(name, mtls=0):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    session_uuid = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute('''
        INSERT INTO sessions (uuid, name, initial_conn, mtls, check_in)
        VALUES (?, ?, ?, ?, ?)
    ''', (session_uuid, name, now, mtls, now))
    conn.commit()
    cursor.close()
    conn.close()
    return session_uuid


def update_check_in(session_uuid):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute('UPDATE sessions SET check_in = ? WHERE uuid = ?', (now, session_uuid))
    conn.commit()
    cursor.close()
    conn.close()


def add_listener(lhost, lport):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS listeners (
        listener_id TEXT PRIMARY KEY,
        lhost TEXT,
        lport INTEGER UNIQUE,
        created_at TEXT
    )
    ''')

    cursor.execute('SELECT listener_id FROM listeners WHERE lport = ?', (lport,))
    row = cursor.fetchone()
    if row:
        listener_id = row[0]
        conn.close()
        return listener_id

    listener_id = str(uuid.uuid4())
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

    cursor.execute('''
        INSERT INTO listeners (listener_id, lhost, lport, created_at)
        VALUES (?, ?, ?, ?)
    ''', (listener_id, lhost, lport, created_at))

    conn.commit()
    cursor.close()
    conn.close()
    return listener_id

def get_listeners():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT lport FROM listeners")
    rows = cursor.fetchall()
    conn.close()
    return [{"portx": r[0]} for r in rows]

def remove_listener(port):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM listeners WHERE lport = ?", (port,))
    conn.commit()
    conn.close()

