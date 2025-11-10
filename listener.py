import socket
import threading
import datetime
import sq3db_conn as db_conn

listeners = {}
listeners_lock = threading.Lock()
listener_counter = 1

def start_listener(lhost, lport):
    global listener_counter
    try:
        listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener_socket.bind((lhost, int(lport)))
        listener_socket.listen(5)

        listener_id = db_conn.add_listener(lport)

        with listeners_lock:
            listeners[listener_id] = {
                "host": lhost,
                "port": lport,
                "socket": listener_socket,
                "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }

        t = threading.Thread(target=listener_thread, args=(listener_socket, lhost, lport), daemon=True)
        t.start()

        print(f"[\033[32m+\033[0m] Listener {listener_id} started on {lhost}:{lport}")
        return listener_id

    except Exception as e:
        print(f"[!] Failed to start listener on {lhost}:{lport} — {e}")
        return None

def listener_thread(sock, lhost, lport):
    while True:
        try:
            client, addr = sock.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]} on {lhost}:{lport}")
            client.close()
        except Exception as e:
            break
