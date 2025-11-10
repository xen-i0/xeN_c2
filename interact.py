import json
import os
import random
import time
import threading

CB_FILE = os.path.join(os.path.dirname(__file__), "callbacks.json")
_lock = threading.Lock()

def _load_callbacks():
    if not os.path.exists(CB_FILE):
        return {}
    with open(CB_FILE, "r") as f:
        try: return json.load(f)
        except: return {}

def _save_callbacks(d):
    with open(CB_FILE, "w") as f:
        json.dump(d, f)

def gen_callback_id():
    d = _load_callbacks()
    for _ in range(1000):
        cid = "{:06d}".format(random.randint(0, 999999))
        if cid not in d:
            return cid
    raise RuntimeError("unable to generate unique callback id")

def create_callback(session_uuid):
    with _lock:
        d = _load_callbacks()
        cid = gen_callback_id()
        d[cid] = {"session_uuid": session_uuid, "created_at": time.time()}
        _save_callbacks(d)
        return cid

def remove_callback(callback_id):
    with _lock:
        d = _load_callbacks()
        if callback_id in d:
            del d[callback_id]
            _save_callbacks(d)
            return True
        return False

def list_callbacks():
    d = _load_callbacks()
    out = []
    for k, v in d.items():
        out.append((k, v.get("session_uuid"), v.get("created_at")))
    return out

def interact(callback_id, listener_obj, initial_cmd=None, timeout=5):
    srv = listener_obj.get("server")
    if srv is None:
        raise RuntimeError("listener does not have running server")
    cmds_queue = getattr(srv, "cmds", None)
    if cmds_queue is None:
        raise RuntimeError("listener.server.cmds not found")
    if initial_cmd:
        cmds_queue.append(initial_cmd)

    try:
        print(f"[interact {callback_id}] starting interactive. type 'exit' to quit.")
        while True:
            cmd = input(f"{callback_id} >> ").strip()
            if not cmd: continue
            if cmd.lower() in ("exit", "quit"): break
            cmds_queue.append(cmd)
            print(f"[interact {callback_id}] queued -> {cmd}")
            time.sleep(timeout)
    except KeyboardInterrupt:
        print()
    return True
