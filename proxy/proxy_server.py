import socket
import threading
import requests
import datetime
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty

# ================= Configuration =================
HOST = "127.0.0.1"
PORT = 8080
FASTAPI_URL = "http://127.0.0.1:8000"
BLOCKED_REFRESH_INTERVAL = 10  # seconds
MAX_THREADS = 50

blocked_sites = []
executor = ThreadPoolExecutor(max_workers=MAX_THREADS)
log_queue = Queue()


# ================= Functions =================
def fetch_blocked_sites():
    global blocked_sites
    try:
        response = requests.get(f"{FASTAPI_URL}/blocked-sites", timeout=5)
        if response.status_code == 200:
            blocked_sites = response.json()
            print(f"[INFO] Fetched blocked sites: {blocked_sites}")
    except Exception as e:
        print(f"[WARNING] Failed to fetch blocked sites: {e}")


def enqueue_log(domain, status):
    log_queue.put({
        "domain": domain,
        "status": status,
        "timestamp": datetime.datetime.now().isoformat()
    })


def log_worker():
    """Continuously send queued logs to FastAPI."""
    session = requests.Session()
    session.trust_env = False  # bypass proxy
    LOG_ENDPOINT = f"{FASTAPI_URL}/logs"

    while True:
        try:
            log_entry = log_queue.get(timeout=1)
        except Empty:
            continue

        try:
            response = session.post(LOG_ENDPOINT, json=log_entry, timeout=5)
            if response.status_code != 200:
                print(f"[WARNING] Failed to send log: {response.status_code} {response.text}")
        except requests.RequestException as e:
            print(f"[WARNING] Log send failed: {e}")
            log_queue.put(log_entry)
            time.sleep(2)
        finally:
            log_queue.task_done()


def is_blocked(host):
    return any(site in host for site in blocked_sites)


def forward(source, destination):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    except:
        pass
    finally:
        source.close()
        destination.close()


def handle_client(client_conn, client_addr):
    client_conn.settimeout(30)
    try:
        request = client_conn.recv(4096)
        if not request:
            client_conn.close()
            return

        first_line = request.split(b'\n')[0].decode(errors='ignore')
        parts = first_line.split()
        if len(parts) < 2:
            client_conn.close()
            return

        method, url = parts[0], parts[1]

        # HTTPS CONNECT
        if method.upper() == "CONNECT":
            host_port = url.split(":")
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 443

            if is_blocked(host):
                print(f"[BLOCKED HTTPS] {host}")
                enqueue_log(host, "BLOCKED")
                try:
                    client_conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by proxy")
                except BrokenPipeError:
                    pass
                client_conn.close()
                return

            enqueue_log(host, "ALLOWED")
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(30)
            remote.connect((host, port))
            client_conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")

            executor.submit(forward, client_conn, remote)
            executor.submit(forward, remote, client_conn)

        else:
            # HTTP
            if "://" in url:
                _, url = url.split("://", 1)
            host_port_path = url.split("/", 1)
            host_port = host_port_path[0]
            path = "/" + host_port_path[1] if len(host_port_path) > 1 else "/"

            if ":" in host_port:
                host, port = host_port.split(":")
                port = int(port)
            else:
                host = host_port
                port = 80

            if is_blocked(host):
                print(f"[BLOCKED HTTP] {host}")
                enqueue_log(host, "BLOCKED")
                try:
                    client_conn.sendall(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<h1>Blocked by proxy</h1>"
                    )
                except BrokenPipeError:
                    pass
                client_conn.close()
                return

            enqueue_log(host, "ALLOWED")
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(30)
            remote.connect((host, port))
            new_request = request.replace(url.encode(), path.encode())
            remote.sendall(new_request)

            while True:
                data = remote.recv(4096)
                if not data:
                    break
                client_conn.sendall(data)
            client_conn.close()
            remote.close()

    except socket.timeout:
        client_conn.close()
    except Exception as e:
        print(f"[ERROR] {e}")
        client_conn.close()


def refresh_blocked_sites_periodically():
    while True:
        fetch_blocked_sites()
        time.sleep(BLOCKED_REFRESH_INTERVAL)


def start_proxy():
    fetch_blocked_sites()
    threading.Thread(target=refresh_blocked_sites_periodically, daemon=True).start()
    threading.Thread(target=log_worker, daemon=True).start()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)
    print(f"[*] Dynamic Proxy running on {HOST}:{PORT}")

    try:
        while True:
            client_conn, client_addr = server_socket.accept()
            executor.submit(handle_client, client_conn, client_addr)
    except KeyboardInterrupt:
        print("\n[*] Proxy shutting down...")
        server_socket.close()
        executor.shutdown(wait=True)


if __name__ == "__main__":
    start_proxy()
