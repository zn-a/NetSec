from sys import argv
import socket
import ssl
import os
import threading
from OpenSSL import crypto
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

ROOT_CA_CERT_PATH = "/certificate/rootCA.crt"
ROOT_CA_KEY_PATH = "/certificate/rootCA.key"
CERT_DIR = "/tmp/mitm_certs"
CERT_CACHE = {}

def generate_certificate(hostname):
    # forge a valid TLS certificate signed by local root CA

    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR, exist_ok=True)

    key_path = os.path.join(CERT_DIR, f"{hostname}.key.pem")
    cert_path = os.path.join(CERT_DIR, f"{hostname}.crt.pem")

    # generate private key
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)

    # create certificate
    cert = crypto.X509()
    cert.get_subject().CN = hostname
    cert.get_subject().C = "NL"
    cert.set_serial_number(int(os.urandom(16).hex(), 16))
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)

    # load root CA and sign the forged certificate with it
    with open(ROOT_CA_CERT_PATH, "rt") as f:
        root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
    with open(ROOT_CA_KEY_PATH, "rt") as f:
        root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

    cert.set_issuer(root_cert.get_subject())
    cert.set_pubkey(pkey)
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False,
                             f"DNS:{hostname}".encode("ascii"))
    ])
    cert.sign(root_key, "sha256")

    if hostname != "proxy.default.local":
        print("Certificate request self-signature ok")
        print(f"subject=C = {cert.get_subject().C}, CN = {cert.get_subject().CN}")

    # save the private key and certificate to files
    with open(key_path, "wt") as f:
        f.write(crypto.dump_privatekey(
            crypto.FILETYPE_PEM, pkey).decode("utf-8"))
    with open(cert_path, "wt") as f:
        f.write(crypto.dump_certificate(
            crypto.FILETYPE_PEM, cert).decode("utf-8"))

    return cert_path, key_path

def get_or_generate_cert(hostname):
    if hostname not in CERT_CACHE:
        CERT_CACHE[hostname] = generate_certificate(hostname)
    return CERT_CACHE[hostname]

def sni_callback(ssl_sock, server_name, ctx):
    if not server_name:
        return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
    try:
        cert_file, key_file = get_or_generate_cert(server_name)
        new_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        new_ctx.load_cert_chain(cert_file, key_file)
        ssl_sock.context = new_ctx
        ssl_sock.requested_server_name = server_name
    except Exception:
        return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR

def handle_client(client_ssl, client_addr, hostname):
    # intercepts encrypted communication between client and server

    try:
        remote = socket.create_connection((hostname, 443))
        context = ssl.create_default_context()
        server_ssl = context.wrap_socket(remote, server_hostname=hostname)

        # read HTTP request from client over TLS
        request = b""
        try:
            while b"\r\n\r\n" not in request:
                chunk = client_ssl.recv(4096)
                if not chunk:
                    break
                request += chunk
        except socket.timeout:
            pass

        if not request:
            return

        print(request.decode(errors='ignore').rstrip())
        print()

        server_ssl.sendall(request)

        # read response from server and send back to client
        response = b""
        try:
            while b"\r\n\r\n" not in response:
                chunk = server_ssl.recv(4096)
                if not chunk:
                    break
                response += chunk

            headers = response.split(b"\r\n\r\n", 1)[0].decode(errors='ignore')
            length = -1
            chunked = False

            for line in headers.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    length = int(line.split(":", 1)[1].strip())
                    break
                if "chunked" in line.lower():
                    chunked = True
                    break

            body = response.split(b"\r\n\r\n", 1)[1]

            if length != -1:
                while len(body) < length:
                    chunk = server_ssl.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    body += chunk
            elif chunked:
                while not response.endswith(b"\r\n0\r\n\r\n"):
                    chunk = server_ssl.recv(4096)
                    if not chunk:
                        break
                    response += chunk
        except socket.timeout:
            pass

        print(response.decode(errors='ignore').rstrip())
        client_ssl.sendall(response)
    finally:
        client_ssl.close()
        if 'server_ssl' in locals():
            server_ssl.close()

def main():
    if len(argv) != 2:
        print(f"Correct usage: python3 tls_intercept.py 8443")
        return

    port = int(argv[1])
    cert_file, key_file = get_or_generate_cert("proxy.default.local")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    context.sni_callback = sni_callback

    sock = socket.socket()
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(5)

    try:
        while True:
            client_sock, addr = sock.accept()
            try:
                ssl_client = context.wrap_socket(
                    client_sock, server_side=True, do_handshake_on_connect=False)
                ssl_client.do_handshake()
                hostname = getattr(ssl_client, 'requested_server_name', None)
                if hostname:
                    threading.Thread(target=handle_client, args=(
                        ssl_client, addr, hostname), daemon=True).start()
                else:
                    ssl_client.close()
            except Exception:
                client_sock.close()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
