#!/usr/bin/env python3

from sys import argv
import socket
import ssl
import os
import threading
from OpenSSL import crypto

# --- Configuration ---
ROOT_CA_CERT_PATH = "/certificate/rootCA.crt"
ROOT_CA_KEY_PATH = "/certificate/rootCA.key"
CERT_DIR = "/tmp/mitm_certs" # Directory to store generated certificates
CERT_CACHE = {} # Cache for generated certificate paths: {hostname: (cert_file, key_file)}

# --- Certificate Generation ---
def generate_certificate(hostname):
    """
    Generates a new certificate for the given hostname, signed by the root CA.
    Prints confirmation messages and saves the cert/key to files.
    """
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR, exist_ok=True)

    key_file_path = os.path.join(CERT_DIR, f"{hostname}.key.pem")
    cert_file_path = os.path.join(CERT_DIR, f"{hostname}.crt.pem")

    # 1. Generate a new private key for the certificate
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)

    # 2. Create the certificate
    cert = crypto.X509()
    cert.get_subject().CN = hostname
    cert.get_subject().C = "NL"  # As per example output

    cert.set_serial_number(int(os.urandom(16).hex(), 16)) # Random serial number
    cert.gmtime_adj_notBefore(0)  # Valid from now
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valid for 1 year

    # Load root CA
    with open(ROOT_CA_CERT_PATH, "rt") as f:
        root_ca_cert_pem = f.read()
    with open(ROOT_CA_KEY_PATH, "rt") as f:
        root_ca_key_pem = f.read()

    root_ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_ca_cert_pem)
    root_ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, root_ca_key_pem)

    cert.set_issuer(root_ca_cert.get_subject()) # Issuer is the Root CA
    cert.set_pubkey(pkey) # Use the new private key's public part

    # Add Subject Alternative Name (SAN) extension - crucial for modern clients
    san_list = [f"DNS:{hostname}"]
    cert.add_extensions([
        crypto.X509Extension(b"subjectAltName", False, ", ".join(san_list).encode('ascii'))
    ])

    cert.sign(root_ca_key, "sha256") # Sign the certificate with the Root CA's key

    # Print messages as per the example output
    print("Certificate request self-signature ok")
    subject_c = cert.get_subject().C
    subject_cn = cert.get_subject().CN
    print(f"subject=C = {subject_c}, CN = {subject_cn}")


    # Save the generated key and certificate to files
    with open(key_file_path, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey).decode("utf-8"))
    with open(cert_file_path, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))

    return cert_file_path, key_file_path

def get_or_generate_cert(hostname):
    """
    Retrieves cert/key from cache or generates new ones if not found.
    """
    if hostname in CERT_CACHE:
        return CERT_CACHE[hostname]

    cert_file, key_file = generate_certificate(hostname)
    CERT_CACHE[hostname] = (cert_file, key_file)
    return cert_file, key_file

# --- SNI Callback for dynamic context switching ---
def sni_callback(ssl_socket, server_name, original_context):
    """
    Called when the client provides SNI.
    Generates a cert for the server_name and switches the SSLContext.
    """
    try:
        if server_name:
            # print(f"[*] SNI: Client requested {server_name}")
            cert_file, key_file = get_or_generate_cert(server_name)

            new_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            new_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            ssl_socket.context = new_context # Switch to the new context for this connection
            ssl_socket.requested_server_name = server_name # Store for handler
        else:
            # print("[!] SNI: No server name provided by client.")
            # Optionally, handle this case (e.g., use a default cert or close)
            # For this assignment, we expect SNI.
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
    except Exception as e:
        print(f"[!] Error in SNI callback for {server_name}: {e}")
        return ssl.ALERT_DESCRIPTION_INTERNAL_ERROR # Signal an internal error


# --- Client Handling ---
def handle_client_connection(client_ssl_socket, client_address, requested_hostname):
    """
    Handles the connection: connects to target, relays data, prints traffic.
    """
    # print(f"[*] Handling connection from {client_address} for {requested_hostname}")
    target_socket = None
    try:
        # 1. Connect to the actual target server
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_ssl_context = ssl.create_default_context() # Standard context for client
        secure_target_socket = target_ssl_context.wrap_socket(target_socket, server_hostname=requested_hostname)
        secure_target_socket.connect((requested_hostname, 443)) # Standard HTTPS port
        # print(f"[*] Connected to target: {requested_hostname}:443")

        # Set timeouts for operations
        client_ssl_socket.settimeout(5.0)
        secure_target_socket.settimeout(5.0)

        # 2. Read request from client
        client_request_data = b""
        try:
            # Read headers first
            while b"\r\n\r\n" not in client_request_data:
                chunk = client_ssl_socket.recv(4096)
                if not chunk: break
                client_request_data += chunk
            # For GET, this is typically the whole request. Add body reading if POST etc. needed.
        except socket.timeout:
            # print("[*] Timeout reading from client")
            pass # Expected if client sends data and stops

        if not client_request_data:
            # print("[*] No data received from client.")
            return

        # Print client request (mimicking example output format)
        print(client_request_data.decode(errors='ignore').rstrip())
        print() # Blank line after request, before response (as per example)

        # 3. Forward request to target server
        secure_target_socket.sendall(client_request_data)

        # 4. Read response from target server
        target_response_data = b""
        try:
            # Read headers
            while b"\r\n\r\n" not in target_response_data:
                chunk = secure_target_socket.recv(4096)
                if not chunk: break
                target_response_data += chunk

            # Determine content length to read the full body for responses that have it
            headers_part_str = target_response_data.split(b"\r\n\r\n", 1)[0].decode(errors='ignore')
            content_length = -1
            is_chunked = False

            for header_line in headers_part_str.split("\r\n"):
                if header_line.lower().startswith("content-length:"):
                    content_length = int(header_line.split(":", 1)[1].strip())
                    break
                if header_line.lower().startswith("transfer-encoding:") and "chunked" in header_line.lower():
                    is_chunked = True
                    break
            
            if content_length != -1:
                body_so_far = target_response_data.split(b"\r\n\r\n", 1)[1]
                while len(body_so_far) < content_length:
                    needed = content_length - len(body_so_far)
                    chunk = secure_target_socket.recv(min(4096, needed))
                    if not chunk: break
                    target_response_data += chunk
                    body_so_far += chunk
            elif is_chunked: # Simplified chunked reading
                while not target_response_data.endswith(b"\r\n0\r\n\r\n"):
                    chunk = secure_target_socket.recv(4096)
                    if not chunk: break
                    target_response_data += chunk
            # else: (no content-length, not chunked - e.g. connection close indicates end)
            # For simplicity, we assume the initial reads + header logic caught most cases for the assignment.
            # A full robust HTTP parser is complex.

        except socket.timeout:
            # print("[*] Timeout reading from target server")
            pass

        if not target_response_data:
            # print("[*] No data received from target server.")
            return

        # Print target response
        print(target_response_data.decode(errors='ignore').rstrip())

        # 5. Forward response to client
        client_ssl_socket.sendall(target_response_data)

    except ssl.SSLError as e:
        # print(f"[!] SSL Error in handle_client for {requested_hostname}: {e}")
        pass
    except socket.error as e:
        # print(f"[!] Socket Error in handle_client for {requested_hostname}: {e}")
        pass
    except Exception as e:
        print(f"[!] General Error in handle_client for {requested_hostname}: {e}")
    finally:
        if secure_target_socket:
            secure_target_socket.close()
        if client_ssl_socket:
            client_ssl_socket.close()
        # print(f"[*] Closed connection for {requested_hostname}")


# --- Main Server Logic ---
def main():
    if len(argv) < 2:
        print(f"Usage: {argv[0]} <port>")
        return

    try:
        listen_port = int(argv[1])
    except ValueError:
        print(f"Error: Invalid port number '{argv[1]}'")
        return

    # Initial (default) SSL context for the server.
    # This needs a cert/key, even if SNI callback replaces it.
    # We generate a dummy one for "localhost" or a placeholder.
    try:
        default_cert_file, default_key_file = get_or_generate_cert("proxy.default.local")
    except Exception as e:
        # Clear the prints from the default cert generation if it's not the main interaction
        # For this script, we'll let it print. If it fails, server won't start.
        print(f"[!] Failed to generate default certificate for server context: {e}")
        return

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        server_context.load_cert_chain(certfile=default_cert_file, keyfile=default_key_file)
    except Exception as e:
        print(f"[!] Failed to load default cert/key into context: {e}")
        return

    server_context.sni_callback = sni_callback

    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listen_socket.bind(('0.0.0.0', listen_port))
        listen_socket.listen(5) # Max queued connections
    except Exception as e:
        print(f"[!] Error binding or listening on port {listen_port}: {e}")
        return

    # print(f"[*] Listening on 0.0.0.0:{listen_port}...")

    try:
        while True:
            client_socket, client_address = listen_socket.accept()
            # print(f"[*] Accepted connection from {client_address[0]}:{client_address[1]}")

            try:
                # Wrap socket, but do not handshake immediately. Handshake triggers SNI.
                client_ssl_socket = server_context.wrap_socket(client_socket, server_side=True,
                                                               do_handshake_on_connect=False)
                client_ssl_socket.do_handshake() # This will trigger sni_callback

                requested_hostname = getattr(client_ssl_socket, 'requested_server_name', None)

                if requested_hostname:
                    # Create a new thread to handle this client connection
                    handler_thread = threading.Thread(target=handle_client_connection,
                                                      args=(client_ssl_socket, client_address, requested_hostname))
                    handler_thread.daemon = True # Allow main program to exit even if threads are running
                    handler_thread.start()
                else:
                    # print("[!] Could not determine server name via SNI. Closing connection.")
                    client_ssl_socket.close()

            except ssl.SSLError as e:
                # print(f"[!] SSL Handshake or wrap error: {e}")
                client_socket.close() # Close the raw socket
            except Exception as e:
                # print(f"[!] Error accepting/wrapping connection: {e}")
                client_socket.close() # Close the raw socket


    except KeyboardInterrupt:
        print("\n[*] Server shutting down...")
    finally:
        if listen_socket:
            listen_socket.close()
        # print("[*] Cleaned up resources.")
        # Optional: Clean up CERT_DIR
        # import shutil
        # if os.path.exists(CERT_DIR):
        #     shutil.rmtree(CERT_DIR)


if __name__ == "__main__":
    main()