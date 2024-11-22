import socket
import sys
import threading

def handle_client(conn, addr, other_conn):
    try:
        print(f"Connected by {addr}")
        data = conn.recv(4096)
        if not data:
            print(f"No data received from {addr}")
            return

        print(f"Received public key from {addr}")
        other_conn.sendall(data)
        print(f"Forwarded public key to the other client")

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection closed for {addr}")

def start_server(host='localhost', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        try:
            server_socket.bind((host, port))
            server_socket.listen(2)
            print(f"Server is listening on {host}:{port}")

            while True:
                conn_a, addr_a = server_socket.accept()
                print(f"Alice connected from {addr_a}")

                conn_b, addr_b = server_socket.accept()
                print(f"Bob connected from {addr_b}")

                thread_a = threading.Thread(target=handle_client, args=(conn_a, addr_a, conn_b))
                thread_b = threading.Thread(target=handle_client, args=(conn_b, addr_b, conn_a))

                thread_a.start()
                thread_b.start()

                thread_a.join()
                thread_b.join()

        except KeyboardInterrupt:
            print("Server shutting down.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            server_socket.close()

if __name__ == "__main__":
    start_server()