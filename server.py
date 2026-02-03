import socket
import ssl
import secrets
import mysql.connector

# MySQL Connection
db = mysql.connector.connect(host="localhost", user="root", password="yourpassword", database="security_db")
cursor = db.cursor()

HOST, PORT = '127.0.0.1', 8443
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="certfile.pem", keyfile="keyfile.pem")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind((HOST, PORT))
    sock.listen(5)
    print("Server listening...")

    while True:
        newsocket, fromaddr = sock.accept()
        try:
            with context.wrap_socket(newsocket, server_side=True) as ssock:
                # 1. Pick a random codeword
                codeword = secrets.token_hex(16)
                
                # 2. Save to MySQL
                cursor.execute("INSERT INTO codewords (word) VALUES (%s)", (codeword,))
                db.commit()
                
                # 3. Send codeword to client
                ssock.sendall(codeword.encode())
                print(f"Sent codeword {codeword} to {fromaddr}")
                
        except Exception as e:
            print(f"Error: {e}")