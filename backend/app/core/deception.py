import socket
from datetime import datetime

class SpiderwebHoneypot:
    """
    A honeypot that pretend to be a server like an SSH or Telnet to catch attackers
    scanning your network.
    """
    def __init__(self, port, host = "0.0.0.0", service_name = "Honeypot"):
        self.port = port
        self.host = host
        self.service_name = service_name

    #This method will open up a fake server and wait for connections.
    def start_listening(self):
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            conn, addr = server_socket.accept()
            data = conn.recv(1024)
            conn.close()

    def format_alert(self, attacker_ip, port, username = None, password=None):
        alert = { "attacker_ip": attacker_ip,
                  "port" : port,
                  "service_name": self.service_name,
                  "timestamp" : str(datetime.now()),
                  "username" : username,
                  "password" : password
        }

        return alert