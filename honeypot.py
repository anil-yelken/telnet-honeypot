import socket
import logging
import datetime
logging.basicConfig(filename='honeypot.log',level=logging.DEBUG)
hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)
honeypot = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
log=str(datetime.datetime.now())+"|Honeypot started|" + IP + ':23'
logging.debug(log)
honeypot.bind(("0.0.0.0", 23))
honeypot.listen()
global honeypot_socket,address
(honeypot_socket, address) = honeypot.accept()
honeypot_socket.settimeout(20)
log="|"+str(datetime.datetime.now())+"|Honeypot connection from|"+ address[0] + ':' + str(address[1])
logging.debug(log)
try:
    data = "Ubuntu\n\n#"
    honeypot_socket.send(data.encode())
    log = "|"+str(datetime.datetime.now()) + "|Honeypot data|Ubuntu"
    logging.debug(log)
except socket.error:
    honeypot_socket.close()
command=""
while True:
    try:
        recv_data = honeypot_socket.recv(1024).decode()
        command+=recv_data
        try:
            if command == 'whoami':
                data="\nroot\n#"
                honeypot_socket.send(data.encode())
                log = "|"+str(datetime.datetime.now()) + "|Honeypot data|whoami"
                import logging
                logging.debug(log)
                command=""
            elif command == 'id':
                data="\n0\n#"
                honeypot_socket.send(data.encode())
                log = "|"+str(datetime.datetime.now()) + "|Honeypot data|id"
                import logging
                logging.debug(log)
                command=""
            elif command == 'ls':
                data="\n\n#"
                honeypot_socket.send(data.encode())
                log = "|"+str(datetime.datetime.now()) + "|Honeypot data|ls"
                import logging
                logging.debug(log)
                command=""
            elif command == 'ifconfig' or command=="ip a":
                data="""\neth0      Link encap:Ethernet  HWaddr 00:00:00:12:e1:a5  
          inet addr:192.168.1.5 Bcast:192.168.1.255  Mask:255.255.255.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:54071 errors:1 dropped:0 overruns:0 frame:0
          TX packets:48515 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:22009423 (20.9 MiB)  TX bytes:25690847 (24.5 MiB)
          Interrupt:10 Base address:0xd020 \n#"""
                honeypot_socket.send(data.encode())
                log = "|"+str(datetime.datetime.now()) + "|Honeypot data|ifconfig/ip a"
                import logging
                logging.debug(log)
                command=""
            elif command == 'ps':
                data="""\n  PID TTY          TIME CMD
11130 pts/0    00:00:00 bash
21111 pts/0    00:00:00 ps\n#"""
                honeypot_socket.send(data.encode())
                log = "|"+str(datetime.datetime.now()) + "|Honeypot data|ps"
                import logging
                logging.debug(log)
                command=""
            elif command == 'help':
                data = """\nwhoami id ps ls ifconfig\n#"""
                honeypot_socket.send(data.encode())
                log = "|" + str(datetime.datetime.now()) + "|Honeypot data|ps"
                import logging
                logging.debug(log)
                command = ""
        except:
            honeypot_socket.close()
    except socket.error:
        log = "|" + str(datetime.datetime.now()) + "|Honeypot closed|"
        import logging
        logging.debug(log)
        exit()