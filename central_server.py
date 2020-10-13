"""
Central server to share peers, grows the network.
"""


import os
import DB
import socket
import datetime
from _thread import *

def main():
    database = './Data/central_serverDB.db'
    dictionary = '/home/phed/Resources/rockyou.txt'
    # Create default database file if it does not exist.
    if not os.path.isfile(database):
        DB.build_database(database, dictionary)

    # ------------------------------------------------------------------------ #
    sIP = get_ip() # Source IP for listener. Automatically get local machine IP.
    sPort = 50000  # Source port for listener.
    # ------------------------------------------------------------------------ #

    s = socket.socket()
    # Bind port, start listener.
    try:
        s.bind((sIP, sPort))
    except socket.error as e:
        print(str(e))
    print(str(datetime.datetime.now()) + ' | Listening on ' + str(sIP) + ':' + str(sPort) + ' [PEER SYNC].')
    s.listen(5)    # Listen for connections.
    # Accept clients.
    while True:
        conn, addr = s.accept()   # Accept connection. (This is where the process waits.)
        print(str(datetime.datetime.now()) + ' | Connected to: ' + addr[0] + ':' + str(addr[1]) + ' [PEER SYNC].')
        DB.add_peer(database, addr[0]) # Add the connected client (IP) as a peer in the record of peers.
        start_new_thread(client_conn, (database, conn, addr[0], addr[1])) # Each connected node separate thread.
    s.close()


def client_conn(database, conn, ip, port):
    """
    Connected client. Send the client record of peers.
    """
    peer_list = DB.get_peers(database)    # List of peers.
    sData = ';'.join(peer_list)  # Prep sent data as string.
    conn.sendall(sData.encode('utf-8'))
    conn.close()
    print(str(datetime.datetime.now()) + ' | Connection closed to: ' + ip + ':' + str(port) + ' [PEER SYNC].')


def get_ip():
    """
    Get the ip address of the local machine.
    https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip


if __name__ == '__main__':
    main()
