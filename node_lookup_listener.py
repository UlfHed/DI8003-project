"""
Node synchronization with central server.
Node providing hash lookup service on local database, for peer nodes.
"""

import os
import DB
import sys
from _thread import *
import socket
import datetime
import time


def main():
    database = './Data/nodeDB.db'
    dictionary = '/home/phed/Resources/rockyou.txt'
    # Create default database file if it does not exist.
    if not os.path.isfile(database):
        DB.build_database(database, dictionary)

    # ------------------------------------------------------------------------ #
    dIP_CentralServer = get_dIP_CentralServer()
    dPort_CentralServer = 50000
    syncTimer = 30  # Synchronization request.
    sIP_listener = get_ip()  # Source IP. Peers requesting hash lookup.
    sPort_listener = 50001   # Source Port. Peers requesting hash lookup.
    # ------------------------------------------------------------------------ #

    # Synchronization with server.
    start_new_thread(sync_node, (dIP_CentralServer, dPort_CentralServer, database, syncTimer))    # Background thread.

    time.sleep(2)   # CLI Message output.

    # Receive queries from peer nodes.
    start_new_thread(receive_hash_lookup, (database, sIP_listener, sPort_listener)) # Background thread.

    # Keep program running.
    while True:
        time.sleep(1)




def receive_hash_lookup(database, sIP, sPort):
    """
    Listener, receive and accept peer nodes request for hash lookup.
    """
    s = socket.socket()
    try:
        s.bind((sIP, sPort))
    except socket.error as e:
        print(str(e))
    print(str(datetime.datetime.now()) + ' | Listening on ' + str(sIP) + ':' + str(sPort) + ' [HASH LOOKUP].')
    s.listen(5)    # Listen for connections.
    # Accept clients.
    while True:
        conn, addr = s.accept()   # Accept connection. (This is where the process waits.)
        print(str(datetime.datetime.now()) + ' | Connected to: ' + addr[0] + ':' + str(addr[1]) + ' [HASH LOOKUP].')
        DB.add_peer(database, addr[0]) # Add the connected client (IP) as a peer in the record of peers.
        start_new_thread(client_conn, (database, conn, addr[0], addr[1])) # Each connected node separate thread.
    s.close()


def client_conn(database, conn, ip, port):
    """
    Connected client. Search database for password, send password to connected client.
    """
    while True: # Keep trying to receive data.
        rData = conn.recv(2048).decode('utf-8')   # Buffer size?
        if rData: # If data has been received.
            break
    qResult = DB.query_hash(database, rData)  # Query local database.
    # Send result to remote peer if found password.
    if qResult:  # If password found, not empty list.
        sData = ';'.join(qResult)  # Prep sent data as string. Each element separated by ";".
        conn.sendall(sData.encode('utf-8'))  # Send data.
    else:
        conn.sendall('Null'.encode('utf-8'))    # Necessary for remote node to stop receiving data.
    conn.close()
    print(str(datetime.datetime.now()) + ' | Connection closed to: ' + ip + ':' + str(port) + ' [HASH LOOKUP].')


def sync_node(dIP, dPort, database, timer):
    """
    Main synchronization program. Get the latest peer list.
    """
    while True: # Never exit, keep running with sleep intervall.
        print(str(datetime.datetime.now()) + ' | Connecting to server at ' + str(dIP) + ':' + str(dPort) + ' [PEER SYNC].')
        s = socket.socket()
        try:
            s.connect((dIP, dPort))
        except socket.error as e:
            print(str(e))
            time.sleep(timer)
            continue    # New connection attempt.
        while True: # Keep trying to receive data.
            rData = s.recv(2048).decode('utf-8')
            if rData: # If data has been received.
                break
        s.close()
        print(str(datetime.datetime.now()) + ' | Connection to server closed [PEER SYNC].')
        # Update local peer record.
        count = 0
        peer_list = rData.split(';')  # List of peers.
        for peer in peer_list:
            count += DB.add_peer(database, peer)    # Add peers to database, returns 1 if new peer added, else 0.
        if count > 0:
            print(str(datetime.datetime.now()) + ' | + ' + str(count), ' new peer(s) added to database [PEER SYNC].')
        # Synchronization interval.
        time.sleep(timer)


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


def get_dIP_CentralServer():
    """
    User prompt to give IP of central synchronization server.
    """
    print('Provide IP of peer synchronization server.')
    while True:
        try:
            ip = input('IP: ')
        except Exception as e:
            print(str(e))
        break
    return ip


if __name__ == '__main__':
    main()
