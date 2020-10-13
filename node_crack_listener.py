"""
Node providing brute-force cracking service.
"""

import os
import DB
import sys
from _thread import *
import socket
import time
import hashlib
import datetime

def main():

    database = './Data/nodeDB.db'
    dictionary = '/home/phed/Resources/rockyou.txt'
    # Create default database file if it does not exist.
    if not os.path.isfile(database):
        DB.build_database(database, dictionary)

    # ------------------------------------------------------------------------ #
    sIP_listener = get_ip()  # Source IP. Peers requesting crack result.
    sPort_listener_probe = 50002   # Source port for listener (incoming queries).
    sPort_listener_crack = 50003   # Source port for listener (incoming job).
    dPort_crack = 50004   # Destination port. Send cracking result.
    sPort_listener_crack_stop = 50005   # Source port for listener (termination request of cracker).
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    global crack_status
    crack_status = {}   # Each client job status.
    # ------------------------------------------------------------------------ #

    # Receive probe requests.
    start_new_thread(receive_probe_BF, (sIP_listener, sPort_listener_probe))

    # Accept and manage jobs.
    start_new_thread(receive_job_BF, (sIP_listener, sPort_listener_crack, dPort_crack, alphabet, database))

    # Receive message to terminate cracker of specific client (UUID), when client gets password from other peer.
    start_new_thread(receive_crack_stop, (sIP_listener, sPort_listener_crack_stop))

    # Keep program running.
    while True:
        time.sleep(1)


def client_crack_stop(conn, ip, port):
    """
    Connected client. Set crack status for client (UUID) to False.
    """
    global crack_status
    # Receive client UUID, if match - terminate.
    while True:
        rData = conn.recv(2048).decode('utf-8')
        if rData: # If data has been received.
            break
    # rData is cUUID as string of the connected client.
    if rData in crack_status: # If this client has an active job.
        crack_status[rData] = False
        print(bcolors.OKGREEN + str(datetime.datetime.now()) + ' | Cracker job for ' + rData + ' terminated [JOB STOP].' + bcolors.ENDC)
    else:
        print(str(datetime.datetime.now()) + ' | No active cracker job for: ' + str(ip) + ':' + str(port) + ' [JOB STOP].')
    conn.close()
    print(str(datetime.datetime.now()) + ' | Connection closed to: ' + str(ip) + ':' + str(port) + ' [JOB STOP].')


def receive_crack_stop(sIP, sPort):
    """
    Listen for a terminate message to stop active cracking job.
    """
    s = socket.socket()
    try:
        s.bind((sIP, sPort))
    except socket.error as e:
        print(str(datetime.datetime.now()) + ' | Listening service on: ' + str(sIP) + ':' + str(sPort) + ' [ERROR].')
        print(str(e))
    print(str(datetime.datetime.now()) + ' | Listening on ' + str(sIP) + ':' + str(sPort) + ' [JOB STOP].')
    s.listen(5)    # Listen for connections.
    # Accept clients.
    while True:
        conn, addr = s.accept()   # Accept connection. (This is where the process waits.)
        print(str(datetime.datetime.now()) + ' | Connected to: ' + addr[0] + ':' + str(addr[1]) + ' [JOB STOP].')
        start_new_thread(client_crack_stop, (conn, addr[0], addr[1])) # Each connected node separate thread.
    s.close()


def cracker(nodeLetterRange, qHash, alphabet, cUUID):
    """
    Searches the password space up to 6 letter range, based on letter range provided.
    """
    global crack_status
    # 1. E.g. a to z.
    for letterOne in nodeLetterRange:
        if get_md5(letterOne) == qHash:
            return letterOne
    # 2. E.g. aa to zz.
    for letterOne in nodeLetterRange:
        for letterTwo in alphabet:
            current = letterOne + letterTwo
            if crack_status[cUUID] == True:
                if get_md5(current) == qHash:
                    return current
            else:
                return False
    # 3. E.g. aaa to zzz.
    for letterOne in nodeLetterRange:
        for letterTwo in alphabet:
            for letterThree in alphabet:
                current = letterOne + letterTwo + letterThree
                if crack_status[cUUID] == True:
                    if get_md5(current) == qHash:
                        return current
                else:
                    return False
    # 4. E.g. aaaa to zzzz.
    for letterOne in nodeLetterRange:
        for letterTwo in alphabet:
            for letterThree in alphabet:
                for letterFour in alphabet:
                    current = letterOne + letterTwo + letterThree + letterFour
                    if crack_status[cUUID] == True:
                        if get_md5(current) == qHash:
                            return current
                    else:
                        return False
    # 5. E.g. aaaaa to zzzzz.
    for letterOne in nodeLetterRange:
        for letterTwo in alphabet:
            for letterThree in alphabet:
                for letterFour in alphabet:
                    for letterFive in alphabet:
                        current = letterOne + letterTwo + letterThree + letterFour + letterFive
                        if crack_status[cUUID] == True:
                            if get_md5(current) == qHash:
                                return current
                        else:
                            return False
    # 6. E.g. aaaaaa to zzzzzz.
    for letterOne in nodeLetterRange:
        for letterTwo in alphabet:
            for letterThree in alphabet:
                for letterFour in alphabet:
                    for letterFive in alphabet:
                        for letterSix in alphabet:
                            current = letterOne + letterTwo + letterThree + letterFour + letterFive + letterSix
                            if crack_status[cUUID] == True:
                                if get_md5(current) == qHash:
                                    return current
                            else:
                                return False

    # 7. E.g. aaaaaaa to zzzzzzz.
    for letterOne in nodeLetterRange:
        for letterTwo in alphabet:
            for letterThree in alphabet:
                for letterFour in alphabet:
                    for letterFive in alphabet:
                        for letterSix in alphabet:
                            for letterSeven in alphabet:
                                current = letterOne + letterTwo + letterThree + letterFour + letterFive + letterSix + letterSeven
                                if crack_status[cUUID] == True:
                                    if get_md5(current) == qHash:
                                        return current
                                else:
                                    return False

    # 8. E.g. aaaaaaaa to zzzzzzzz.
    for letterOne in nodeLetterRange:
        for letterTwo in alphabet:
            for letterThree in alphabet:
                for letterFour in alphabet:
                    for letterFive in alphabet:
                        for letterSix in alphabet:
                            for letterSeven in alphabet:
                                for letterEight in alphabet:
                                    current = letterOne + letterTwo + letterThree + letterFour + letterFive + letterSix + letterSeven + letterEight
                                    if crack_status[cUUID] == True:
                                        if get_md5(current) == qHash:
                                            return current
                                    else:
                                        return False
    # If no results.
    return False


def client_job_BF(conn, ip, port, dPort, alphabet, database):
    """
    Wait for connection. Receive and crack hash.
    """
    # Receive range, hash, and UUID.
    while True: # Keep trying to receive data.
        rData = conn.recv(2048).decode('utf-8')
        if rData: # If data has been received.
            break
    conn.close()

    # Start brute-force cracking job.
    print(str(datetime.datetime.now()) + ' | Cracking job started for: ' + str(ip) + ':' + str(port) + ' [Cracking...].')
    rData = rData.split(';')
    delegated_range = rData[0]
    qHash = rData[1]
    cUUID = rData[2]
    global crack_status
    crack_status[cUUID] = True  # The job is accepted for this client (UUID).
    # Run cracker and receive result.
    cResult = cracker(delegated_range, qHash, alphabet, cUUID)

    # Send brute-force cracking results to client.
    print(str(datetime.datetime.now()) + ' | Connecting to peer at ' + str(ip) + ':' + str(dPort) + ' [JOB RESULTS].')
    s = socket.socket()
    try:
        s.connect((ip, dPort))
    except socket.error as e:
        print(str(e))
        return False
    if cResult != False:
        s.sendall(cResult.encode('utf-8'))
        print(bcolors.OKGREEN + str(datetime.datetime.now()) + ' | Password found: >>> ' + str(cResult) +  ' <<< [JOB RESULTS].' + bcolors.ENDC)
        # Add cracked password to database.
        DB.add_hash(database, qHash, cResult)
    else:
        s.sendall('FALSE'.encode('utf-8'))
        print(str(datetime.datetime.now()) + ' | No matches (or terminated) [JOB RESULTS].')
    conn.close()
    print(str(datetime.datetime.now()) + ' | Connection closed to: ' + str(ip) + ':' + str(dPort) + ' [JOB RESULTS].')


def receive_job_BF(ip, port, dPort, alphabet, database):
    """
    Listener program run in the background. Accept job from saved client (from probe).
    """
    s = socket.socket()
    try:
        s.bind((ip, port))
    except socket.error as e:
        print(str(datetime.datetime.now()) + ' | Listening service on: ' + str(ip) + ':' + str(port) + ' [ERROR].')
        print(str(e))
    print(str(datetime.datetime.now()) + ' | Receiving remote cracking job requests on ' + str(ip) + ':' + str(port) + ' [JOB REQUEST].')
    s.listen(5)
    # Accept clients.
    while True:
        conn, addr = s.accept()   # Accept connection. (This is where the process waits.)
        print(str(datetime.datetime.now()) + ' | Connected to: ' + addr[0] + ':' + str(addr[1]) + ' [JOB REQUEST].')
        start_new_thread(client_job_BF, (conn, addr[0], addr[1], dPort, alphabet, database)) # Client probe requests.
    s.close()


def receive_probe_BF(ip, port):
    """
    Receive probe for service availability.
    """
    s = socket.socket()  # Socket object.
    try:
        s.bind((ip, port))
    except socket.error as e:
        print(str(datetime.datetime.now()) + ' | Listening service on: ' + str(ip) + ':' + str(port) + ' [ERROR].')
        print(str(e))
    print(str(datetime.datetime.now()) + ' | Receiving remote probe requests on ' + str(ip) + ':' + str(port) + ' [REMOTE PROBE].')
    s.listen(5)    # Listen for connections.
    while True:
        conn, addr = s.accept()   # Accept connection. (This is where the process waits.)
        print(str(datetime.datetime.now()) + ' | Connected to: ' + addr[0] + ':' + str(addr[1]) + ' [REMOTE PROBE].')
        start_new_thread(client_probe, (conn, addr[0], addr[1])) # Client probe requests.
    s.close()


def client_probe(conn, ip, port):
    """
    Wait for connection. Receive probe, respond if available.
    """
    # Receive PING
    while True: # Keep trying to receive data.
        rData = conn.recv(2048).decode('utf-8')
        if rData: # If data has been received.
            break
    # Let the requesting node know availability.
    conn.sendall('AVAILABLE'.encode('utf-8'))
    print(str(datetime.datetime.now()) + ' | Accepted job request from: ' + str(ip) + ':' + str(port) + ' [JOB ACCEPT].')
    conn.close()
    print(str(datetime.datetime.now()) + ' | Connection closed to: ' + str(ip) + ':' + str(port) + ' [REMOTE PROBE].')


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


def get_md5(string):
    """
    Returns md5 hash of input string.
    """
    hash_object = hashlib.md5(string.encode())
    return hash_object.hexdigest()


class bcolors:
    """
    Color terminal output message.
    https://stackoverflow.com/questions/287871/how-to-print-colored-text-in-python
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


if __name__ == '__main__':
    main()
