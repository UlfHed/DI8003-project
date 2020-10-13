import os
import DB
import socket
import time
import re
from _thread import *
import datetime
import uuid

def main():

    database = './Data/nodeDB.db'
    dictionary = '/home/phed/Resources/rockyou.txt'
    # Create default database file if it does not exist.
    if not os.path.isfile(database):
        DB.build_database(database, dictionary)

    # ------------------------------------------------------------------------ #
    dPort_hash_lookup = 50001   # Remote query is sent to listener port on remote nodes, for hash lookup.
    dPort_peer_probe = 50002   # Remote request, for cracker service availability check.
    dPort_peer_crack = 50003   # Remote crack job initiation.
    sPort_listener_crack = 50004 # Becomes listener for result from node cracks.
    dPort_peer_crack_stop = 50005   # Remote crack job cancel.
    sIP_listener = get_ip()  # Source IP. Peers requesting crack result.
    alphabet = 'abcdefghijklmnopqrstuvwxyz' # Symbols used for brute-force.
    global cUUID
    cUUID = str(uuid.uuid4()) # Unique identifier for client.
    global found_password
    found_password = False
    # ------------------------------------------------------------------------ #

    # Main driver.
    while True:
        time.sleep(1)    # Best placed here due to interruption callbacks.
        # Input hash.
        print('#' * 51)
        print('Provide a hash (MD5) for lookup or quit(q).')
        while True:
            try:
                qHash = input('Valid MD5 hash > ')
                if confirm_md5(qHash):
                    break
                elif qHash.lower() in ('q', 'quit', 'end', 'stop'):
                    exit()
                else:
                    print('Invalid hash.')
            except Exception as e:
                print(e)

        # Run local query.
        print('#' * 51)
        qResult = local_hash_lookup(database, qHash)
        if qResult != False:
            print(bcolors.OKGREEN + str(datetime.datetime.now()) + ' | Password(s) found in local database [LOCAL HASH LOOKUP].' + bcolors.ENDC)
            for password in qResult:
                print(bcolors.OKGREEN + ' +', password + bcolors.ENDC)
            continue    # Return to main prompt. Password has been found.

        # Query peer databases - If password not found in local database.
        else:
            print('#' * 51)
            print(str(datetime.datetime.now()) + ' | Querying peer(s) ... [REMOTE HASH LOOKUP].')
            password_list = []
            peer_list = DB.get_peers(database)  # List of peers.
            peer_list.remove(sIP_listener)   # Remove local machine, don't query itself.
            for dIP in peer_list:  # Each peer in list of peers.
                qResult = remote_hash_lookup(database, dIP, dPort_hash_lookup, qHash)
                if qResult != False:    # Resurns False if no password or error.
                    for password in qResult:    # One peer may give multiple passwords for 1 hash.
                        password_list.append(password)
            if password_list != []:
                print(bcolors.OKGREEN + str(datetime.datetime.now()) +' | Password(s) found by remote peer(s) [REMOTE HASH LOOKUP].' + bcolors.ENDC)
                for password in password_list:
                    print(' +', password)
                continue    # Return to main prompt. Password has been found.

            # Request brute-force cracking service - If password not found in peer database.
            else:
                print(bcolors.WARNING + str(datetime.datetime.now()) + ' | No password results for ' + str(qHash) + ' [REMOTE HASH LOOKUP].' + bcolors.ENDC)
                print('#' * 51)
                while True:
                    try:
                        answer = input(bcolors.OKBLUE + 'Request peers to brute-force hash in real-time? (Y/N): ' + bcolors.ENDC).lower()
                        if answer in ('y', 'n', 'yes', 'no'):
                            break
                        elif answer in ('q', 'stop', 'exit', 'quit'):
                            exit()
                    except Exception as e:
                        print(e)

                # Brute-force cracking service.
                peer_list.append(sIP_listener)    # Add itself to include local brute force service.
                if answer in ('y', 'yes'):
                    available_peers = []  # List of available peers.
                    for dIP in peer_list:   # The nodes that were contacted for hash lookup earlier.
                        # Probe peers for availability.
                        qResult = remote_probe_BF(dIP, dPort_peer_probe)
                        if qResult:    # True if available.
                            available_peers.append(dIP)
                    print(bcolors.OKBLUE + str(datetime.datetime.now()) + ' | ' + str(len(available_peers)) + ' node(s) available for brute-force cracking. [REMOTE PROBE].' + bcolors.ENDC)
                    # Get the template for range, based on number of available nodes.
                    delegated_range = get_range_template(alphabet, len(available_peers))
                    # Start brute-force job at remote peers.
                    count = 0   # Index count of delegated_range.
                    for dIP in available_peers:
                        remote_job_BF(dIP, dPort_peer_crack, delegated_range[count], qHash)
                        count += 1

                    # Start listener for response. Done as to not tie up the nodes. Above connection from request must be closed for cracking jobs to run parallell.
#                    receive_crack_result(sIP_listener, sPort_listener_crack, len(available_peers))
                    start_new_thread(receive_crack_result, (sIP_listener, sPort_listener_crack, dPort_peer_crack_stop, available_peers,))    # Background thread.
                    while found_password == False:
                        time.sleep(2)


def receive_crack_result(ip, port_start, port_stop, available_peers):
    """
    Listener program for all remote nodes sending their cracking results.
    """
    s = socket.socket()
    try:
        s.bind((ip, port_start))
    except socket.error as e:
        print(str(datetime.datetime.now()) + ' | Listening service on: ' + str(ip) + ':' + str(port_start) + ' [ERROR].')
        print(str(e))
    print(str(datetime.datetime.now()) + ' | Receiving cracking results on ' + str(ip) + ':' + str(port_start) + ' [JOB RESULTS].')
    s.listen(5)    # Listen for connections.
    # Accept clients.
    while True:
        conn, addr = s.accept()   # Accept connection. (This is where the process waits.)
        #print(str(datetime.datetime.now()) + ' | Connected to: ' + addr[0] + ':' + str(addr[1]) + ' [JOB RESULTS].')
        start_new_thread(client_conn_crack, (conn, addr[0], addr[1], port_stop, available_peers)) # Receive job results.
    s.close()


def client_conn_crack(conn, ip, port_start, port_stop, available_peers):
    """
    Connected client. Receive brute-force crack results.
    """
    global found_password
    global cUUID
    # Receive cracking results.
    while True: # Keep trying to receive data.
        rData = conn.recv(2048).decode('utf-8')
        if rData: # If data has been received.
            break
    if rData != 'FALSE':
        print('#' * 51)
        print(bcolors.OKGREEN + str(datetime.datetime.now()) + ' | >>> ' + str(rData) + ' <<<' + ' Found by ' + str(ip) + ':' + str(port_start) + ' [JOB RESULTS].' + bcolors.ENDC)
        print('#' * 51)
        found_password = True
        print(str(datetime.datetime.now()) + ' | Terminating active cracking jobs at peers [JOB STOP].')
        # Terminate active job for all other clients, by UUID.
        for dIP in available_peers:
            #print(str(datetime.datetime.now()) + ' | Connecting to peer at ' + str(dIP) + ':' + str(port_stop) + ' [JOB STOP].')
            s = socket.socket()
            try:
                s.connect((dIP, port_stop))
            except socket.error as e:
                print(str(e))
            s.sendall(cUUID.encode('utf-8'))  # Send data.
            s.close()
        print(str(datetime.datetime.now()) + ' | Connection to peer(s) closed [JOB STOP].')
    conn.close()


def remote_job_BF(ip, port, delegated_range, qHash):
    """
    Start job crack service at remote peer. Send delegated range and hash.
    """
    global cUUID
    print(str(datetime.datetime.now()) + ' | Starting cracking service at: ' + str(ip) + ':' + str(port) + ' [JOB START].')
    s = socket.socket()
    try:
        s.connect((ip, port))
    except socket.error as e:
        print(str(datetime.datetime.now()) + ' | Connecting to: ' + str(ip) + ':' + str(port) + ' [ERROR].')
        print(str(e))
        return False
    # Send range, hash, and UUID.
    message = delegated_range + ';' + qHash + ';' + str(cUUID)
    s.sendall(message.encode('utf-8'))    # Used for hierarchy at listener, as to not "snipe".
    s.close()
    return True


def get_range_template(alphabet, nrNodes):
    """
    Split the alphabet evenly on number of nodes.
    Increadibly inefficient.
    E.g. 5 nodes: ['abcdef', 'ghijk', 'lmnop', 'qrstu', 'vwxyz']
    """
    # Prep alphabet. Make each str element a list element.
    alphabetList = []
    alphabetList_baseTemplate = []
    for letter in alphabet:
        alphabetList.append(str(letter))
        alphabetList_baseTemplate.append(str(letter))
    # Create template of nr nodes list elements.
    baseTemplate = []
    baseStringTemplate = []
    for node in range(nrNodes): # E.g. 4 loops for 4 nodes, 4 elements.
        baseTemplate.append(0)
        baseStringTemplate.append('')
    # Derive distribution on nr nodes.
    nodeCount = 0
    while alphabetList_baseTemplate:
        if nodeCount == nrNodes:
            nodeCount = 0
        baseTemplate[nodeCount] += 1
        nodeCount += 1
        if alphabetList_baseTemplate:
            alphabetList_baseTemplate.pop(0)
    # Get letter distribution.
    nodeCount = 0
    count = 0
    for letter in alphabet:
        baseStringTemplate[nodeCount] += letter
        count += 1
        if count == baseTemplate[nodeCount]:
            count = 0
            nodeCount += 1
    return baseStringTemplate


def remote_probe_BF(dIP, dPort):
    """
    Probe remote peers, see if they are available. Lock service by UUID of requesting node.
    """
    print(str(datetime.datetime.now()) + ' | Requesting cracking service at ' + str(dIP) + ':' + str(dPort) + ' [REMOTE PROBE].')
    s = socket.socket()
    try:
        s.connect((dIP, dPort))
    except socket.error as e:
        print(str(datetime.datetime.now()) + ' | Connecting to: ' + str(dIP) + ':' + str(dPort) + ' [ERROR].')
        print(str(e))
        return False
    # Probe, send UUID.
    s.sendall('PING'.encode('utf-8'))    # Check availability.
    # Receive status.
    while True: # Keep trying to receive data.
        rData = s.recv(2048).decode('utf-8')
        if rData: # If data has been received.
            break
    # See if available. Receive "AVAILABLE" if it is.
    if rData == 'AVAILABLE':
        s.close()
        return True
    else:
        s.close()
        return False


def remote_hash_lookup(database, dIP, dPort, qHash):
    """
    Send query. Search peer database for all password matches to the input hash.
    Return list of passwords, if result, else False.
    """
    print(str(datetime.datetime.now()) + ' | Connecting to: ' + str(dIP) + ':' + str(dPort) + ' [REMOTE HASH LOOKUP].')
    s = socket.socket()
    try:
        s.connect((dIP, dPort))
    except socket.error as e:
        print(str(datetime.datetime.now()) + ' | Connecting to: ' + str(dIP) + ':' + str(dPort) + ' [ERROR].')
        print(str(e))
        return False
    s.sendall(qHash.encode('utf-8'))  # Send the hash for query.
    # Receive result of query on remote node.
    while True: # Keep trying to receive data.
        rData = s.recv(2048).decode('utf-8')
        if rData: # If data has been received.
            break
    # If node doesn't find password, message NULL is sent.
    if rData == 'Null':
        s.close()
        return False
    rData = rData.split(';')  # List of passwords from client.
    s.close()
    return rData


def local_hash_lookup(database, qHash):
    """
    Search local copy for all password matches to the input hash.
    Return found password, else return False.
    """
    print(str(datetime.datetime.now()) + ' | Searching local database ... [LOCAL HASH LOOKUP].')
    qResult = DB.query_hash(database, qHash)  # Query local database.
    if qResult: # If found in local database.
        return qResult
    else:
        print(bcolors.WARNING + str(datetime.datetime.now()) + ' | No password results for ' + str(qHash) + ' [LOCAL HASH LOOKUP].' + bcolors.ENDC)
        return False


def confirm_md5(string):
    """
    Return True if string is MD5 hash, else False.
    """
    if len(string) == 32 and len(re.findall(r"([a-fA-F\d]{32})", string)) > 0:
        return True
    return False


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
