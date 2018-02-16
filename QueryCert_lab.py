import sys
import ssl
import subprocess
import resource
import socket
import requests
import time

#write in python2.7
ca_path = '/etc/ssl/certs/ca-certificates.crt'

def get_server_cert():
    cert = ssl.get_server_certificate((sys.argv[1], 443))
    with open(sys.argv[1]+'.pem', 'w') as f:
        f.write(cert)
        f.close()
    cert_text = subprocess.check_output(["openssl", "x509", "-text", "-noout", "-in", sys.argv[1]+'.pem'])
    print cert_text

def req_verify():
    req = requests.get('https://'+sys.argv[1], verify=ca_path)
    print '-----------------req--------------------'

def ssl_verify():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    wrappedSocket = ssl.wrap_socket(sock, cert_reqs=ssl.CERT_REQUIRED, ca_certs='/etc/ssl/certs/ca-certificates.crt')
    try:
        wrappedSocket.connect((sys.argv[1], 443))
    except:
        response = False
    else:
        pem_cert = ssl.DER_cert_to_PEM_cert(wrappedSocket.getpeercert(True))
    wrappedSocket.close()
    print '-----------------ssl--------------------'

def main():
    if len(sys.argv) != 3:
        print 'python QuerCert.py [url] [memoryLimit]'
        sys.exit(0)

    #limit soft memory
    rsrc = resource.RLIMIT_DATA
    soft, hard = resource.getrlimit(rsrc)
    print 'Soft limit starts as :', soft

    resource.setrlimit(rsrc, (int(sys.argv[2]), hard))
    soft, hard = resource.getrlimit(rsrc)
    print 'Soft limit changed to :', soft
    
    #get_server_cert()
    
    start_time = time.clock()
    ssl_verify()
    print 'ssl_verify time =', time.clock() - start_time, 'seconds'   

    start_time = time.clock()
    req_verify()
    print 'req_verify time =', time.clock() - start_time, 'seconds'

if __name__ == '__main__':
    main()
