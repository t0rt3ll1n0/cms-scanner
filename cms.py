#usr/bin/python3

import datetime
import socket
import struct
import os
try:
    import requests
except ModuleNotFoundError:
    print("\nRequests non è installato, lo farò io per te...\n")
    os.system('pip3 install requests')
    if os.name == 'NT':
        os.system('cls')
    else:
        os.system('clear')
import sys

def uso():
    print("""  
cms.py: un semplice script python per capire con che cms è fatto un sito
uso: python3 cms.py https://www.sito.com
compatibile con: Windows, Linux, MacOS, Android.
""")

try:
    url = sys.argv[1]
except IndexError:
    uso()
    sys.exit(" ")

def cve():
    sock = socket.socket(socket.AF_INET)
    sock.settimeout(4)
    ip = input("Inserisci l'ip del server ")
    try:
        sock.connect((ip,  445))
    except socket.timeout:
        print("Timeout della connessione")
    buffer = b'\x00\x00\x00\xc0\xfeSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$\x00\x08\x00\x01\x00\x00\x00\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x\x00\x00\x00\x02\x00\x00\x00\x02\x02\x10\x02"\x02$\x02\x00\x03\x02\x03\x10\x03\x11\x03\x00\x00\x00\x00\x01\x00&\x00\x00\x00\x00\x00\x01\x00 \x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\n\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'

    sock.send(buffer)

    nb, = struct.unpack(">I", sock.recv(4))
    result = sock.recv(nb)

    if not result[68:70] == b"\x11\x03":
        print("Non Vulnerabile")
        sys.exit[1]
    if not result[70:72] == b"\x02\x00":
        print("Non Vulnerabile")
        sys.exit[2]

    print("Vulnerabile")


def joomla(url):
    print("Target: " + url +"\n")
    r = requests.get(url +"/administrator")
    status = r.status_code
    if(status == 200):
        print("\n[+] Joomla! CMS Trovato")
    elif(status == 404):
        print("\n[-] Joomla! CMS Non Trovato")
    elif(status == 502):
        sys.exit("Errore: bad gateway")
    elif(status == 403 or status == 401):
        sys.exit("Errore: non sei autorizzato")
    else:
        sys.exit("Errore sconosciuto, riprovare")
def wp(url):
    r = requests.get(url +"/wp-login.php")
    status = r.status_code
    if(status == 200):
        print("\n[+] WordPress CMS Trovato")
    elif(status == 404):
        print("\n[-] WordPress CMS Non Trovato")
    elif(status == 502):
        sys.exit("Errore: bad gateway")
    elif(status == 403 or status == 401):
        sys.exit("Errore: non sei autorizzato")
    else:
        sys.exit("Errore sconosciuto, riprovare")
def drupal(url):
    r = requests.get(url +"/drupal")
    status = r.status_code
    if(status == 200):
        print("\n[+] Drupal CMS Trovato")
    elif(status == 404):
        print("\n[-] Drupal CMS Non Trovato")
    elif(status == 502):
        sys.exit("Errore: bad gateway")
    elif(status == 403 or status == 401):
        sys.exit("Errore: non sei autorizzato")
    else:
        sys.exit("Errore sconosciuto, riprovare")
try:
    adesso = datetime.datetime.now()
    joomla(url)
    wp(url)
    drupal(url)
    print("\n[*] Controllo se è vulnerabile a SMBGhost...\n")
    cve()
    adesso_davvero = datetime.datetime.now()
    tempo_scan = adesso_davvero - adesso
    print("\n[*] Scansione finita in " + str(tempo_scan))
except KeyboardInterrupt:
    sys.exit("\n\nRilevato CTRL+C, uscita")

