import socket
import ssl
import re
import requests

# Terminal colour Class
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#Updating malicious links list
print(f"{bcolors.UNDERLINE}Updating malicious links list...............!{bcolors.ENDC}")
print(' ')
while True:
    try:
        mal_data_url = 'https://openphish.com/feed.txt'
        download_data = requests.get(mal_data_url, allow_redirects=True)
        open('mal_data_url.txt', 'wb').write(download_data.content)
        print(f"{bcolors.OKBLUE}Success: Malicious links list updated!{bcolors.ENDC}")
        break
    except requests.ConnectionError:
        print(f"{bcolors.WARNING}Malicious links is not updated{bcolors.ENDC}")
        break

print(' ')

#SSL_Connection_Prerequisites
context = ssl.SSLContext()
context.load_default_certs()

#URL_sanitization

result = ' '
protocol_in_use = ' '
host_name = ' '
uri_path_port = ' '
domain_path = ' '
uri_path = ' '
conn_port = ''
get_req_path = ''

user_input = input("Enter The HostName: ").lower()
print(' ')

if '://' in user_input:
    protocol_in_use, domain_path = user_input.split('://')
else: domain_path = user_input

if ':' in domain_path:
    uri_path = re.split(':|/|\n',domain_path)
    conn_port = int(uri_path[1])
    get_host_path = domain_path.replace((':'+(str(conn_port))),'')    
else:get_host_path = domain_path

if '/' in get_host_path:
    host_domain_name, get_req_path = get_host_path.split("/", 1)
    domain_path = host_domain_name

for value in domain_path.split('/'):
    try: 
        host_name, aliases, addresses  = socket.gethostbyname_ex(value)
    except socket.gaierror: continue

if len(conn_port)<=0:
    if len(protocol_in_use)>0:
        serv_port = socket.getservbyname(protocol_in_use)
    else:serv_port = 443
else: serv_port = conn_port

print("Your URL = ", get_host_path)
print("Your URL_PATH = ", get_req_path)
print("Your Host_Name = ", host_name)
print(' ')

#SSL Connection
if len(get_req_path)<=0:
    get_request = (f'GET / HTTP/1.1\r\nHost: {host_name}\r\n\r\n')
else: get_request = (f'GET /{get_req_path} HTTP/1.1\r\nHost: {host_name}\r\n\r\n')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s_ssl = context.wrap_socket(s, server_hostname = host_name)
s_ssl.connect((host_name, serv_port))
s_ssl.send(get_request.encode())

#Receiving_data

while True:
    new_data = s_ssl.recv(1024).decode('utf-8')
    if not new_data:
        break
    result += new_data

href_links = []
src_links = []
srcset_links = []

#Fetching URL
href_links_data = re.findall("href=[\"\'](.*?)[\"\']", result)
for value in href_links_data:
    if value not in href_links:
        href_links.append(value)
src_links_data =  re.findall("src=[\"\'](.*?)[\"\']", result)
for value in src_links_data:
    if value not in src_links:
        src_links.append(value)
srcset_links = re.findall("srcset=[\"\'](.*?)[\"\']", result)
srcset_links_clean = []
srcset_links_squeakyclean = []

for i in srcset_links:
    srcset_links_clean.extend(i.split())
for i in srcset_links_clean:     
    if '://' in i:
        srcset_links_squeakyclean.append(i)

def url_check(url_i):
    with open('mal_data_url.txt') as file:
        if url_i in file.read():
            return True

def print_url(url_i):
    for index, value in enumerate(url_i):
        if url_check(value):
            if protocol_in_use in value:
                print(f"{index}:{bcolors.WARNING}<Malicious link found> {value}{bcolors.ENDC}")
        elif protocol_in_use in value:
            print(f"{index}:{bcolors.OKGREEN}<CLEAN> {value}{bcolors.ENDC}")
        else: print(f"{index}:{bcolors.OKGREEN}<CLEAN> {protocol_in_use}://{host_name}{value}{bcolors.ENDC}")

print(f"{bcolors.UNDERLINE}Hypertext_REFerence_Links{bcolors.ENDC}")
print_url(href_links)
print(' ')
print(f"{bcolors.UNDERLINE}Source_Links{bcolors.ENDC}")
print_url(src_links)
print(' ')
print(f"{bcolors.UNDERLINE}Source_Set_Links{bcolors.ENDC}")
print_url(srcset_links_squeakyclean)
print(' ')

#Writing_received_data

fh = open('page.html', 'w', encoding='utf-8') 
head, body= result.split('<!DOCTYPE html>', 1)
fh.write("<!DOCTYPE html>"+body)
fh.close()

print("## Retrived HTML file(Page.html) and mal_data_url.txt are available in C:\\Users\\<Current User>\\")