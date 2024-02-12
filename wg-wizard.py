from collections import OrderedDict
import json
import os
import pathlib
import re
import subprocess
import sys
import time

program_path = pathlib.Path(__file__).absolute()
program_config_path = program_path.with_suffix('.json')
max_peers = 253
docker_config_path = pathlib.Path("/etc/docker/daemon.json")
wireguard_config_path = pathlib.Path(os.path.expanduser('~' + os.getlogin())) /  'wireguard'
docker_run_template = 'sudo docker run -d -p 51820:51820/udp {publish} -e PUID="{puid}" -e PGID="{pgid}" -e TZ="$(cat /etc/timezone)" -e SERVERURL=auto -e SERVERPORT=51820 -e PEERS="{peers}" -e PEERDNS=auto -e INTERNAL_SUBNET=10.13.13.0 -e ALLOWEDIPS=0.0.0.0/0 -e PERSISTENTKEEPALIVE_PEERS="" -e LOG_CONFS=false -v "{config_path}":/config --cap-add=NET_ADMIN --cap-add=SYS_MODULE --name=wireguard --restart=unless-stopped linuxserver/wireguard:latest'
wg0_postup_template = "iptables -t nat -A PREROUTING -i eth+ -p {protocol} --dport {port_range} -j DNAT --to-destination {ip}"
wg0_postdown_template = "iptables -t nat -D PREROUTING -i eth+ -p {protocol} --dport {port_range} -j DNAT --to-destination {ip}"

def print_info(msg):
    print(f"\033[34m{msg}\033[0m")

def print_warn(msg):
    print(f"\033[33m{msg}\033[0m")

def print_error(msg):
    print(f"\033[31m{msg}\033[0m")

def verify_config(dict_obj):
    if len(dict_obj) > max_peers:
        print_error(f"The number of peers cannot exceed {max_peers}.")
        return False

    used_tcp_ports = set()
    used_udp_ports = set()

    for peer, forward_rules in dict_obj.items():
        if not re.match(r"^[A-Za-z0-9]+$", peer):
            print_error(f"'{peer}' is an invalid peer name. Only alphabetic characters and numbers are allowed.")
            return False
        if not isinstance(forward_rules, list):
            print_error(f"Forward rules of '{peer}' must be in [].")
            return False
        for forward_rule in forward_rules:
            if not isinstance(forward_rule, dict):
                print_error(f"Each forward rule of '{peer}' must be defined within {{}}.")
                return False
            if not all([e in forward_rule.keys() for e in ['protocol', 'port-range']]):
                print_error("Every forward rule must contain the following keys: protocol, port-range")
                return False
            for key, value in forward_rule.items():
                if key == 'protocol':
                    if value not in ['tcp', 'udp']:
                        print_error("The value for key 'protocol' must be tcp or udp.")
                        return False
                elif key == 'port-range':
                    if re.match(r"^[0-9]+-[0-9]+$", value):
                        start_port = int(value.split('-')[0])
                        end_port = int(value.split('-')[1])
                        if start_port not in range(0, 65536):
                            print_error("The value for key 'port-range' is invalid. start_port must be an integer between 0 and 65535.")
                            return False
                        if end_port not in range(0, 65536):
                            print_error("The value for key 'port-range' is invalid. end_port must be an integer between 0 and 65535.")
                            return False
                        if start_port == end_port:
                            print_warn("The value for key 'port-range' has the same start_port and end_port. If start_port and end_port are the same, it is recommended to express them as a single integer.")
                            dict_obj[peer][dict_obj[peer].index(forward_rule)]['port-range'] = str(start_port)
                        if start_port > end_port:
                            print_error("The value for key 'port-range' is invalid. end_port must be greater than start_port.")
                            return False
                        if forward_rule['protocol'] == 'tcp':
                            if len(used_tcp_ports.intersection(set(range(start_port, end_port + 1)))) > 0:
                                print_error("The value for key 'port-range' is invalid. An attempt was made to reuse a tcp port that has already been used.")
                                return False
                            else:
                                used_tcp_ports.update(range(start_port, end_port + 1))
                        elif forward_rule['protocol'] == 'udp':
                            if len(used_udp_ports.intersection(set(range(start_port, end_port + 1)))) > 0:
                                print_error("The value for key 'port-range' is invalid. An attempt was made to reuse a udp port that has already been used.")
                                return False
                            else:
                                used_udp_ports.update(range(start_port, end_port + 1))
                        else:
                            print_error("The value for key 'protocol' must be tcp or udp.")
                            return False
                    elif value.isdecimal():
                        single_port = int(value)
                        if single_port not in range(0, 65536):
                            print_error("The value for key 'port-range' is invalid. Must be an integer between 0 and 65535.")
                            return False
                        if forward_rule['protocol'] == 'tcp':
                            if single_port in used_tcp_ports:
                                print_error("The value for key 'port-range' is invalid. An attempt was made to reuse a tcp port that has already been used.")
                                return False
                            else:
                                used_tcp_ports.add(single_port)
                        elif forward_rule['protocol'] == 'udp':
                            if single_port in used_udp_ports:
                                print_error("The value for key 'port-range' is invalid. An attempt was made to reuse a udp port that has already been used.")
                                return False
                            else:
                                used_udp_ports.add(single_port)
                        else:
                            print_error("The value for key 'protocol' must be tcp or udp.")
                            return False
                    else:
                        print_error("The value of key 'port-range' must be an integer between 0 and 65535 or a port range in the format start_port-end_port.")
                        return False
                else:
                    print_warn(f"An unnecessary key '{key}' exists in the forward rule of {peer}.")

    return True

if not program_config_path.is_file():
    print_error(f"{str(program_config_path)} file cannot be found.")
    sys.exit(1)

with program_config_path.open('r', encoding='utf-8') as f:
    program_config_dict = json.load(f, object_pairs_hook=OrderedDict) or OrderedDict()

# Verify program_config_dict
if not verify_config(program_config_dict):
    sys.exit(1)

# Configure ufw firewall
if subprocess.run("which ufw".split(), stdout = subprocess.DEVNULL).returncode == 0:
    print_info("ufw was found. I'm going to reset the firewall and set it up from scratch.")

    subprocess.run("sudo ufw disable".split(), check=True, stdout = subprocess.DEVNULL)
    subprocess.run("sudo ufw --force reset".split(), check=True, stdout = subprocess.DEVNULL)
    subprocess.run("sudo ufw default deny incoming".split(), check=True, stdout = subprocess.DEVNULL)
    subprocess.run("sudo ufw default allow outgoing".split(), check=True, stdout = subprocess.DEVNULL)

    ss_output = subprocess.run("sudo ss -nlptu".split(), check=True, stdout=subprocess.PIPE).stdout.decode()
    grep_sshd = [e for e in ss_output.split('\n') if 'sshd' in e]
    awk_print_5 = [e.split()[4] for e in grep_sshd]
    sshd_ports = list(set([e.rpartition(':')[2] for e in awk_print_5]))

    if len(sshd_ports) > 0:
        print_info(f"It seems that the ssh server is using the following port. {sshd_ports}")
        
        for port in sshd_ports:
            subprocess.run(f"sudo ufw allow {port}/tcp".split(), check=True, stdout = subprocess.DEVNULL)

    subprocess.run("sudo ufw allow 51820/udp".split(), check=True, stdout = subprocess.DEVNULL)

    for forward_rules in program_config_dict.values():
        for forward_rule in forward_rules:
            subprocess.run(f"sudo ufw allow {forward_rule['port-range'].replace('-', ':')}/{forward_rule['protocol']}".split(), check=True, stdout = subprocess.DEVNULL)

    subprocess.run("sudo ufw --force enable".split(), check=True, stdout = subprocess.DEVNULL)

    print(subprocess.run("sudo ufw show added".split(), check=True, stdout=subprocess.PIPE).stdout.decode())
else:
    print_info("ufw was not found. I will skip setting up the firewall.")

# Install docker
if subprocess.run("which docker".split(), stdout = subprocess.DEVNULL).returncode == 0:
    print_info("Docker was found. I will skip installing docker.")
else:
    print_info("Docker was not found. I'm going to install docker.")

    subprocess.run("""
DEBIAN_FRONTEND=noninteractive

for pkg in docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc; do sudo apt-get remove -y $pkg; done

sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
""".strip(), check=True, shell=True)

# Apply tweak to Docker
if docker_config_path.is_file():
    with docker_config_path.open('r', encoding='utf-8') as f:
        docker_config_dict = json.load(f, object_pairs_hook=OrderedDict) or OrderedDict()
else:
    docker_config_dict = OrderedDict()

if 'userland-proxy' not in docker_config_dict or docker_config_dict['userland-proxy'] == True:
    print_info("I will apply a tweak to prevent docker from using the userland proxy.")
    
    docker_config_dict['userland-proxy'] = False

    with docker_config_path.open('w', encoding='utf-8') as f:
        json.dump(docker_config_dict, f, indent=2, sort_keys=False)

    subprocess.run("sudo systemctl restart docker.service".split(), check=True, stdout = subprocess.DEVNULL)
else:
    print_info("The tweak is already applied to docker.")

# Run wireguard server
wireguard_config_path.mkdir(exist_ok=True, parents=False)

with os.scandir(wireguard_config_path) as it:
    if any(it):
        print_warn("There is an existing configuration for the wireguard server. Updating your current settings is not guaranteed and may conflict with your existing settings.")

docker_run_publish = []

for forward_rules in program_config_dict.values():
    for forward_rule in forward_rules:
        docker_run_publish.append(f"-p {forward_rule['port-range']}:{forward_rule['port-range']}/{forward_rule['protocol']}")

docker_run = docker_run_template.format(publish=' '.join(docker_run_publish), puid=f"$(id -u {os.getlogin()})", pgid=f"$(id -g {os.getlogin()})", peers=','.join(program_config_dict.keys()), config_path=str(wireguard_config_path))

print_info("I'm going to run the wireguard server using the following command.")
print(docker_run)

subprocess.run("sudo docker stop wireguard".split(), stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
subprocess.run("sudo docker rm wireguard".split(), stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
subprocess.run(docker_run, check=True, shell=True, stdout = subprocess.DEVNULL)

# Edit wg0.conf
wg0_config_path = wireguard_config_path / "wg_confs/wg0.conf"
start_time = time.time()

while not wg0_config_path.is_file():
    if (time.time() - start_time) >= 15:
        print_error(f"{str(wg0_config_path)} file cannot be found.")
        exit(1)
    time.sleep(1)

print_info("I will add forward rules to the wireguard server.")

wg0_config = []

with wg0_config_path.open('r', encoding='utf-8') as f:
    for line in f:
        line = line.strip()

        if re.match("^PostUp *=", line, re.I):
            temp = []
            temp.append("PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth+ -j MASQUERADE")

            for i, (peer, forward_rules) in enumerate(program_config_dict.items()):
                for forward_rule in forward_rules:
                    temp.append(wg0_postup_template.format(protocol=forward_rule['protocol'], port_range=forward_rule['port-range'].replace('-', ':'), ip=f"10.13.13.{str(i+2)}"))

            wg0_config.append('; '.join(temp))
        elif re.match("^PostDown *=", line, re.I):
            temp = []
            temp.append("PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth+ -j MASQUERADE")

            for i, (peer, forward_rules) in enumerate(program_config_dict.items()):
                for forward_rule in forward_rules:
                    temp.append(wg0_postdown_template.format(protocol=forward_rule['protocol'], port_range=forward_rule['port-range'].replace('-', ':'), ip=f"10.13.13.{str(i+2)}"))

            wg0_config.append('; '.join(temp))
        else:
            wg0_config.append(line)

with wg0_config_path.open('w', encoding='utf-8') as f:
    f.write('\n'.join(wg0_config))

subprocess.run("sudo docker restart wireguard".split(), check=True, stdout = subprocess.DEVNULL)

# Generate auto setup scripts
print_info("I will create auto setup scripts. If you run the generated python script with administrator privileges, it will connect to the wireguard server.")

for peer, forward_rules in program_config_dict.items():
    auto_setup_script = []

    auto_setup_script.append('''
import concurrent.futures
import configparser
import pathlib
import random
import re
import socket
import subprocess
import urllib.error
import urllib.request

wg0_config = configparser.ConfigParser()
'''.strip())

    with pathlib.Path(wireguard_config_path / f"peer_{peer}/peer_{peer}.conf").open('r', encoding='utf-8') as f:
        auto_setup_script.append(f"wg0_config.read_string({repr(f.read())})")

    auto_setup_script.append(f"forward_rules = {json.dumps(forward_rules, indent=2, sort_keys=False)}")

    auto_setup_script.append('''
wg0_postup_template = "ip rule add sport {port} table main"
wg0_postdown_template = "ip rule del sport {port} table main"
wg0_config_path = pathlib.Path("/etc/wireguard/wg0.conf")
ip_test_api = "https://checkip.amazonaws.com"
tcp_port_test_api = "https://check-host.net/check-tcp?host={address}&max_nodes=3"
udp_port_test_api = "https://check-host.net/check-udp?host={address}&max_nodes=3"
wg0_service_path = pathlib.Path("/etc/systemd/system/wg0.service")

def print_info(msg):
    print(f"\\033[34m{msg}\\033[0m")

def print_warn(msg):
    print(f"\\033[33m{msg}\\033[0m")

def print_error(msg):
    print(f"\\033[31m{msg}\\033[0m")

def test_tcp_port(ip, port):
    def sock_accept(sock):
        con, addr = sock.accept()
        con.close()
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', int(port)))
        sock.listen()
        
        future = executor.submit(sock_accept, sock)

        req = urllib.request.Request(tcp_port_test_api.format(address=f"{ip}:{port}"))
        req.add_header('Accept', 'application/json')
        req.add_header('User-Agent', 'curl/7.81.0')

        try:
            response = urllib.request.urlopen(req, timeout=10)
            response.close()
        except (urllib.error.URLError, urllib.error.HTTPError):
            print_error("API used in tcp port test appears to be unavailable.")
            sock.close()
            return False

        try:
            future.result(timeout=15)
            return True
        except concurrent.futures.TimeoutError:
            return False
        finally:
            sock.close()

def test_udp_port(ip, port):
    def sock_recvfrom(sock):
        data, addr = sock.recvfrom(1024)
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', int(port)))
        
        future = executor.submit(sock_recvfrom, sock)

        req = urllib.request.Request(udp_port_test_api.format(address=f"{ip}:{port}"))
        req.add_header('Accept', 'application/json')
        req.add_header('User-Agent', 'curl/7.81.0')

        try:
            response = urllib.request.urlopen(req, timeout=10)
            response.close()
        except (urllib.error.URLError, urllib.error.HTTPError):
            print_error("API used in udp port test appears to be unavailable.")
            sock.close()
            return False

        try:
            future.result(timeout=15)
            return True
        except concurrent.futures.TimeoutError:
            return False
        finally:
            sock.close()

# Install wireguard
if subprocess.run("which wg-quick".split(), stdout = subprocess.DEVNULL).returncode == 0:
    print_info("wg-quick was found. I will skip installing wireguard.")
else:
    print_info("wg-quick was not found. I'm going to install wireguard.")

    subprocess.run("""
DEBIAN_FRONTEND=noninteractive

sudo apt update
sudo apt install -y wireguard resolvconf
""".strip(), check=True, shell=True)

# Write peer profile
print_info(f"I will write the peer profile included in this script to the following path. {wg0_config_path}")

ss_output = subprocess.run("sudo ss -nlptu".split(), check=True, stdout=subprocess.PIPE).stdout.decode()
grep_sshd = [e for e in ss_output.split('\\n') if 'sshd' in e]
awk_print_5 = [e.split()[4] for e in grep_sshd]
sshd_ports = list(set([e.rpartition(':')[2] for e in awk_print_5]))

if len(sshd_ports) > 0:
    print_info(f"It seems that the ssh server is using the following port. {sshd_ports}")
    print_info("I will exclude all packets going out of the ssh port from entering the wireguard server so that you can make an ssh connection to this computer from the internal network.")

    wg0_config['Interface']['PostUp'] = '; '.join([wg0_postup_template.format(port=port) for port in sshd_ports])
    wg0_config['Interface']['PostDown'] = '; '.join([wg0_postdown_template.format(port=port) for port in sshd_ports])

with wg0_config_path.open('w', encoding='utf-8') as f:
    wg0_config.write(f)

# Connect to the wireguard server
print_info("Now, I will connect this computer to the wireguard server.")

subprocess.run("sudo wg-quick down wg0".split(), stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
subprocess.run("sudo wg-quick up wg0".split(), check=True, stdout = subprocess.DEVNULL)

# Test external IP
try:
    with urllib.request.urlopen(ip_test_api, timeout=10) as response:
        response_html = response.read().decode(response.headers.get_content_charset())
except (urllib.error.URLError, urllib.error.HTTPError, TypeError):
    print_error("API used in IP test appears to be unavailable.")
    exit(1)

wg_server_ip = wg0_config['Peer']['Endpoint'].rpartition(':')[0]

if wg_server_ip in response_html:
    print_info("Test passed. Your external IP is the wireguard server's IP.")
else:
    print_error("Test failed. Your external IP is different from the wireguard server's IP.")
    print_error("There seems to be a problem with automatic setup. If you find a bug, please report it.")
    exit(1)

# Test port forwarding
if len(forward_rules) == 0:
    print_info("There are no forwarding rules defined for this peer, so I will skip the port forwarding test.")
else:
    print_info("Testing all ports is time-consuming and inefficient, so I will choose one representative port to test.")

    selected_forward_rule = random.choice(forward_rules)

    if '-' in selected_forward_rule['port-range']:
        selected_port = random.randint(*map(int, selected_forward_rule['port-range'].split('-')))
    else:
        selected_port = selected_forward_rule['port-range']

    if selected_forward_rule['protocol'] == 'tcp':
        port_test_result = test_tcp_port(wg_server_ip, selected_port)
    elif selected_forward_rule['protocol'] == 'udp':
        port_test_result = test_udp_port(wg_server_ip, selected_port)
    else:
        raise NotImplementedError(f"Processing for {selected_forward_rule['protocol']} protocol is not implemented.")
    
    if port_test_result:
        print_info(f"Test passed. {selected_forward_rule['protocol']} port {selected_port} is accessible from outside.")
    else:
        print_error(f"Test failed. {selected_forward_rule['protocol']} port {selected_port} is NOT accessible from outside.")
        print_error("There seems to be a problem with automatic setup. If you find a bug, please report it.")
        exit(1)

# Register wireguard as a systemd service
print_info("I will add wireguard as a systemd service in order to connect to the wireguard server when the system restarts.")

with wg0_service_path.open('w', encoding='utf-8') as f:
    f.write("""
[Unit]
Description=wg0
After=network-online.target

[Service]
ExecStart=/usr/bin/wg-quick up wg0
Type=oneshot
RemainAfterExit=yes
ExecStop=/usr/bin/wg-quick down wg0

[Install]
WantedBy=multi-user.target
""".strip())

subprocess.run("sudo systemctl enable wg0.service".split(), check=True, stdout = subprocess.DEVNULL)

print_info("This is the end of the automatic setup script.")
'''.strip())

    with program_path.with_name(f"auto-setup-{peer}.py").open('w', encoding='utf-8') as f:
        f.write('\n'.join(auto_setup_script))
        print_info(f"{f.name} file has been created.")

print_info("This is the end of the script.")
