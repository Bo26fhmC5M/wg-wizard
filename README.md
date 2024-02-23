# wg-wizard
Configuring port forwarding under CGNAT can be challenging. It can be quite a hassle to install WireGuard on a VPS, configure the server with port forwarding rules, connect to the WireGuard server from a client, and then test the port forwarding. To avoid these inconveniences, you can edit the 'wg-wizard.json' file to define peers and automate the process by running the auto-configuration script 'wg-wizard.py'. The 'wg-wizard.py' has been tested on Ubuntu 22.04.

## Requirements
- Ubuntu 18+
- Python 3.6+

## Quick start
- Once your server is configured successfully, 'auto-setup-#.py' for your client will be generated. Upload this script to your client and run it.
```
# On your server
curl -O "https://raw.githubusercontent.com/Bo26fhmC5M/wg-wizard/main/{wg-wizard.py,wg-wizard.json}"
# Edit wg-wizard.json before running wg-wizard.py script.
sudo python3 wg-wizard.py
# auto-setup-#.py will be generated in the same directory. Upload this script to your client
# On your client
sudo python3 auto-setup-#.py
```
