# wg-wizard
Port forwarding under CGNAT can be tricky.
The series of steps to configure your VPS as a wireguard server with port forwarding rules, connect from any client to the wireguard server, and then test whether the port forwarding actually works is very annoying.
You can save yourself the hassle by editing wg-wizard.json file to define the peer list and forwarding rules and simply running the auto-configuration script(wg-wizard.py).
This auto-configuration script has been tested on Ubuntu 22.04.

## Requirements
- Ubuntu 18+
- Python 3.6+

## Quick start
- Once your server is configured successfully, auto setup script(auto-setup-#.py) for your client will be generated. Upload this script to your client and run it.
```
# On your server
curl -O "https://raw.githubusercontent.com/Bo26fhmC5M/wg-wizard/main/{wg-wizard.py,wg-wizard.json}"
# Edit wg-wizard.json before running wg-wizard.py script.
sudo python3 wg-wizard.py
# auto-setup-#.py will be generated in the same directory. Upload this script to your client
# On your client
sudo python3 auto-setup-#.py
```
