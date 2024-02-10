# wg-wizard
Port forwarding under CGNAT can be tricky.
The series of steps to configure your VPS as a wireguard server with port forwarding rules, connect from any client to the wireguard server, and then test whether the port forwarding actually works is very annoying.
You can save yourself the hassle by editing wg-wizard.json file to define the peer list and forwarding rules and simply running the auto-configuration script(wg-wizard.py).
This auto-configuration script is assumed to work on apt-based Linux and has been tested on Ubuntu 22.04.
Once your server is configured successfully, auto setup script(auto-setup-#.py) will be generated for your client. Upload this script to your client and run it client-side.

## How do I use it?
```
# On your server
curl -O "https://raw.githubusercontent.com/Bo26fhmC5M/wg-wizard/main/{wg-wizard.py,wg-wizard.json}"
# Edit the json file before running the script.
sudo python3 wg-wizard.py
# auto-setup-#.py will be generated in the same directory. Upload this script to your client
# On your client
sudo python3 auto-setup-#.py
```
