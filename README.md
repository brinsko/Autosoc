## Repository Structure 

    Autosoc/
    ├── setup-server.sh          # Full server installer (its only install on server)
    ├── join-client.sh           # Client join script (only install on client)
    ├── README.md                # This file
    └── LICENSE                  # GNU General Public License v3


 ### On SERVER machine:
    1) wget https://raw.githubusercontent.com/brinsko/Autosoc/refs/heads/main/server-setup.sh && chmod +x server-setup.sh && ./server-setup.sh && cd /usr/local/bin && chmod +x setup-my-dns-and-logging-server.sh

    2) Auto dns setup -         /usr/local/bin/setup-my-dns-and-logging-server.sh 192.168.29.206 server.cst.com cst.com (server ip) (fqdn) (domain)

       add user       -        /usr/local/bin/add-client.sh client1 192.168.29.199 cst.com (client name) (client ip) (domain)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    For Block --             sudo /usr/local/bin/admin-block-client.sh block <client-ip>
    Unblock --           sudo /usr/local/bin/admin-block-client.sh unblock <client-ip>
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    For watch logs --     ls /var/log/remote
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# On every CLIENT (once)
    1) wget https://raw.githubusercontent.com/brinsko/Autosoc/refs/heads/main/join-client.sh && chmod +x join-client.sh && sudo ./join-client.sh && cd /usr/local/bin && chmod +x join-dns-and-enable-full-logging.sh

     command - /usr/local/bin/join-dns-and-enable-full-logging.sh 192.168.29.206 cst.com client1  (server ip) (domain) (client/host name)
# WARNING: If you (or admin) block the target machine from reaching the server → it will AUTO POWER OFF in 40 seconds (first time) or just 15 seconds (next times)! ⚠️⚠️⚠️⚠️
