## Repository Structure 

    Autosoc/
    ├── setup-server.sh          # Full server installer (its only install on server)
    ├── join-client.sh           # Client join script (only install on client)
    ├── README.md                # This file
    └── LICENSE                  # GNU General Public License v3


    ### On SERVER machine:
    2) wget
    3) chmod +x setup-server.sh
    4) Auto dns setup -         /usr/local/bin/setup-my-dns-and-logging-server.sh 192.168.29.206 server.cst.com cst.com (server ip) (fqdn) (domain)

       add user       -        /usr/local/bin/add-client.sh client99 192.168.29.199 cst.com (client name) (client ip) (domain)

------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    For Block --             sudo /usr/local/bin/admin-block-client.sh block <client-ip>
    Unblock --           sudo /usr/local/bin/admin-block-client.sh unblock <client-ip>
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
    For watch logs --     ls /var/log/remote
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# On every CLIENT (once)
    1) cd /usr/local/bin 
    2) wget https://raw.githubusercontent.com/brinsko/Insoc/main/join-client.sh -O join-client.sh
