# Zero Trust Project

## Overview

![](https://github.com/WWUZeroTrust/WWUZeroTrust.github.io/blob/master/image/Flowchart.png "ZTN Flowchart")

## Setup

We installed these tools on four different computers and our instructions will reflect that. This is 'Trust Engine and Kolide + ELK Stack Server', 'OPA and Swissknife Handler', 'Network Agent', and Client machine.

### Trust Engine and Kolide + ELK Stack Server

#### Generate Certificates
Kolide Fleet server needs to be configured to use TLS certificates for communication with Osquery agents. These certificates should be generated and placed within the `kolide/certs` directory.
1. `openssl genrsa -out server.key 4096`
2. `openssl req -new -key server.key -out server.csr`
3. `openssl x509 -req -days 366 -in /tmp/server.csr -signkey server.key -out server.cert`
The `server.cert` certificate will automatically be appended to the Kolide containers's `/etc/ssl/certs/ca-certificates.crt` trusted certificate list during its startup.



#### Configure Environment Variables
A number of environment variables need to be set prior to executing `setup.sh`.
1. `export ELK_VERSION=7.6.2`
2. `export MYSQL_PASS=mysqlpass`
3. `export REDIS_PASS=redispass`
4. `export JWT_KEY=jwtkey`
5. `export ELASTIC_PASS=elasticpass`

#### Run Startup Script
`chmod +x setup.sh && ./setup.sh`

#### Configure Kolide
Kolide needs to be configured after it's container has been launched. Access the Kolide server via `https://kolideserver:8080/` and follow the setup instructions.

### Add Osquery Query Packs
No query packs are installed by default on Kolide. To add query packs to Kolide you'll need to download the fleetctl binary from `https://github.com/kolide/fleet/releases` to your workstation.

Add the generated `server.cert` to your trusted certificate keystore otherwise fleetctl will produce TLS errors while trying to communicate with Kolide. Download the Osquery query pack to the same folder as fleetctl and then run the following:
1. `fleetctl config set --address https://kolideserver:8080`
2. `fleetctl login`
3. `fleetctl apply -f querypack.yaml`
If step 3 does not work as it didn't for us, you can manually add the queries and query packs on the Kolide UI.

Verify that you can see the installed query pack on the Kolide web interface.

### Pushing certs, key and osquery flags to Client Machines
1. Pull the osquery.flags file under Zero_Trust_Project/ELK-Kolide-Osquery-Portainer/osqueryfiles

2. Ensure the following options are set within the osquery.flags file
    --enroll_secret_path=/etc/osquery/enroll_secret
    --tls_server_certs=/etc/osquery/localhost_8080.pem
    --tls_hostname=192.168.1.101
    --host_identifier=hostname
    --enroll_tls_endpoint=/api/v1/osquery/enroll
    --config_plugin=tls
    --config_tls_endpoint=/api/v1/osquery/config
    --config_refresh=10
    --disable_distributed=false
    --distributed_plugin=tls
    --distributed_interval=3
    --distributed_tls_max_attempts=3
    --distributed_tls_read_endpoint=/api/v1/osquery/distributed/read
    --distributed_tls_write_endpoint=/api/v1/osquery/distributed/write
    --logger_plugin=tls
    --logger_tls_endpoint=/api/v1/osquery/log
    --logger_tls_period=10

3. On Trust Engine start Kolide Fleet server with command: 
    $ sudo systemctl start fleet 

4. Browse to https://kolideserver:8080 on Host and login to Kolide Fleet 

5. Click on add host and download Fleet Certificate and move from Downloads into the osqueryfiles directory

6. Create a file called enroll_secret and paste the contents of the enroll secret field on this Fleet webpage  

7. Install open ssh server with the following command
    $ sudo apt-get install openssh-server

8. Ensure that the Client has the ssh port open with: 
    $ sudo ufw allow 22 

9. Run the following command to copy the contents of the osqueryfiles directory from the Trust Engine Host to the Client in /tmp: 
    $ sudo scp –r <LOCATION_OF_DIRECTORY_ON_HOST>/osqueryfiles <CLIENT_USERNAME>@<IP_ADDRESS>:/tmp 

10. Move the files on the Client from /tmp into /etc/osquery/ on the Client with the following command:
    $ sudo mv /tmp/osqueryfiles/* /etc/osquery/

11. Run osqueryd on the Client with the following command: 
    $ sudo osqueryd –flagfile=/etc/osquery/osquery.flags 

### OPA and Swissknife Handler
curl -X POST http://localhost:8181/v1/data/myapi/policy/allow --data-binary '{ "input": { "user": "Sam", "access": "read", "object":"server123", "score":"90" } }'
curl -X POST -H "Content-Type: application/json" -d '{"input": {"user": "Sam", "access": "read", "object":"server123", "score":"90"}}' localhost:8181/v1/data/authz/allow

## Network Agent
Within the folder there is a .env file which will have to be edited to add passwords for MariaDB and other systems that are being used for this project. 

The docker-compose file is comprised of containers and configuration from two different places.

The first is the Wodby Docker4Wordpress stack of containers located here:
https://github.com/Wodby/docker4wordpress

With setup instructions for this, if necessary, located here:
https://wodby.com/docs/stacks/wordpress/local/#usage

The second is the Authelia docker-compose file located here:
https://github.com/authelia/authelia/tree/master/compose/local

This link above also gives examples of the user database file and configuration. 

## Ideas for adding onto this project

- Add caching to the Handler and Trust Engine to ensure it only runs once
- Add more fields to Trust Engine to get more accurate scores
- Change the scoring method to better suit particular fields
- Implement IDS system with endpoint monitoring to add to logs going to the ELK stack
- Implement LDAP system to integrate with Authelia 
- Containerize all the systems and programs so that they can all be spun up quickly and easily


## Sources:
Kolide + ELK Stack 
https://github.com/Hart-Open-Source/ELK-Kolide-Osquery
