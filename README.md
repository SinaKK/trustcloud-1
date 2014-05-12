##Directories:

certs: store clients certificates and private keys

files: store the clients' data files 

trustcloud: root folder of the trustcloud server
    /certs: store the certificates files that were uploaded by clients



##trustcloud

Sample running command:

java Server 8000 server.jks password

java Client client.jks password -h 192.168.1.1:8000 -a files/file1

java Client client.jks password -h 192.168.1.1:8000 -u certs/Aole.crt

