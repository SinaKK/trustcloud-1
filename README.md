##Directories:

__certs:__ store clients certificates and private keys

__files:__ store the clients' data files 

__trustcloud:__ root folder of the trustcloud server

    __/certs:__ store the certificates files that were uploaded by clients



##trustcloud

__Sample running command:__

java Server 8000 server.jks password

java Client client.jks password -h 192.168.1.1:8000 -a files/file1

java Client client.jks password -h 192.168.1.1:8000 -u certs/Aole.crt


## TODO & Problems

__-a:__

    * what to do when server already has the file that the client is trying to upload

__-f:__

    * download file with -c option

__-u:__

    * does the server need to store the certificate file, or is it enough to just store the Certificate
        object in its inner data structure

__-v:__

    * when file does not exist
    * when certificate is not stored in server
    * when certificate is stored in server
    * ??when certificate public key and the private key does not match
    * do we store each digital signature in a file? or just store in inner data structure e.g. String

__states saving:__

    * saving states when server terminate, or
    * saving, rewrite the whole data structure at each all, or
    * saving, append writing each acticity

__comments__

__format__

__EXCEPTION HANDLING__

