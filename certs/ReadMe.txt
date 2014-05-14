openssl genrsa -out A.key 1024

    // convert to java read format
    
    // openssl pkcs8 -topk8 -nocrypt -outform DER < $1.key > $1.pk8

openssl req -new -key A.key -out A.r

    // fill in information of A's identity


openssl x509 -req -days 500 -set_serial 01 -CA issuer.crt -CAkey issuer.key -in A.r -out A.crt
    
    // -set_serial should be unique if CA is the same
    
    // openssl x509 -req -days 500 -in self.r -signkey self.key -out self.crt


The rings:  (A -> B:  A signs B)

    
    6: Aole -> Baro -> Ceru -> Dudu -> Eure -> Firo -> Aole

    5: Guru -> Hita -> Ioie -> Jade -> Kuro -> Guru

    4: Lala -> Mimi -> Nono -> Oare -> Lala

    3: Picu -> Qipa -> Ruso -> Picu

    2: Siya -> Tada -> Siya

    1: Uiki -> Uiki


