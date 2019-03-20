openssl ecparam -name secp384r1 -genkey -out key.pem

sudo openssl req -batch -new -x509 -key key.pem -nodes -sha256 \
  -subj /CN=example.com/O=oreore -days 3650 \
  -out cert.pem