#! /bin/sh

# key set A
openssl genrsa -out a.key 2048
openssl rsa -in a.key -pubout -out a.pub

# key set B
openssl genrsa -out b.key 2048
openssl rsa -in b.key -pubout -out b.pub

# passphrased key
echo -n helloworld | openssl rsa -des3 -passout stdin -in a.key -out a_helloworld.key

# encrypts
echo -n encrypted lolcats | openssl rsautl -encrypt -pubin -inkey a.pub -out encrypted.txt
echo -n lolcats with oaep | openssl rsautl -encrypt -pubin -inkey a.pub -oaep -out encrypted_oaep.txt

# signatures
echo -n signed lolcats | openssl rsautl -sign -inkey a.key -out signed.txt
echo -n lolcats with x9.31 | openssl rsautl -sign -inkey a.key -x931 -out signed_x931.txt
