Files Submitted: basic_handshake.py
Description: File transfer using tls

TLS handshake over the previous assignment is done here. the following is an overview of what functions are present and which cypher suite was used.
Cipher Suite: SRP-SHA3-256-RSA-AES-256-CBC-SHA3-256.
Implemented setting up ttp, signing rsa key and sending pub key for the trusted third party(ttp). 
Gnnerating public and private key, ecrypting and decrypting using the key(rsa). 
Sending key/sign request to ttp and overall implemented a whole TLS handshake protocol over the previous assignment protocol

The problem is solved in full.

Libraries used: Sympy - for prime related work
		Random - to generate random num
		os - generate random byte
		socket - for communicating between client and server
		cryptography - for hashing, and AES

