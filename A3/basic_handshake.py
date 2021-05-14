#!/usr/bin/env python3

##### IMPORTS

# Good news: there's no need to include a2.py with your submission! The auto-grader has copies
#   of all these functions:
import os

from a2 import b2i, bytes_to_int, calc_A, calc_B, calc_K_client, calc_K_server, calc_M1, calc_M2, calc_u, calc_x
from a2 import client_prepare, client_register, close_sock, create_socket, i2b, int_to_bytes, prim_root, receive
from a2 import safe_prime, send, server_register, split_ip_port

import argparse

import socket
from sys import exit

from threading import Thread
from time import sleep
from typing import Mapping, Optional, Union
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from sympy import ntheory
from cryptography.hazmat.primitives import padding, ciphers, hmac, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
# Bad news: anything imported for those functions won't be included here, so you'll
#  still need to do the usual imports. Insert them here.


##### METHODS

# this has to be here for globals() to work as intended
def varprint( data, label, source="Client" ):
    """A helper for printing out data."""
    global args

    if not (('args' in globals()) and args.verbose):
        return

    if label is not None:
        middle = f"{label} = "
    else:
        middle = ""

    if type(data) == bytes:
        print( f"{source}: Received {middle}<{data.hex()}>" )
    else:
        print( f"{source}: {middle}{data}" )


##### CLASSES

class DH_params:
    """Contains the two critical parameters for Diffie-Hellman key exchange.
       Makes it easier to pass into functions.

       Some examples of how to use this class:
       > DH     = DH_params()
       > DH2    = DH_params( pair=(DH.N, DH.g) )
       > DH_len = DH.bytes
       """

    def __init__(self, pair: Optional[tuple[int,int]]=None, bits: int=512):
        """Create a DH_params object, either on-the-fly or from existing values.

        PARAMETERS
        ==========
        pair: If creating from existing values, supply them in the form (N,g)
            where N is the safe prime and g is a primitive root of said prime,
            both of which are ints. If this isn't a two-item tuple, new values
            will be generated.
        bits: The number of bits to use when generating N and g. Only used when
            generating an N,g pair, as it can be inferred from the input.

        WARNING: Minimal error checking is done!
        """

        if (type(pair) is tuple):

            # we should be testing N and g here, but that would ruin the point
            #  of the assignment
            self.N, self.g = pair
            self.bits = self.N.bit_length()

        else:

            self.N = safe_prime( bits )
            self.g = prim_root( self.N )

        # keep these around for book-keeping
        self.k     = calc_u( self.N, self.g )  # same calculation!
        self.bits  = bits
        self.bytes = (bits + 7) >> 3            # round up

        assert self.N > self.g

    def calc_A(self, a: Union[int,bytes]) -> int:
        """Just a thin wrapper around calc_A()."""

        return calc_A( self.N, self.g, a )

    def calc_B(self, b: Union[int,bytes], v: Union[int,bytes]) -> int:
        """Just a thin wrapper around calc_B()."""

        return calc_B( self.N, self.g, b, self.k, v )


class RSA_key:
    """Represents an RSA modulus and keypair within the system. Makes it easier
       to generate and share these values, and gives a clean interface for
       signing and encrypting/decrypting."""

    def __init__(self, pubkey: Optional[tuple[int,int]]=None, bits: int=1024):
        """Create an RSA_key object.

        PARAMETERS
        ==========
        pubkey: Optional, allows you to use a public key transmitted to you. If 
           provided it must be a tuple of the form (N,e), where both are 
           integers.
        bits: The number of bits to use for the modulus. Used when generating
           values only, ignored otherwise.

        EXAMPLES
        ========
        > key        = RSA_key()
        > server_key = RSA_key( pubkey=(N,e) )

        WARNING: Minimal error checking is done!
        """

        # check if we were given the proper values
        if (type(pubkey) is tuple):

            # these two values should be tested for validity, in a real
            #  implementation
            self.N, self.e = pubkey

            # fill in the missing values with None, as flags
            self.p = None
            self.q = None
            self.d = None

            # we can calculate this value from N
            self.bits = self.N.bit_length()

        # not in public key mode? Generate a full key
        else:
            self.p, self.q = self.modulus( bits )
            self.N         = self.p * self.q
            self.e, self.d = self.keypair( self.p, self.q )

            self.bits = bits

        self.bytes = (self.bits + 7) >> 3
        assert self.N > self.e

    @staticmethod
    def modulus( bits: int=1024 ) -> tuple[int,int]:
        """Generate an RSA modulus of the given size.
    
        PARAMETERS
        ==========
        bits: An int specifying the number of bits that N = p*q must occupy.

        RETURNS
        =======
        A tuple of the form (p,q), where p and q are ints of the same length.

        EXAMPLES
        ========
        > p, q   = RSA_key.modulus()
        > p2, q2 = key.modulus()        # also works, but note it generates a
                                        #  new modulus rather than returning
                                        #  the existing one.
        """

        assert type(bits) == int
        assert (bits & 0x1) == 0        # must be even
        p=safe_prime(bits//2)
        q=safe_prime(bits//2)
        return(p,q)
# delete this comment and insert your code here

    @staticmethod
    def keypair( p: int, q: int ) -> tuple[int,int]:
        """Generate a suitable public/private keypair for the given p and q.
           IMPORTANT: Implement your own version of the Extended Euclidean
           Algorithm, instead of relying on external routines or pow().
    
        PARAMETERS
        ==========
        p, q: The two parts of an RSA modulus, as integers.

        RETURNS
        =======
        A tuple of the form (e,d), where e is a random number and d its
            multiplicative inverse for phi(n). Both are integers.

        EXAMPLES
        ========
        > key = RSA_key()
        > p, q = key.modulus()
        > e, d = RSA_key.keypair( p, q )
        """

        assert type(p) == int
        assert type(q) == int
        phin=(p-1)*(q-1)
        #e=2
        e=random.randint(1,phin)


        while (gcd(e,phin))!=1:
            e=random.randint(2,phin)

        g,d,y=gcdExtended(e,phin)

        '''
        **Failed Bezouts table method attempt**
        a=[]
        x = e
        y=phin
        a.append(x//y)
        z = x % y
        while (z!=0):
            x=y
            y=z
            a.append(x // y)
            z=x%y
        a.pop()
        first=1
        second=0
        for topVal in a:
            third=(topVal*second)+first
            first=second
            second=third
        d=third'''
        return (e,d)


# delete this comment and insert your code here

    def sign( self, message: Union[int,bytes] ) -> Union[int,None]:
        """Sign a message via this RSA key, if possible.
    
        PARAMETERS
        ==========
        message: The message to be signed. Could be an int or bytes object.

        RETURNS
        =======
        If this has a private key, return the signature as an integer value.
           If it does not, return None.

        EXAMPLES
        ========
        > key = RSA_key()
        > sig = key.sign( 42 )
        """

        assert type(message) in [int, bytes]
        if self.d==None:
            return None
        else:
            if isinstance(message, bytes):
                Message = bytes_to_int(message)
            else:
                Message = message
            print(pow(Message,self.d,self.N))
            print("\n****************\n")
            return pow(Message,self.d,self.N)


# delete this comment and insert your code here

    def encrypt( self, message: Union[int,bytes] ) -> int:
        """Encrypt a message via this RSA key.
    
        PARAMETERS
        ==========
        message: The message to be encrypted. Could be an int or bytes object.

        RETURNS
        =======
        The encrypted value, as an integer.

        EXAMPLES
        ========
        > key    = RSA_key()
        > cypher = key.encrypt( 42 )
        """

        assert type(message) in [int, bytes]
        if isinstance(message, bytes):
            Message = bytes_to_int(message)
        else:
            Message = message
        return pow(Message,self.e,self.N)

# delete this comment and insert your code here

    def decrypt( self, cypher: Union[int,bytes] ) -> Union[int,None]:
        """Decrypt a message via this RSA key.
    
        PARAMETERS
        ==========
        cypher: The encrypted message. Could be an int or bytes object.

        RETURNS
        =======
        The decrypted value, as an integer, if this contains a private
           key. Otherwise, returns None.

        EXAMPLES
        ========
        > plain = server_key.decrypt( crypt )
        """

        assert type(cypher) in [int, bytes]
        if isinstance(cypher, bytes):
            Cypher = bytes_to_int(cypher)
        else:
            Cypher = cypher
        if self.d==None:
            return None
        else:
            return pow(Cypher,self.d,self.N)

# delete this comment and insert your code here
def gcd(a, b):
    if a == 0:
        return b
    return gcd(b % a, a)


def gcdExtended(a, b):
    if a == 0:
        return b,0,1

    gcd, x1, y1 = gcdExtended(b%a, a)
    # back subs
    x = y1-(b//a)* x1
    y = x1

    return gcd,x,y

def pad_encrypt_then_HMAC( plaintext:bytes, key_cypher:bytes, key_HMAC:bytes ) -> bytes:
    """Encrypt a plaintext with AES-256. Note the order of operations!
    
    PARAMETERS
    ==========
    plaintext: The bytes object to be encrypted.
    key_cypher: The bytes object used as a key to encrypt the plaintext.
    key_HMAC: The bytes object used as a key for the keyed-hash MAC.

    RETURNS
    =======
    The cyphertext, as a bytes object.
    """

    assert type(plaintext) is bytes
    assert type(key_cypher) is bytes
    assert len(key_cypher) == 32
    assert type(key_HMAC) is bytes

    pad_ob = padding.PKCS7(128).padder()
    msg_pad = pad_ob.update(plaintext)
    msg_pad += pad_ob.finalize()

    iv=os.urandom(16)
    encrypt = Cipher(algorithms.AES(bytes(key_cypher)), modes.CBC(bytes(iv)), default_backend()).encryptor()
    encrypted_text = encrypt.update(msg_pad) + encrypt.finalize()


    hash = hmac.HMAC(key_HMAC, hashes.SHA3_256())
    hash.update(iv+encrypted_text)
    hash = hash.finalize()
    print(len(hash))
    return iv+encrypted_text+hash

# delete this comment and insert your code here

def decrypt_and_verify( cyphertext: bytes, key_cypher: bytes, key_HMAC:bytes ) -> \
        Optional[bytes]:
    """Decrypt a plaintext that had been encrypted with the prior function.
       Also performs integrity checking to help ensure the original wasn't
       corrupted.
    
    PARAMETERS
    ==========
    cyphertext: The bytes object to be decrypted
    key_cypher: The bytes object used as a key to decrypt the plaintext.
    key_HMAC: The bytes object used as a key for the keyed-hash MAC.

    RETURNS
    =======
    If the cyphertext could be decrypted and validates, this returns a bytes 
      object containing the plaintext. Otherwise, it returns None.
    """

    assert type(cyphertext) is bytes
    assert type(key_cypher) is bytes
    assert len(key_cypher) == 32
    assert type(key_HMAC) is bytes
    iv = cyphertext[:16]
    follow = cyphertext[16:]
    encyption = follow[:-32]
    hashmac = follow[-32:]


    try:
        h = hmac.HMAC(key_HMAC, hashes.SHA3_256())
        h.update(iv+encyption)
        h.verify(hashmac)

    except:
        return None

    decryptor = Cipher(algorithms.AES(bytes(key_cypher)), modes.CBC(bytes(iv)), default_backend()).decryptor()
    d = decryptor.update(encyption) + decryptor.finalize()
    try:
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(d)
        data += unpadder.finalize()
        return data
    except:
        return None
# delete this comment and insert your code here

def ttp_prepare( bits: int=1024 ) -> RSA_key:
    """Calculate a full RSA keypair for the TTP.
    
    PARAMETERS
    ==========
    bits: The number of bits to use for the modulus, as an integer.

    RETURNS
    =======
    An RSA_key object.
    """

# delete this comment and insert your code here
    key= RSA_key(bits=bits)
    return key

def ttp_sign( sock: socket.socket, ttp_key: RSA_key, \
        database: Mapping[str,RSA_key]  ) -> Optional[Mapping[str,RSA_key]]:
    """Carry out the TTP's signing procedure. IMPORTANT: 's' has already
       been read!
    
    PARAMETERS
    ==========
    sock: The communication socket to send/receive data over. Must be closed
       before the function exits.
    ttp_key: An RSA_key object.
    database: A dictionary of all signatures generated, of the form 
        database[server_name] = key, where server_name is a string and
        key is an RSA_key object.

    RETURNS
    =======
    If the server has not requested a signature before, and the values can be 
       signed, return an updated version of the database. If the server has 
       already requested a signature but with different information, return None. 
       If the information was the same, return the database unmodified. If a
       socket error occurs, return None.
    """

    assert type(sock) is socket.socket
    assert type(database) == dict
    nameLengthBytes=receive(sock,1)

    nameLength=bytes_to_int(nameLengthBytes)
    nameBytes=receive(sock,nameLength)
    N_bytes=receive(sock,128)
    e_bytes=receive(sock,128)
    if (len(N_bytes)!=128) or (len(e_bytes)!=128):
        sock.close()
        return None
    hash = hashes.Hash(hashes.SHA3_512())
    hash.update(nameBytes + N_bytes+e_bytes)
    t = hash.finalize()
    hash1 = hashes.Hash(hashes.SHA3_512())
    hash1.update(t)
    tDash = hash1.finalize()
    tAndtdash=bytes_to_int(t+tDash)
    N=bytes_to_int(N_bytes)
    e=bytes_to_int(e_bytes)
    S=tAndtdash%ttp_key.N
    if database.get(nameBytes.decode('utf-8'))==None:
        key = RSA_key(pubkey=(N, e))
        sig = ttp_key.sign(S)
        database[nameBytes.decode('utf-8')] = key

        newNbytes=int_to_bytes(ttp_key.N,128)
        if (sig == None):
            sock.close()
            return database
        sentLength=send(sock, newNbytes)
        if sentLength!=128:
            sock.close()
            return database

        sig_bytes=int_to_bytes(sig,128)
        sentLength=send(sock,sig_bytes)
        if sentLength!=256:
            sock.close()
            return database
        sock.close()
        return database
    else:
        key=database[nameBytes.decode('utf-8')]
        if key.N==N and key.e==e:
            #send(sock,N_bytes)
            sig = ttp_key.sign(S)
            newNbytes = int_to_bytes(ttp_key.N, 128)
            if (sig == None):
                sock.close()
                return database
            sentLength = send(sock, newNbytes)
            if sentLength != 128:
                sock.close()
                return database

            sig_bytes = int_to_bytes(sig, 128)
            sentLength = send(sock, sig_bytes)
            if sentLength != 256:
                sock.close()
                return database
            sock.close()
            return database

        sock.close()
        return None








# delete this comment and insert your code here

def ttp_sendkey( sock: socket.socket, ttp_key: RSA_key ) -> bool:
    """Communicate the TTP's public key. Do not send the private key!
       'k' has already been read, as well.
    
    PARAMETERS
    ==========
    sock: The communication socket to send/receive data over. Must be closed
       before the function exits.
    ttp_key: An RSA_key object.

    RETURNS
    =======
    True, if the data was sent successfully. False, otherwise.
    """
    N=ttp_key.N
    e=ttp_key.e
    N_bytes=int_to_bytes(N,128)
    e_bytes=int_to_bytes(e,128)
    lenSent=send(sock,N_bytes+e_bytes)
    if lenSent<256:
        sock.close()
        return False
    sock.close()
    return True


# delete this comment and insert your code here

def sign_request( IP: str, port: int, server_name: str, server_key: RSA_key ) -> \
        Optional[tuple[int,int]]:
    """Sign the server's public key, via the TTP.
    
    PARAMETERS
    ==========
    IP: A string containing the IP address of the TTP.
    port: The port the TTP is listening on, as an integer.
    server_name: The server's name, as a string.
    server_key: The server's RSA key, as an RSA_key object.

    RETURNS
    =======
    On success, return (ttp_N, ttp_sig) as integers; the former is the TTP's
       RSA modulus, the latter the TTP's signature of the public key. If the 
       TTP could not be contacted, or any other error occurred, return None.
    """
    sock = create_socket(IP, port)
    if sock == None:
        return None


    sentlen = send(sock, b's')
    if sentlen != 1:
        sock.close()
        return None

    name = server_name.encode('utf-8')
    nameLength = len(name)
    nameLengthByte = int_to_bytes(nameLength, 1)
    sentlen = send(sock, nameLengthByte)
    if sentlen != 1:
        sock.close()
        return None

    sentlen = send(sock, name )
    if sentlen != len(name):
        sock.close()
        return None

    if server_key.N == None or server_key.e == None:
        sock.close()
        return None
    N_bytes = int_to_bytes(server_key.N, 128)
    sentlen = send(sock, N_bytes)
    if sentlen != 128:
        sock.close()
        return None
    e_bytes = int_to_bytes(server_key.e, 128)
    sentlen = send(sock, e_bytes)
    if sentlen != 128:
        sock.close()
        return None
    ttp_n = receive(sock, 128)
    ttp_sig = receive(sock, 128)
    if (len(ttp_sig) != 128) or len(ttp_n) != 128:
        sock.close()
        return None
    return (bytes_to_int(ttp_n), bytes_to_int(ttp_sig))


# delete this comment and insert your code here

def key_request( IP: str, port: int ) -> Optional[RSA_key]:
    """Request the TTP's public key.
    
    PARAMETERS
    ==========
    IP: A string containing the IP address of the TTP.
    port: The port the TTP is listening on, as an integer.

    RETURNS
    =======
    On success, return an RSA_key object. If there was a communications error,
      return None.
    """
    sock=create_socket(IP,port)
    k_byte = 'k'.encode('utf-8')
    sentlen = send(sock, k_byte)
    if sentlen != 1:
        sock.close()
        return None
    ttp_n = receive(sock, 128)
    ttp_d = receive(sock, 128)
    if (len(ttp_d) != 128) or len(ttp_n) != 128:
        sock.close()
        return None
    sock.close()
    rsakey=RSA_key(pubkey=(bytes_to_int(ttp_n),bytes_to_int(ttp_d)))
    return rsakey

# delete this comment and insert your code here

def server_prepare( safe_bits: int=512, RSA_bits: int=1024 ) -> tuple[DH_params, RSA_key]:
    """Precalculate key values that the server needs. This includes all the
       prior setup, plus the generation of an RSA key.
    
    PARAMETERS
    ==========
    safe_bits: The size of the safe prime, as an int.
    RSA_bits: The size of the RSA modulus N = p*q, as an int. 

    RETURNS
    =======
    A tuple of the form (DH_params, RSA_key).
    """

    dh=DH_params(None,safe_bits)
    key=RSA_key(None,RSA_bits)
    return (dh,key)


# delete this comment and insert your code here

def server_protocol( sock: socket.socket, dh: DH_params, server_key: RSA_key, \
        server_name: str, ttp_sig: int, database: Mapping[str,tuple[bytes,int]] ) -> \
        Optional[ tuple[str,int,bytes,bytes,bytes] ]:
    """Carry out the protocol and file transfer as per the assignment.
       IMPORTANT: 'p' has already been sent!
    
    PARAMETERS
    ==========
    sock: A socket connected to the client.
    dh: A DH_params object.
    server_key: An RSA_key object. 
    server_name: The server's name, as a string.
    ttp_sig: The signature returned by the TTP, as an int.
    database: A dict containing the user database, as per A2.

    RETURNS
    =======
    If the protocol was successful, return the tuple ( username, b, 
       AES_key, HMAC_key, plaintext ), which are (in order) the username
       supplied by the client, as a string; the server's randomly-chosen value
       for b, as an integer; the key used to encrypt the file transfer, as a
       bytes object; the key used for message authentication, as a bytes
       object; and the plaintext version of the file, as a bytes object.
       If the protocol failed, return None.
    """

    clientUsernameLength=receive(sock,1)

    clientUsernameUTF=receive(sock,bytes_to_int(clientUsernameLength))

    clientUsername=clientUsernameUTF.decode("utf-8")

    server_nameUTF= server_name.encode("utf-8")
    server_nameLen=len(server_nameUTF)
    sentLen=send(sock,int_to_bytes(server_nameLen,1))

    sentLen=send(sock,server_nameUTF)
    Nbytes=int_to_bytes(server_key.N,128)
    ebytes=int_to_bytes(server_key.e,128)
    ttpsignbytes=int_to_bytes(ttp_sig,128)
    sentLen = send(sock, Nbytes)
    sentLen = send(sock, ebytes)
    sentLen = send(sock, ttpsignbytes)


    encA=receive(sock,128)
    A=server_key.decrypt(encA)
    if (A%dh.N==0):
        sock.close()
        return None
    A_bytes = int_to_bytes(A, 64)
    N=dh.N
    g=dh.g
    k=calc_u(N,g)
    reply = database.get(clientUsername)
    if reply == None:
        database=ttp_sign(sock,server_key,database)
    reply = database.get(clientUsername)
    s = reply[0]
    v = reply[1]
    b = random.randint(0, N - 1)
    B = calc_B(N, g, b, k, v)
    B_bytes = int_to_bytes(B, 64)

    concat = s + B_bytes
    lenSent = send(sock, concat)
    '''s and b sent'''


    u = calc_u(A_bytes, B_bytes)
    k_server = calc_K_server(N, A_bytes, b, v, u)
    k_server_bytes = int_to_bytes(k_server, 64)
    M1 = receive(sock, 32)
    m1serv=calc_M1(A_bytes,B_bytes,k_server)
    M2 = calc_M2(A, M1, k_server)
    lenSent = send(sock, M2)

    if (M1==m1serv):

        aesKey=k_server_bytes[:32]
        hmacKey=k_server_bytes[32:]

        cyphertextLen=receive(sock,4)
        cypher=receive(sock,bytes_to_int(cyphertextLen))
        plaintext=decrypt_and_verify(cypher,aesKey,hmacKey)
        sock.close()
        if plaintext==None:
            return None
        return ( clientUsername, b, aesKey, hmacKey, plaintext )
    else:
        sock.close()
        return None



# delete this comment and insert your code here

def client_protocol( ip: str, port: int, dh: DH_params, ttp_key: RSA_key, \
        username: str, pw: str, s: bytes, file_bytes: bytes ) -> \
        Optional[tuple[int,int]]:
    """Generate the shared key and send the file, from the client side.
       IMPORTANT: don't forget to send 'p'!

    PARAMETERS
    ==========
    ip: The IP address to connect to, as a string.
    port: The port to connect to, as an int.
    dh: A DH_params object.
    ttp_key: An RSA_key object.
    username: The username to register, as a string.
    pw: The password, as a string.
    s: The salt, a bytes object 16 bytes long. Must match what the server sends
       back.
    file_bytes: The plaintext to send to the server, as a bytes object.

    RETURNS
    =======
    If successful, return a tuple of the form (a, K_client), where both a and
       K_client are integers. If not, return None.
    """
    try:
        sock=create_socket(ip,port)
        # if sock==None:
        #     return None
        p='p'.encode('utf-8')
        send(sock,p)
        usernameUTF=username.encode('utf-8')
        send(sock,int_to_bytes(len(usernameUTF),1))
        send(sock,usernameUTF)

        serverNameLen1=receive(sock,1)
        serverNameLen=bytes_to_int(serverNameLen1)
        serverNameBytes= receive(sock,serverNameLen)
        serverName=serverNameBytes.decode('utf-8')
        servN_bytes=receive(sock,128)
        serve_bytes=receive(sock,128)

        servN=bytes_to_int(servN_bytes)
        serve=bytes_to_int(serve_bytes)
        server_key=RSA_key(pubkey=(servN,serve))

        ttpSig_bytes=receive(sock,128)
        NameNe=serverNameBytes+servN_bytes+serve_bytes
        ttpSign=bytes_to_int(ttpSig_bytes)
        digest = hashes.Hash(hashes.SHA3_512())
        digest.update(NameNe)
        t = digest.finalize()
        digest = hashes.Hash(hashes.SHA3_512())
        digest.update(t)
        tdash = digest.finalize()
        tFinal=bytes_to_int(t+tdash)
        verSig=pow(tFinal,ttp_key.d,ttp_key.N)

        # verify
        if (verSig!=ttpSign):
            sock.close()
            return None
        N=dh.N
        g=dh.g
        a = random.randint(0, N - 1)
        A = calc_A(N, g, a)
        encA=server_key.encrypt(A)
        encABytes=int_to_bytes(encA,128)
        sentLen=send(sock,encABytes)

        salt = receive(sock, 16)


        if salt != s:
            sock.close()
            return None
        B = receive(sock, 64)
        # calc u
        u = calc_u(A, B)


        k=calc_u(N,g)

        # calc x
        x=calc_x(s,pw)

        # calc v
        v = pow(g, x, N)
        # calc K_client
        k_client = calc_K_client(N, B, k, v, a, u, x)
        # calc M1 and send
        M1 = calc_M1(A, B, k_client)
        sentLen = send(sock, M1)
        if sentLen < len(M1):
            sock.close()
            return None

        M2 = receive(sock, 32)
        clientM2=calc_M2(A,M1,k_client)
        if (M2==clientM2):
            k_client_bytes=int_to_bytes(k_client,64)
            aesKey=k_client_bytes[:32]
            hmacKey=k_client_bytes[32:]
            cyphertext=pad_encrypt_then_HMAC(file_bytes,aesKey,hmacKey)
            cypherLen=int_to_bytes(len(cyphertext),4)
            send(sock,cypherLen)
            send(sock,cyphertext)
            sock.close()
            return (A,k_client)
        sock.close()
        return None
    except:
        return None



# delete this comment and insert your code here


##### MAIN

if __name__ == '__main__':

    # parse the command line args
    cmdline = argparse.ArgumentParser( description="Test out a secure handshake algorithm by transferring a file." )

    methods = cmdline.add_argument_group( 'ACTIONS', "The four actions this program can do." )

    methods.add_argument( '--ttp', action='store_true', help='Launch the TTP server.' )
    methods.add_argument( '--client', action='store_true', \
            help='Perform signature verification, registration, and the protocol.' )
    methods.add_argument( '--server', action='store_true', \
        help='Get a certificate signed, then launch the server.' )
    methods.add_argument( '--quit', action='store_true', \
        help='Tell all running servers to quit.' )

    methods = cmdline.add_argument_group( 'OPTIONS', "Modify the defaults used for the above actions." )

    methods.add_argument( '--server_addr', metavar='IP:port', type=str, default='127.0.4.18:3180', \
        help='Use the given IP address and port for the server.' )
    methods.add_argument( '--server_name', metavar='STRING', type=str, default='Gibson', \
        help='The name of the server.' )
    methods.add_argument( '--ttp_addr', metavar='IP:port', type=str, default='127.0.4.18:31800', \
        help='Use the given IP address and port for the TTP.' )
    methods.add_argument( '--username', metavar='NAME', type=str, default="admin", \
        help='The username the client sends to the server.' )
    methods.add_argument( '--password', metavar='PASSWORD', type=str, default="swordfish", \
        help='The password the client sends to the server.' )
    methods.add_argument( '--salt', metavar='FILE', type=argparse.FileType('rb', 0), \
        help='A specific salt for the client to use, stored as a file. Randomly generated if not given.' )
    methods.add_argument( 'input_file', metavar='INPUT', type=argparse.FileType('rb', 0), \
        help='A file to be transmitted by the client.' )
    methods.add_argument( 'output_file', metavar='OUTPUT', type=argparse.FileType('wb', 0), \
        help='The destination where the server places a received file.' )
    methods.add_argument( '--timeout', metavar='SECONDS', type=int, default=600, \
        help='How long until the program automatically quits. Negative or zero disables this.' )
    methods.add_argument( '-v', '--verbose', action='store_true', \
        help="Be more verbose about what is happening." )

    args = cmdline.parse_args()

    # handle the salt
    if args.salt:
        salt = args.salt.read( 16 )
    else:
        salt = client_prepare()

    if args.verbose:
        print( f"Program: Using salt <{salt.hex()}>" )
    
    # first off, do we have a timeout?
    killer = None           # save this for later
    if args.timeout > 0:

        # define a handler
        def shutdown( time, verbose=False ):

            sleep( time )
            if verbose:
                print( "Program: exiting after timeout.", flush=True )

            return # optional, but I like having an explicit return

        # launch it
        if args.verbose:
            print( "Program: Launching background timeout.", flush=True )
        killer = Thread( target=shutdown, args=(args.timeout,args.verbose) )
        killer.daemon = True
        killer.start()

    # handle the TTP, if it needs to be launched
    ttp_addr    = split_ip_port( args.ttp_addr )
    ttp_thr     = None
    if args.ttp:
        if args.verbose:
            print( "Program: Attempting to launch the TTP.", flush=True )
    if ttp_addr is None:
        print( "Program: Invalid address for the TTP, cannot launch it.", flush=True )
    else:
        IP, port = ttp_addr
        if args.verbose:
            print( f"TTP: Asked to start on IP {IP} and port {port}.", flush=True )
            print( f"TTP: Generating an RSA keypair, this will take some time.", flush=True )

        ttp_key = ttp_prepare() 
        if args.verbose:
            print( f"TTP: Finished generating the keypair.", flush=True )

        # use an inline routine, as this doesn't have to be globally visible
        def ttp_loop( IP, port, key, verbose=False ):
            
            database = dict()           # for tracking signed keys

            sock = create_socket( IP, port, listen=True )
            if sock is None:
                if verbose:
                    print( f"TTP: Could not create socket, exiting.", flush=True )
                return

            if verbose:
                print( f"TTP: Beginning connection loop.", flush=True )
            while True:

                (client, client_address) = sock.accept()
                if verbose:
                    print( f"TTP: Got connection from {client_address}.", flush=True )

                mode = receive( client, 1 )
                if len(mode) != 1:
                    if verbose:
                        print( f"TTP: Socket error with client, closing it and waiting for another connection.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    continue

                if mode == b'q':
                    if verbose:
                        print( f"TTP: Asked to quit by client. Shutting down.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    return

                elif mode == b's':
                    if verbose:
                        print( f"TTP: Asked to sign by a Server.", flush=True )

                    temp = ttp_sign( client, key, database )
                    if (temp is None) and verbose:
                            print( f"TTP: Signing failed, closing socket and waiting for another connection.", flush=True )
                    elif type(temp) is dict:
                        if verbose:
                            print( f"TTP: Signing complete, current Servers: {[x for x in temp]}.", flush=True )
                        database = temp

                elif mode == b'k':
                    if verbose:
                        print( f"TTP: Asked for our public key.", flush=True )

                    ttp_sendkey( client, key )

                # clean up is done inside the functions
                # loop back

        # launch the TTP
        if args.verbose:
            print( "Program: Launching the TTP.", flush=True )
        ttp_thr = Thread( target=ttp_loop, args=(IP, port, ttp_key, args.verbose) )
        ttp_thr.daemon = True
        ttp_thr.start()

    # next off, are we launching the server?
    server_addr = split_ip_port( args.server_addr )
    server_thr  = None

    if args.server and (args.output_file is None):
        print( "Program: Cannot launch the Server without an output file.", flush=True )
        args.server = None

    if (server_addr is None) or (ttp_addr is None):
        print( "Program: Cannot launch the Server without addresses for both the Server and the TTP.", flush=True )
    elif args.server:

        IP, port = server_addr
        if args.verbose:
            print( "Program: Attempting to launch the Server.", flush=True )
            print( f"Server: Asked to start on IP {IP} and port {port}.", flush=True )

        if args.verbose:
            print( f"Server: Preparing N/g and our RSA key. This will take some time.", flush=True )
        dh, server_key = server_prepare()

        def server_loop( IP, port, dh, key, server_name, output_file, verbose=False ):
            
            database = dict()           # for tracking registered users

            if verbose:
                print( f"Server: Retrieving a signature of our key.", flush=True )
            result = sign_request( *ttp_addr, server_name, key ) 
            if result is None:
                print( f"Server: Could not get a signature. Quitting.", flush=True )
                return

            ttp_N, ttp_sig = result
            if verbose:
                print( f"Server: Finished all preparations, ready to listen.", flush=True )

            sock = create_socket( IP, port, listen=True )
            if sock is None:
                if verbose:
                    print( f"Server: Could not create socket, exiting.", flush=True )
                return

            if verbose:
                print( f"Server: Beginning connection loop.", flush=True )
            while True:

                (client, client_address) = sock.accept()
                if verbose:
                    print( f"Server: Got connection from {client_address}.", flush=True )

                mode = receive( client, 1 )
                if len(mode) != 1:
                    if verbose:
                        print( f"Server: Socket error with client, closing it and waiting for another connection.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    continue

                if mode == b'q':
                    if verbose:
                        print( f"Server: Asked to quit. Shutting down.", flush=True )
                    client.shutdown(socket.SHUT_RDWR)
                    client.close()
                    sock.shutdown(socket.SHUT_RDWR)
                    sock.close()
                    return

                elif mode == b'r':
                    if verbose:
                        print( f"Server: Asked to register by the Client.", flush=True )

                    temp = server_register( client, dh.N, dh.g, database )
                    if (temp is None) and verbose:
                        print( f"Server: Registration failed, closing socket and waiting for another connection.", flush=True )
                    elif temp is not None:
                        if verbose:
                            print( f"Server: Registration complete, current users: {[x for x in temp]}.", flush=True )
                        database = temp

                elif mode == b'p':
                    if verbose:
                        print( f"Server: Asked to share a file by a Client.", flush=True )

                    temp = server_protocol( client, dh, key, server_name, ttp_sig, database )
                    if (temp is None) and verbose:
                            print( f"Server: Protocol failed, closing socket and waiting for another connection.", flush=True )
                    elif (type(temp) == tuple) and (len(temp) == 5):
                        if verbose:
                            print( f"Server: Protocol complete, negotiated shared key for {temp[0]}.", flush=True )
                            print( f"Server:  AES key is {temp[2].hex()}, HMAC key is {temp[3].hex()}.", flush=True )

                        # write out the file
                        output_file.write( temp[4] )
                        output_file.close()

                # clean up is done inside the functions
                # loop back

        # launch the server
        if args.verbose:
            print( "Program: Launching server.", flush=True )
        server_thr = Thread( target=server_loop, args=(IP, port, dh, server_key, \
                args.server_name, args.output_file, args.verbose) )
        server_thr.daemon = True
        server_thr.start()

    # finally, check if we're launching the client
    client_thr = None
    if args.client and (args.input_file is None):       # no input file = no client
        print( "Program: Cannot launch the Client without an input file.", flush=True )
        args.client = None

    if (server_addr is None) or (ttp_addr is None):
        print( "Program: Cannot launch the Client without addresses for both the Server and the TTP.", flush=True )

    elif args.client:

        if args.verbose:
            print( "Program: Attempting to launch client.", flush=True )

        # one final inline routine
        def client_routine( ttp_addr, server_addr, username, pw, s, input_file, verbose=False ):

            sleep( 1 )      # give the Server some time to spin up
            if verbose:
                print( f"Client: Retrieving TTP public key.", flush=True )

            ttp_key = key_request( *ttp_addr )
            if ttp_key is None:
                print( "Client: Could not retrieve the public key." )
                return

            if verbose:
                print( f"Client: Beginning registration.", flush=True )

            results = client_register( *server_addr, username, pw, s )
            if results is None:
                if verbose:
                    print( f"Client: Registration failed, not attempting the protocol.", flush=True )
                return
            else:
                N, g, v = results

            dh = DH_params( pair=(N,g) )

            if verbose:
                print( f"Client: Beginning the shared-key protocol.", flush=True )

            input = input_file.read()       # we want this in bytes
            input_file.close()

            results = client_protocol( *server_addr, dh, ttp_key, username, pw, s, input )
            if results is None:
                if verbose:
                    print( f"Client: Protocol failed.", flush=True )
            else:
                a, K_client = results
                if verbose:
                    print( f"Client: Protocol successful.", flush=True )
                    print( f"Client:  K_client = {K_client}.", flush=True )

            return

        # launch the client
        if args.verbose:
            print( "Program: Launching client.", flush=True )
        client_thr = Thread( target=client_routine, args=( ttp_addr, server_addr, \
            args.username, args.password, salt, args.input_file, args.verbose) )
        client_thr.daemon = True
        client_thr.start()

    # finally, the quitting routine
    result      = None     # reset this value

    if args.quit:
        if client_thr is not None:
            if args.verbose:
                print( f"Quit: Waiting for the client to complete first.", flush=True )
            client_thr.join()

        if args.verbose:
            print( "Quit: Attempting to kill the server.", flush=True )

        # no need for threading here
        sock = create_socket( *server_addr )
        if sock is None:
            if args.verbose:
                print( f"Quit: Could not connect to the server to send the kill signal.", flush=True )
        else:
            count = send( sock, b'q' )
            if count != 1:
                if args.verbose:
                    print( f"Quit: Socket error when sending the signal.", flush=True )
            elif args.verbose:
                    print( f"Quit: Signal sent successfully.", flush=True )

            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

        if args.verbose:
            print( "Quit: Attempting to kill the TTP.", flush=True )

        sock = create_socket( *ttp_addr )
        if sock is None:
            if args.verbose:
                print( f"Quit: Could not connect to the TTP to send the kill signal.", flush=True )
        else:
            count = send( sock, b'q' )
            if count != 1:
                if args.verbose:
                    print( f"Quit: Socket error when sending the signal.", flush=True )
            elif args.verbose:
                    print( f"Quit: Signal sent successfully.", flush=True )

            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    # finally, we wait until we're told to kill ourselves off, or all threads are done
    while not ((server_thr is None) and (client_thr is None) and (ttp_thr is None)):

        if (killer is not None) and (not killer.is_alive()):
            if args.verbose:
                print( f"Program: Timeout reached, so exiting.", flush=True )
            exit()

        if (client_thr is not None) and (not client_thr.is_alive()):
            if args.verbose:
                print( f"Program: Client terminated.", flush=True )
            client_thr = None
        
        if (server_thr is not None) and (not server_thr.is_alive()):
            if args.verbose:
                print( f"Program: Server terminated.", flush=True )
            server_thr = None

        if (ttp_thr is not None) and (not ttp_thr.is_alive()):
            if args.verbose:
                print( f"Program: TTP terminated.", flush=True )
            ttp_thr = None
        
