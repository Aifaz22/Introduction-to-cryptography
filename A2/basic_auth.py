#!/usr/bin/env python3

##### IMPORTS

import argparse
import os
import random
from multiprocessing import Process
from sys import exit
from time import sleep
import socket
from sympy import ntheory
from cryptography.hazmat.primitives import hashes


# Insert your imports here


##### METHODS

def split_ip_port(string):
	"""Split the given string into an IP address and port number.

    PARAMETERS
    ==========
    string: A string of the form IP:PORT.

    RETURNS
    =======
    If successful, a tuple of the form (IP,PORT), where IP is a
      string and PORT is a number. Otherwise, returns None.
    """
	assert type(string) == str

	try:
		idx = string.index(':')
		return (string[:idx], int(string[idx + 1:]))
	except:
		return None


def int_to_bytes(value, length):
	"""Convert the given integer into a bytes object with the specified
       number of bits. Uses network byte order.

    PARAMETERS
    ==========
    value: An int to be converted.
    length: The number of bytes this number occupies.

    RETURNS
    =======
    A bytes object representing the integer.
    """

	assert type(value) == int
	assert length > 0

	return value.to_bytes(length, 'big')


def bytes_to_int(value):
	"""Convert the given bytes object into an integer. Uses network
       byte order.

    PARAMETERS
    ==========
    value: An bytes object to be converted.

    RETURNS
    =======
    An integer representing the bytes object.
    """

	assert type(value) == bytes
	return int.from_bytes(value, 'big')


def create_socket(ip, port, listen=False):
	"""Create a TCP/IP socket at the specified port, and do the setup
       necessary to turn it into a connecting or receiving socket. Do
       not actually send or receive data here!

    PARAMETERS
    ==========
    ip: A string representing the IP address to connect/bind to.
    port: An integer representing the port to connect/bind to.
    listen: A boolean that flags whether or not to set the socket up
       for connecting or receiving.

    RETURNS
    =======
    If successful, a socket object that's been prepared according to
       the instructions. Otherwise, return None.
    """

	assert type(ip) == str
	assert type(port) == int

	try:
		sock = socket.socket()
		if not listen:
			sock.connect((ip, port))
			return sock
		else:
			sock.bind((ip, port))
			return sock  
	except:
		return None


# delete this comment and insert your code here

def send(sock, data):
	"""Send the provided data across the given socket. This is a
       'reliable' send, in the sense that the function retries sending
       until either a) all data has been sent, or b) the socket
       closes.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    data: A bytes object containing the data to send.

    RETURNS
    =======
    The number of bytes sent. If this value is less than len(data),
       the socket is dead and a new one must be created, plus an unknown
       amount of the data was transmitted.
    """

	assert type(sock) == socket.socket
	assert type(data) == bytes

	try:
		length = sock.send(data)
		if length < len(data):
			
			return 0
		else:
			return length
	except:
		return 0


# delete this comment and insert your code here


def receive(sock, length):
	"""Receive the provided data across the given socket. This is a
       'reliable' receive, in the sense that the function never returns
       until either a) the specified number of bytes was received, or b)
       the socket closes. Never returning is an option.

    PARAMETERS
    ==========
    sock: A socket object to use for sending and receiving.
    length: A positive integer representing the number of bytes to receive.

    RETURNS
    =======
    A bytes object containing the received data. If this value is less than
       length, the socket is dead and a new one must be created.
    """

	assert type(sock) == socket.socket
	assert length > 0
	try:
		data = sock.recv(length)
		if length != len(data):
			
			return b''
		else:
			return data
	except:
		return b''


# delete this comment and insert your code here


def safe_prime(bits=512):
	"""Generate a safe prime that is at least 'bits' bits long. The result
       should be greater than 1 << (bits-1).

    PARAMETERS
    ==========
    bits: An integer representing the number of bits in the safe prime.
       Must be greater than 1.

    RETURNS
    =======
    An interger matching the spec.
    """

	assert bits > 1
	min = 2 ** (bits - 2)
	max = 2 ** (bits - 1)
	q = ntheory.randprime(min,max)
	while q <= max:
		p = (q * 2) + 1
		if (ntheory.isprime(q) and ntheory.isprime(p)):
			return p
		q = ntheory.randprime(min,max)
	return 2


# delete this comment and insert your code here

def prim_root(N):
	"""Find a primitive root for N, a large safe prime. Hint: it isn't
       always 2.

    PARAMETERS
    ==========
    N: The prime in question. May be an integer or bytes object.

    RETURNS
    =======
    An integer representing the primitive root. Must be a positive
       number greater than 1.
    """

	primeFact = ntheory.primefactors(N - 1)
	for j in range(2, N):
		found = True
		for factor in primeFact:
			if pow(j,(N - 1) // factor, N) == 1:
				found = False
				break
		if found == True:
				return j
	return 0
	


# delete this comment and insert your code here


def calc_x(s, pw):
	"""Calculate the value of x, according to the assignment.

    PARAMETERS
    ==========
    s: The salt to use. A bytes object consisting of 16 bytes.
    pw: The password to use, as a string.

    RETURNS
    =======
    An integer representing x.
    """

	assert type(pw) == str
	passbyte = pw.encode("utf8")
	concatenatedText = s + passbyte
	dig = hashes.Hash(hashes.SHA256())
	dig.update(concatenatedText)
	h = dig.finalize()
	integer = bytes_to_int(h)
	return integer


# delete this comment and insert your code here


def calc_A(N, g, a):
	"""Calculate the value of A, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    g: A primitive root of N. Could be an integer or bytes object.
    a: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing A.
    """


	if isinstance(N,bytes):
		n=bytes_to_int(N)
	else:
		n=N
	if isinstance(g,bytes):
		G=bytes_to_int(g)
	else:
		G=g
	if isinstance(a,bytes):
		A=bytes_to_int(a)
	else:
		A=a
	return pow(G,A,n)

# delete this comment and insert your code here



def calc_B(N, g, b, k, v):
	"""Calculate the value of B, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    g: A primitive root of N. Could be an integer or bytes object.
    b: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    k: The hash of N and g. Could be an integer or bytes object.
    v: See calc_v(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing B.
    """



	if isinstance(N,bytes):
		n=bytes_to_int(N)
	else:
		n=N
	if isinstance(g,bytes):
		G=bytes_to_int(g)
	else:
		G=g
	if isinstance(b,bytes):
		B=bytes_to_int(b)
	else:
		B=b
	if isinstance(k,bytes):
		K=bytes_to_int(k)
	else:
		K=k
	if isinstance(v,bytes):
		V=bytes_to_int(v)
	else:
		V=v

	return ((K*V)%n+pow(G,B,n))%n

# delete this comment and insert your code here


def calc_u(A, B):
	"""Calculate the value of u, according to the assignment.

    PARAMETERS
    ==========
    N: See calc_A(). Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing u.
    """
	if isinstance(A,int):
		a=int_to_bytes(A,64)
	else:
		a=A
	if isinstance(B,int):
		b=int_to_bytes(B,64)
	else:
		b=B
	concatenatedText = a+b
	dig = hashes.Hash(hashes.SHA256())
	dig.update(concatenatedText)
	h = dig.finalize()
	integer = bytes_to_int(h)
	return integer

# delete this comment and insert your code here


def calc_K_client(N, B, k, v, a, u, x):
	"""Calculate the value of K_client, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.
    k: The hash of N and g. Could be an integer or bytes object.
    v: See calc_v(). Could be an integer or bytes object.
    a: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    u: The hash of A and B. Could be an integer or bytes object.
    x: See calc_x(). Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing K_client.
    """
	if isinstance(x,bytes):
		X=bytes_to_int(x)
	else:
		X=x
	if isinstance(u,bytes):
		U=bytes_to_int(u)
	else:
		U=u
	if isinstance(a,bytes):
		A=bytes_to_int(a)
	else:
		A=a
	if isinstance(v,bytes):
		V=bytes_to_int(v)
	else:
		V=v
	if isinstance(k,bytes):
		K=bytes_to_int(k)
	else:
		K=k
	if isinstance(B,bytes):
		b=bytes_to_int(B)
	else:
		b=B
	if isinstance(N,bytes):
		n=bytes_to_int(N)
	else:
		n=N
	return pow(b-(K*V),A+(U*X),n)
# delete this comment and insert your code here


def calc_K_server(N, A, b, v, u):
	"""Calculate the value of K_server, according to the assignment.

    PARAMETERS
    ==========
    N: The safe prime. Could be an integer or bytes object.
    A: See calc_A(). Could be an integer or bytes object.
    b: A random value between 0 and N-1, inclusive. Could be an integer or bytes object.
    v: See calc_v(). Could be an integer or bytes object.
    u: The hash of A and B. Could be an integer or bytes object.

    RETURNS
    =======
    An integer representing K_server.
    """

	if isinstance(u,bytes):
		U=bytes_to_int(u)
	else:
		U=u
	if isinstance(A,bytes):
		a=bytes_to_int(A)
	else:
		a=A
	if isinstance(v,bytes):
		V=bytes_to_int(v)
	else:
		V=v
	if isinstance(b,bytes):
		B=bytes_to_int(b)
	else:
		B=b
	if isinstance(N,bytes):
		n=bytes_to_int(N)
	else:
		n=N
	return (pow(a,B,n)*pow(V,U*B, n))%n
# delete this comment and insert your code here


def calc_M1(A, B, K_client):
	"""Calculate the value of M1, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    B: See calc_B(). Could be an integer or bytes object.
    K_client: See calc_K_client(). Could be an integer or bytes object.

    RETURNS
    =======
    A bytes object representing M1.
    """
	if isinstance(A,int):
		a=int_to_bytes(A,64)
	else:
		a=A
	if isinstance(B,int):
		b=int_to_bytes(B,64)
	else:
		b=B
	if isinstance(K_client,int):
		k_client=int_to_bytes(K_client,64)
	else:
		k_client=K_client
	concatenatedText = a + b+ k_client
	dig = hashes.Hash(hashes.SHA256())
	dig.update(concatenatedText)

	return dig.finalize()


# delete this comment and insert your code here


def calc_M2(A, M1, K_server):
	"""Calculate the value of M2, according to the assignment.

    PARAMETERS
    ==========
    A: See calc_A(). Could be an integer or bytes object.
    M1: See calc_M1(). Could be an integer or bytes object.
    K_server: See calc_K_server(). Could be an integer or bytes object.

    RETURNS
    =======
    A bytes object representing M2.
    """
	if isinstance(A,int):
		a=int_to_bytes(A,64)
	else:
		a=A
	if isinstance(M1,int):
		m1=int_to_bytes(M1,32)
	else:
		m1=M1
	if isinstance(K_server,int):
		k_server=int_to_bytes(K_server,64)
	else:
		k_server=K_server

	concatenatedText = a + m1 + k_server

	dig = hashes.Hash(hashes.SHA256())
	dig.update(concatenatedText)
	
	return dig.finalize()

# delete this comment and insert your code here


def client_prepare():
	"""Do the preparations necessary to connect to the server. Basically,
       just generate a salt.

    RETURNS
    =======
    A bytes object containing a randomly-generated salt, 16 bytes long.
    """
	str=os.urandom(16)
	return str


# delete this comment and insert your code here


def server_prepare():
	"""Do the preparations necessary to accept clients. Generate N and g,
       and compute k.

    RETURNS
    =======
    A tuple of the form (N, g, k), containing those values as integers.
    """
	N=safe_prime()
	g=prim_root(N)
	n = int_to_bytes(N, 64)
	G = int_to_bytes(g, 64)
	concatenatedText=n+G
	dig = hashes.Hash(hashes.SHA256())
	dig.update(concatenatedText)
	h = dig.finalize()
	k= bytes_to_int(h)
	return (N,g,k)

# delete this comment and insert your code here


def client_register(ip, port, username, pw, s):
	"""Register the given username with the server, from the client.
       IMPORTANT: don't forget to send 'r'!

    PARAMETERS
    ==========
    ip: The IP address to connect to, as a string.
    port: The port to connect to, as an int.
    username: The username to register, as a string.
    pw: The password, as a string.
    s: The salt, a bytes object 16 bytes long.

    RETURNS
    =======
    If successful, return a tuple of the form (N, g, v), all integers.
       On failure, return None.
    """
	sock = create_socket(ip, port)
	data='r'.encode('utf-8')
	lengthSent=send(sock,data)
	if lengthSent==len(data):
		data=receive(sock,128)
		if (data==b''):
			sock.close()
			return None
		N=data[:64]
		G=data[64:]
		n=bytes_to_int(N)
		g=bytes_to_int(G)
		x=calc_x(s,pw)
		v=pow(g,x,n)
		user = username.encode('utf-8')
		lenUser= int_to_bytes(len(user),1)
		V=int_to_bytes(v,64)
		concat= lenUser+user+s+V
		lengthSent = send(sock, concat)
		if (lengthSent != len(concat)):
			sock.close()
			return None

		sock.close()
		return (n,g,v)
	else:
		print("dead socket\n")
		sock.close()
		return None

# delete this comment and insert your code here


def server_register(sock, N, g, database):
	"""Handle the server's side of the registration. IMPORTANT: reading the
       initial 'r' has been handled for you.

    PARAMETERS
    ==========
    sock: A socket object that contains the client connection.
    N: A safe prime. Could be an integer or bytes object.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    database: A dictionary of all registered users. The keys are usernames
       (as strings!), and the values are tuples of the form (s, v), where s
       is the salt (16 bytes) and v is as per the assignment (integer).

    RETURNS
    =======
    If the registration process was successful, return an updated version of the
       database. If it was not, return None. NOTE: a username that tries to
       re-register with a different salt and password is likely malicious,
       and should therefore count as an unsuccessful registration that doesn't
       modify the user database.
    """
	if isinstance(N,int):
		n=int_to_bytes(N,64)
	else:
		n=N
	if isinstance(g,int):
		G=int_to_bytes(g,64)
	else:
		G=g
	data=n+G
	sentLen=send(sock,data)
	if sentLen!=len(data):
		sock.close()
		return None
	userLength=receive(sock,1)
	lengthOfUsername=bytes_to_int(userLength)
	user=receive(sock,lengthOfUsername)
	salt=receive(sock,16)
	v_bytes=receive(sock,64)

	if userLength==b'' or user==b'' or salt==b'' or v_bytes==b'':
		sock.close()
		return None

	v=bytes_to_int(v_bytes)
	username=user.decode('utf-8')
	if (database.get(username)!=None):
		if (salt,v)!=database.get(username):
			sock.close()
			return None
		sock.close()
		return database
	database[username]=(salt,v)
	sock.close()
	return database
# delete this comment and insert your code here


def client_protocol(ip, port, N, g, username, pw, s):
	"""Register the given username with the server, from the client.
       IMPORTANT: don't forget to send 'p'!

    PARAMETERS
    ==========
    ip: The IP address to connect to, as a string.
    port: The port to connect to, as an int.
    N: A safe prime. Could be an integer or bytes object.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    username: The username to register, as a string.
    pw: The password, as a string.
    s: The salt, a bytes object 16 bytes long. Must match what the server
       sends back.

    RETURNS
    =======
    If successful, return a tuple of the form (a, K_client), where both a and
       K_client are integers. If not, return None.
    """
	if isinstance(N,bytes):
		N_bytes=N
		N=bytes_to_int(N)
	else:
		N_bytes=int_to_bytes(N,64)
	if isinstance(g,bytes):
		g_bytes=g
		g=bytes_to_int(g)
	else:
		g_bytes=int_to_bytes(g,64)

	sock=create_socket(ip,port)
	pByte='p'.encode('utf-8')
	sentLen=send(sock,pByte)
	if sentLen!=len(pByte):
		sock.close()
		return None
	# generate random a and calc A
	a=random.randint(0,N-1)
	A=calc_A(N,g,a)

	#send username and A
	A_bytes=int_to_bytes(A,64)
	username_bytes=username.encode('utf-8')
	lengthOfUsername=len(username_bytes)
	lenByte=int_to_bytes(lengthOfUsername,1)
	sentLen=send(sock,lenByte)
	if sentLen<1:
		sock.close()
		return None
	sentLen=send(sock,username_bytes)
	if sentLen<len(username_bytes):
		sock.close()
		return None
	sentLen=send(sock,A_bytes)
	if sentLen<len(A_bytes):
		sock.close()
		return None

	#recv s and B
	salt=receive(sock,16)
	B=receive(sock,64)

	if salt!=s:
		sock.close()
		return None
	#calc u
	u=calc_u(A,B)

	#calc k =h(N||g)
	concat=N_bytes+g_bytes
	dig=hashes.Hash(hashes.SHA256())
	dig.update(concat)
	k=dig.finalize()

	#calc x
	pw_bytes=pw.encode('utf-8')
	concat=salt+pw_bytes
	dig = hashes.Hash(hashes.SHA256())
	dig.update(concat)
	x_bytes = dig.finalize()
	x=bytes_to_int(x_bytes)

	#calc v
	v=pow(g,x,N)
	#calc K_client
	k_client=calc_K_client(N,B,k,v,a,u,x_bytes)
	#calc M1 and send
	M1=calc_M1(A,B,k_client)
	sentLen=send(sock,M1)
	if sentLen<len(M1):
		sock.close()
		return None

	M2=receive(sock,32)
	k_client_bytes=int_to_bytes(k_client,64)
	concat=A_bytes+M1+k_client_bytes
	dig = hashes.Hash(hashes.SHA256())
	dig.update(concat)
	M2Check=dig.finalize()
	if M2Check!=M2:
		sock.close()
		return None
	sock.close()
	return (a,k_client)



def server_protocol(sock, N, g, database):
	"""Handle the server's side of the consensus protocal.
       IMPORTANT: reading the initial 'p' has been handled for
       you.

    PARAMETERS
    ==========
    sock: A socket object that contains the client connection.
    N: A safe prime. Could be an integer or bytes object.
    g: A primitive root of the safe prime. Could be an integer or bytes object.
    database: A dictionary of all registered users. The keys are usernames
       (as strings!), and the values are tuples of the form (s, v), where s
       is the salt (16 bytes) and v is as per the assignment (integer).

    RETURNS
    =======
    If successful, return a tuple of the form (username, b, K_server), where both b and
       K_server are integers while username is a string. If not, return None.
    """
	if isinstance(N,bytes):
		N_bytes=N
		N=bytes_to_int(N)
	else:
		N_bytes=int_to_bytes(N,64)
	if isinstance(g,bytes):
		g_bytes=g
		g=bytes_to_int(g)
	else:
		g_bytes=int_to_bytes(g,64)
	b=random.randint(0,N-1)
	concat = N_bytes + g_bytes
	dig = hashes.Hash(hashes.SHA256())
	dig.update(concat)
	k = dig.finalize()
	data=receive(sock,1)
	lenUser=bytes_to_int(data)
	user=receive(sock,lenUser)
	A=receive(sock,64)
	if user==b'' or A==b'':
		sock.close()
		return None

	username=user.decode('utf-8')
	reply=database.get(username)
	if reply==None:
		sock.close()
		return None
	s=reply[0]
	v=reply[1]
	B=calc_B(N,g,b,k,v)
	B_bytes=int_to_bytes(B,64)
	if len(s)!=16 or len(B_bytes)!=64:
		sock.close()
		return None

	concat=s+B_bytes
	if len(concat)!=80:
		sock.close()
		return None
	lenSent=send(sock,concat)
	if lenSent<80:
		sock.close()
		return None
	u=calc_u(A,B)
	k_server=calc_K_server(N,A,b,v,u)
	k_server_bytes=int_to_bytes(k_server,64)
	M1=receive(sock,32)
	if M1==b'':
		sock.close()
		return None
	concat=A+B_bytes+k_server_bytes
	dig = hashes.Hash(hashes.SHA256())
	dig.update(concat)
	if M1!=dig.finalize():
		sock.close()
		return None
	
	M2=calc_M2(A,M1,k_server)
	
	lenSent=send(sock,M2)
	if lenSent<32:
		sock.close()
		return None
	sock.close()
	return (username,b,k_server)


# delete this comment and insert your code here

##### MAIN

if __name__ == '__main__':

	# parse the command line args
	cmdline = argparse.ArgumentParser(description="Test out a secure key exchange algorithm.")

	methods = cmdline.add_argument_group('ACTIONS', "The three actions this program can do.")

	methods.add_argument('--client', metavar='IP:port', type=str, \
								help='Perform registration and the protocol on the given IP address and port.')
	methods.add_argument('--server', metavar='IP:port', type=str, \
								help='Launch the server on the given IP address and port.')
	methods.add_argument('--quit', metavar='IP:port', type=str, \
								help='Tell the server on the given IP address and port to quit.')

	methods = cmdline.add_argument_group('OPTIONS', "Modify the defaults used for the above actions.")

	methods.add_argument('--username', metavar='NAME', type=str, default="admin", \
								help='The username the client sends to the server.')
	methods.add_argument('--password', metavar='PASSWORD', type=str, default="swordfish", \
								help='The password the client sends to the server.')
	methods.add_argument('--salt', metavar='FILE', type=argparse.FileType('rb', 0), \
								help='A specific salt for the client to use, stored as a file. Randomly generated if not given.')
	methods.add_argument('--timeout', metavar='SECONDS', type=int, default=600, \
								help='How long until the program automatically quits. Negative or zero disables this.')
	methods.add_argument('-v', '--verbose', action='store_true', \
								help="Be more verbose about what is happening.")

	args = cmdline.parse_args()

	# handle the salt
	if args.salt:
		salt = args.salt.read(16)
	else:
		salt = client_prepare()

	if args.verbose:
		print(f"Program: Using salt <{salt.hex()}>")

	# first off, do we have a timeout?
	killer = None  # save this for later
	if args.timeout > 0:

		# define a handler
		def shutdown(time, verbose=False):

			sleep(time)
			if verbose:
				print("Program: exiting after timeout.", flush=True)

			return  # optional, but I like having an explicit return


		# launch it
		if args.verbose:
			print("Program: Launching background timeout.", flush=True)
		killer = Process(target=shutdown, args=(args.timeout, args.verbose))
		killer.daemon = True
		killer.start()

	# next off, are we launching the server?
	result = None  # pre-declare this to allow for cascading

	server_proc = None
	if args.server:
		if args.verbose:
			print("Program: Attempting to launch server.", flush=True)
		result = split_ip_port(args.server)

	if result is not None:

		IP, port = result
		if args.verbose:
			print(f"Server: Asked to start on IP {IP} and port {port}.", flush=True)
			print(f"Server: Generating N and g, this will take some time.", flush=True)
		N, g, k = server_prepare()
		if args.verbose:
			print(f"Server: Finished generating N and g.", flush=True)


		# use an inline routine as this doesn't have to be globally visible
		def server_loop(IP, port, N, g, k, verbose=False):

			database = dict()  # for tracking registered users

			sock = create_socket(IP, port, listen=True)
			if sock is None:
				if verbose:
					print(f"Server: Could not create socket, exiting.", flush=True)
				return

			if verbose:
				print(f"Server: Beginning connection loop.", flush=True)
			while True:

				(client, client_address) = sock.accept()
				if verbose:
					print(f"Server: Got connection from {client_address}.", flush=True)

				mode = receive(client, 1)
				if len(mode) != 1:
					if verbose:
						print(f"Server: Socket error with client, closing it and waiting for another connection.", flush=True)
					client.shutdown(socket.SHUT_RDWR)
					client.close()
					continue

				if mode == b'q':
					if verbose:
						print(f"Server: Asked to quit by client. Shutting down.", flush=True)
					client.shutdown(socket.SHUT_RDWR)
					client.close()
					sock.shutdown(socket.SHUT_RDWR)
					sock.close()
					return

				elif mode == b'r':
					if verbose:
						print(f"Server: Asked to register by client.", flush=True)

					temp = server_register(client, N, g, database)
					if (temp is None) and verbose:
						print(f"Server: Registration failed, closing socket and waiting for another connection.", flush=True)
					elif temp is not None:
						if verbose:
							print(f"Server: Registration complete, current users: {[x for x in temp]}.", flush=True)
						database = temp

				elif mode == b'p':
					if verbose:
						print(f"Server: Asked to generate shared secret by client.", flush=True)

					temp = server_protocol(client, N, g, database)
					if (temp is None) and verbose:
						print(f"Server: Protocol failed, closing socket and waiting for another connection.", flush=True)
					elif type(temp) == tuple:
						if verbose:
							print(f"Server: Protocol complete, negotiated shared key for {temp[0]}.", flush=True)
							print(f"Server:  Shared key is {temp[2]}.", flush=True)


		# clean up is done inside the functions
		# loop back

		# launch the server
		if args.verbose:
			print("Program: Launching server.", flush=True)
		p = Process(target=server_loop, args=(IP, port, N, g, k, args.verbose))
		p.daemon = True
		p.start()
		server_proc = p

	# finally, check if we're launching the client
	result = None  # clean this up

	client_proc = None
	if args.client:
		if args.verbose:
			print("Program: Attempting to launch client.", flush=True)
		result = split_ip_port(args.client)

	if result is not None:

		IP, port = result
		if args.verbose:
			print(f"Client: Asked to connect to IP {IP} and port {port}.", flush=True)


		# another inline routine
		def client_routine(IP, port, username, pw, s, verbose=False):

			if verbose:
				print(f"Client: Beginning registration.", flush=True)

			results = client_register(IP, port, username, pw, s)
			if results is None:
				if verbose:
					print(f"Client: Registration failed, not attempting the protocol.", flush=True)
				return
			else:
				N, g, v = results
				if verbose:
					print(f"Client: Registration successful, g = {g}.", flush=True)

			if verbose:
				print(f"Client: Beginning the shared-key protocol.", flush=True)

			results = client_protocol(IP, port, N, g, username, pw, s)
			if results is None:
				if verbose:
					print(f"Client: Protocol failed.", flush=True)
			else:
				a, K_client = results
				if verbose:
					print(f"Client: Protocol successful.", flush=True)
					print(f"Client:  K_client = {K_client}.", flush=True)

			return


		# launch the server
		if args.verbose:
			print("Program: Launching client.", flush=True)
		p = Process(target=client_routine, args=(IP, port, args.username, args.password, salt, args.verbose))
		p.daemon = True
		p.start()
		client_proc = p

	# finally, the quitting routine
	result = None  # clean this up

	if args.quit:
		# defer on the killing portion, in case the client is active
		result = split_ip_port(args.quit)

	if result is not None:

		IP, port = result
		if args.verbose:
			print(f"Quit: Asked to connect to IP {IP} and port {port}.", flush=True)
		if client_proc is not None:
			if args.verbose:
				print(f"Quit: Waiting for the client to complete first.", flush=True)
			client_proc.join()

		if args.verbose:
			print("Quit: Attempting to kill the server.", flush=True)

		# no need for multiprocessing here
		sock = create_socket(IP, port)
		if sock is None:
			if args.verbose:
				print(f"Quit: Could not connect to the server to send the kill signal.", flush=True)
		else:
			count = send(sock, b'q')
			if count != 1:
				if args.verbose:
					print(f"Quit: Socket error when sending the signal.", flush=True)
			elif args.verbose:
				print(f"Quit: Signal sent successfully.", flush=True)

			sock.shutdown(socket.SHUT_RDWR)
			sock.close()

	# finally, we wait until we're told to kill ourselves off, or both the client and server are done
	while not ((server_proc is None) and (client_proc is None)):

		if not killer.is_alive():
			if args.verbose:
				print(f"Program: Timeout reached, so exiting.", flush=True)
			if client_proc is not None:
				client_proc.terminate()
			if server_proc is not None:
				server_proc.terminate()
			exit()

		if (client_proc is not None) and (not client_proc.is_alive()):
			if args.verbose:
				print(f"Program: Client terminated.", flush=True)
			client_proc = None

		if (server_proc is not None) and (not server_proc.is_alive()):
			if args.verbose:
				print(f"Program: Server terminated.", flush=True)
			server_proc = None

#    exit()