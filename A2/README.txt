Files Submitted: basic_auth.py
Description: A modified Diffie Hellman Key Exchange protocol implementation

Generating safe primes (N bit long):
- Generated N-1 bit random prime number
- Then multiplied it to 2 and added 1 to the product
- If the result is also a prime, we have generated a safe prime of N bits
- If not go back to generating and calculating

Generating primitive root of N
- We get all prime factors of N-1
- Then we check for every number j, from 2 to N-1,  and see if j^((N-1)/factor)  mod N = 1, where factor is each prime factor of N-1.
- If we found a factor that results in 1, i.e. if j^((N-1)/factor)  mod N=1 is satisfied for any factor, then j is not a primitive root. If no factor results in the equation to satisfy, then it is a primitive root of N.

The problem is solved in full.

There is one bug that is basically the receive does not work as it should when listening to multiple values which was not necessary for this problem. Otherwise, there are no known bugs.

Libraries used: Sympy - for prime related work
		Random - to generate random num
		os - generate random byte
		socket - for communicating between client and server
		cryptography - for hashing

