Files Submitted: encrypt_modify.py
DESCRIPTION: There are functions to check for encrypt, pad, decrypt, generating password based on information we have, and changing contents of it and re-encrypt it.
The problem was solved in full. 
Was able to decrpyt where it was possible using the generated passwords. 
There are no known bugs.
Libraries used:
	cryptography- which was the base library.
	os- which was used for generating random initailization vector (IV)
	datetime- this was just used for generating the passwords and storing as a list in a particular format.