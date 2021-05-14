Files Submitted: prefix_collision.py
DESCRIPTION: This program basically tries to find collisions in SHA-2 224 hashes when they are trimmed off to a particular length and stored. There are functions to check for collisions, hash a plaintext and also to fid collisions.
The problem was solved in full. 
Was able to find collisions of the hashes with first length characters. 
Data sructure used was Hashmap, so it checks and accesses the character in constant time.
There are no known bugs. But when the parameter length for find_collision method is too small, the program may not be able to detect collisions properly since the strings generated are of size- 2^length.
Libraries used:
	cryptography- which was the base library.
	os- which was used for generating random strings
	time- this was just used for a timeout (2 min) while finding collisions but this is rarely used