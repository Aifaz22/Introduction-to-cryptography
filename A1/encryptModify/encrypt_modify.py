#!/usr/bin/env python3

import argparse
from sys import exit
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding

# Insert your imports here
from cryptography.hazmat.primitives import ciphers
from datetime import timedelta, date


def string_to_bytes( string ):
   """A helper function to convert strings into byte objects.

   PARAMETERS
   ==========
   input: A string to be converted to bytes.

   RETURNS
   =======
   A bytes version of the string.
   """

   return string.encode('utf-8')


def create_iv( length=16 ):
   """Create an initialization vector to be used during encryption.
      Should be cryptographically random.

   PARAMETERS
   ==========
   length: How many bytes long the IV should be.

   RETURNS
   =======
   A bytes object "length" bytes long.
   """
   iv = os.urandom(length)
   return iv

   # delete this comment and insert your code here

def derive_key( input ):
   """Create a key to use with AES-128 encryption by hashing a string
      and keeping only the first 16 bytes.

   PARAMETERS
   ==========
   input: A string, to be used to create a key.

   RETURNS
   =======
   A bytes object 16 bytes long.
   """
   res= hashes.Hash(hashes.SHA224())
   res.update(string_to_bytes(input))
   result=res.finalize()
   return result[:16]

   # delete this comment and insert your code here

def pad_bytes( input ):
   """Pad the given input to ensure it is a multiple of 16 bytes,
      via PKCS7.

   PARAMETERS
   ==========
   input: A bytes object to be padded.

   RETURNS
   =======
   A bytes object that has had padding applied.
   """
   pad_ob = padding.PKCS7(128).padder()
   msg_pad = pad_ob.update(input)
   msg_pad += pad_ob.finalize()
   return msg_pad
   # delete this comment and insert your code here

def encrypt_bytes( input, key, iv ):
   """Encrypt the given input with the given key using AES-128.
      Assumes the input has been padded to the appropriate length.

   PARAMETERS
   ==========
   input: A bytes object to be encrypted.
   key: A bytes object, 16 bytes long, to be used as a key.
   iv: A bytes object, 16 bytes long, to be used as an initialization
     vector.

   RETURNS
   =======
   A bytes object that has been encrypted.
   """
   aes_cipher = ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.CBC(iv))
   aes_encryptor = aes_cipher.encryptor()
   ciphertext = aes_encryptor.update(input)
   ciphertext += aes_encryptor.finalize()
   return ciphertext
   # delete this comment and insert your code here

def hash_pad_then_encrypt( input, string, iv ):
   """Combine the prior routines to convert the string into a key,
      append a hash of the input to its end, pad both to the 
      appropriate length, encrypt the padded input, and return that 
      with the IV prepended.

   PARAMETERS
   ==========
   input: A bytes object to be encrypted.
   string: A string to be used as a key.
   iv: A bytes object, 16 bytes long, to be used as an initialization
     vector.

   RETURNS
   =======
   A bytes object in the form IV + cyphertext.
   """
   #convert string into key
   key=derive_key(string)
   #hash input
   res = hashes.Hash(hashes.SHA224())
   res.update(input)
   result = res.finalize()
   #append to the end of key
   inpHash = input + result
   #pad
   m=pad_bytes(inpHash)
   ctxt=encrypt_bytes(m,key,iv)
   final=iv+ctxt
   return final
   # delete this comment and insert your code here


def check_tag( input ):
   """Check the SHA2 224 hash appended to the given input byte array.
      Use the return value to flag if the tag matched

   PARAMETERS
   ==========
   input: A bytes object with a SHA2 224 hash appended to it.

   RETURNS
   =======
   If the tag matches the input, the return value is a bytes object with
     the tag stripped out. If it does not, the return is None.
   """
   hash=input[len(input)-28:len(input)]
   msg=input[:len(input)-28]
   res = hashes.Hash(hashes.SHA224())
   res.update(msg)
   result = res.finalize()
   if result == hash:
      return msg
   else:
      return None

   # delete this comment and insert your code here

def decrypt_unpad_check( input, string ):
   """Combine the prior routines to convert the string into a key,
      extract out the IV, decrypt the remainder, unpad whatever decrypted,
      and check the SHA2 224 tag appended to the end.

   PARAMETERS
   ==========
   input: A bytes object to be decrypted according to the above.
   string: A string to be used as a key.

   RETURNS
   =======
   If the input could be decoded and the tag matches, the return value is a 
     bytes object containing the plaintext. In all other cases, the return is 
     None.
   """
   key=derive_key(string)
   iv=input[:16]
   ctext=input[16:]
   aes_cipher = ciphers.Cipher(ciphers.algorithms.AES(key), ciphers.modes.CBC(iv))
   aes_decryptor = aes_cipher.decryptor()
   plain = aes_decryptor.update(ctext) + aes_decryptor.finalize()

   try:
      unpadder = padding.PKCS7(128).unpadder()
      data = unpadder.update(plain)
      data += unpadder.finalize()
   except:
      return None


   res=check_tag(data)
   return res
   # delete this comment and insert your code here

def generate_passwords( year=1984, month=1, day=1 ):
   """A generator that outputs passwords of the form "YYYYMMDD", starting from
      the given date. The defaults match with the assignment requirements.
      Do not generate dates in the future, where "future" is in reference to the
      day this code is executed.

   PARAMETERS
   ==========
   year: An integer representing the year.
   month: The above, but for months.
   day: The above, but for days.

   RETURNS
   =======
   A string of the form "YYYYMMDD", a numeric value for a specific date.
   """
   PasswordList=[]


   def daterange(date1, date2):
      for n in range(int((date2 - date1).days) + 1):
         yield date1 + timedelta(n)

   start = date(year, month, day)
   end = date.today()
   for dt in daterange(start, end):
      PasswordList.append(dt.strftime("%Y%m%d"))

   return PasswordList
   # delete this comment and insert your code here

def determine_password( input ):
   """For the given encrypted input, attempt to brute-force the password used
      to encrypt it. This routine makes no attempt to check for the codeword,
      but it will reject a tag that doesn't match.

   PARAMETERS
   ==========
   input: A bytes object containing the encrypted input. "Encrypted" means the
     output of hash_pad_then_encrypt(), not just the encrypted phase.

   RETURNS
   =======
   Either a tuple of the form (plaintext, password), or None if the password 
     couldn't be determined.
     "plaintext" is the fully decrypted content, as a bytes object, with no padding or tag added.
     "password" is the password used during encryption, as a string.
   """
   passList=generate_passwords()
   for i in passList:
      plaintext=decrypt_unpad_check(input, i)
      if plaintext != None:
         return (plaintext,i)
   return None


   # delete this comment and insert your code here

def attempt_substitute( input, codeword, target, substitute ):
   """Brute-force the password for input, and if successfully decrypted check that it
      contains "codeword". If it does, swap "target" for "substitute", re-encrypt
      with the same password, and return the encrypted version.

   PARAMETERS
   ==========
   input: A bytes object to be decrypted.
   codeword: A string that must be present in the decrypted input.
   target: A string that we're searching for in the decrypted input.
   substitute: A string to replace "target" with in the plaintext.

   RETURNS
   =======
   If the input could be decrypted and the codeword was present, return the modified
     plaintext encrypted with the same key but a different IV; no modifications counts 
     as a successful modification. If the input could not be decrypted, or the 
     codeword was absent, return None.
   """
   tuple=determine_password(input)
   if tuple==None:
      return None
   plaintext=tuple[0]
   cword=string_to_bytes(codeword)
   i=plaintext.find(cword)
   if i==-1:
      return None
   tar=string_to_bytes(target)
   sub=string_to_bytes(substitute)
   modPT=plaintext.replace(tar,sub)
   password=tuple[1]
   iv=create_iv()
   final=hash_pad_then_encrypt(modPT,password,iv)
   return final
   # delete this comment and insert your code here


if __name__ == '__main__':

   cmdline = argparse.ArgumentParser(description="Modify one of Bob's encrypted files.")
   cmdline.add_argument( 'output', metavar='FILE', type=argparse.FileType('wb', 0), help='The destination file for one of the above actions.' )

   methods = cmdline.add_argument_group( 'MODES', "The three modes you can run this program in." )
   methods.add_argument( '--encrypt', metavar='FILE', type=argparse.FileType('rb', 0), help='Encrypt the given file. Useful for debugging.' )
   methods.add_argument( '--decrypt', metavar='FILE', type=argparse.FileType('rb', 0), help='Decrypt the given file. Useful for debugging.' )
   methods.add_argument( '--modify', metavar='FILE', type=argparse.FileType('rb', 0), help='Perform the modification the question asks for.' )

   enc_dec = cmdline.add_argument_group( 'ENCRYPTION/DECRYPTION OPTIONS', "When in encryption or decryption mode, use these options." )
   enc_dec.add_argument( '--iv', metavar='FILE', type=argparse.FileType('rb', 0), help='A binary file to use as an IV. Useful for debugging.' )
   enc_dec.add_argument( '--password', metavar='STRING', default="19850101", help='A string to use as a password. Useful for debugging.' )
   enc_dec.add_argument( '--verify', metavar='FILE', type=argparse.FileType('rb', 0), help='Compare what would have been written to the given file. Useful for debugging.' )

   modify  = cmdline.add_argument_group( 'MODIFICATION OPTIONS', "Use these options during modification. The defaults line up with the assignment requirements." )
   modify.add_argument( '--codeword', metavar='STRING', default="FOXHOUND", help='A string that Bob always includes in their messages.' )
   modify.add_argument( '--target', metavar='STRING', default="CODE-RED", help="The string to be replaced in Bob's messages." )
   modify.add_argument( '--substitute', metavar='STRING', default="CODE-BLUE", help="The replacement for the above string." )

   args = cmdline.parse_args()

   block_bits  = 128
   block_bytes = block_bits >> 3

   if args.iv:
       iv = args.iv.read( block_bytes )
   else:
       iv = create_iv( block_bytes )

   output = bytes()

   if args.encrypt:

       input = args.encrypt.read()
       output = hash_pad_then_encrypt( input, args.password, iv )

   elif args.decrypt:

       input = args.decrypt.read()
       output = decrypt_unpad_check( input, args.password )
       if output is None:
          print( f"Darn, {args.decrypt.name} could not be decrypted with \"{args.password}\" and the given IV." )
          exit( 1 )
    
   elif args.modify:

       input = args.modify.read()
       output = attempt_substitute( input, args.codeword, args.target, args.substitute )
       if output is None:
          print( f"Shoot, {args.modify.name} could not be modified. Check your code, and ask a TA if you can't figure out what's wrong." )
          exit( 1 )
    
   if args.verify:
       validate = args.verify.read()
       if output == validate:
          print( f"Success! {args.output.name} and {args.verify.name} match." )
       else:
          print( f"Uh oh, {args.output.name} and {args.verify.name} differ. Check your code, and ask a TA if you can't figure out what's wrong." )

   args.output.write( output )
