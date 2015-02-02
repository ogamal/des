# Data Encryption Standard Algorithm (DES)

- An implementation of the famous DES encryption algorithm in C.
- Files:
      - des.c, tables.h, Makefile

- COMPILE:
    $ make clean; make

- USAGE:

  	$ ./des.out [mode] [input_file] [output_file]

- MODES:
 
  	e for encryption

	  d for decryption

- USAGE EXAMPLES:

	  $ ./des.out e plain.txt cipher.txt
	
	  $ ./des.out d cipher.txt orig.txt
