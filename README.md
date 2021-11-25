A basic implementation of the famous **Data Encryption Standard** algorithm (DES) in C. This implementation was written for educational purpose and is NOT meant to be used in real applications.

Usage:
===========
- Compile as `$ make clean && make`
- Run as `$ ./des.out [mode] [input_file] [output_file]`
- Available modes:
  - `e` for encryption
  - `d` for decryption
- Usage examples:
  - Encryption: `$ ./des.out e plain.txt cipher.txt`
  - Decreption: `$ ./des.out d cipher.txt orig.txt`
