//////////////////////////////////////////////
//											//
// 			   Author: Osama Attia			//
//			   ogamal@iastate.edu			//
//											//
//////////////////////////////////////////////

#include "stdio.h"
#include "stdlib.h"
#include "string.h"
                  
// Including DES permutation tables, S-Boxes
#include "tables.h"

// Usage message
char *usage_msg = "USAGE:\n\
\t$ ./des.out [mode] [input_file] [output_file]\n\n\
MODES:\n\
\te for encryption\n\
\td for decryption\n\n\
EXAMPLES:\n\
\t$ ./des.out e plain.txt cipher.txt\n\
\t$ ./des.out d cipher.txt orig.txt\n";

// Define 64-bit integer
typedef unsigned long long uint64;

// ENCRYPTION KEY
uint64 encKey = 0x133457799BBCDFF1;

// Extract bit i from an int, where i from 0 to 63
int getBit (uint64 ch, int i) {
    return (ch >> (63 - i)) & 0x01;
}

// Pack 8 characters in one long long integer of 64bit size
uint64 pack64 (char ch[]) {
	int i = 0;
	uint64 packed = ch[i];
	
	for (i = 1; i < 8; i++) {
		packed <<= 8;
		packed |= (uint64)ch[i];
	}
	
	return packed;
}

// Function to unpack the input back to 8 characters
// It unpacks them in the public array outCh
void unpack64 (uint64 input, char *outCh) {
	int i = 0; for (; i < 8; i++)
		outCh[i] = 0;
	
	for (i = 0; i < 64; i++) {
		outCh[i / 8] |= getBit(input, i);
		if ((i + 1) % 8 != 0)
			outCh[i / 8] <<= 1;
	}
}

// Print the bits of a block. You can use this for debugging
void printBits (uint64 block, int size) {
	int i = 0; for (; i < size; i++) {
		printf("%d", getBit(block, i));
		if ((i + 1) % 8 == 0)
			printf(" ");
	}
}

// Function to permutate input block according to the permutation table
// It outputs a block of the target size
uint64 permute (uint64 input, int output_size, int perm_table[], int offset) {
	uint64 output = 0;
	
	int i = 0; for (; i < output_size; i++) {
		output |= getBit(input, perm_table[i] - 1 + offset);
		if (i != output_size - 1)
			output <<= 1;
	}

	// Shift the key bits to fix the length issue
	output <<= 64 - output_size;
	
	return output;
}

// Shift key
uint64 shift_key (uint64 inputKey, int round) {
	// Shift key halfs to the left according to the shift table
	int i, temp;
	uint64 outputKey = 0;
		
	// Shifting the left half bits from 0 to 27
	temp = getBit(inputKey, 0);
	for (i = 1; i < 28; i++) {
		outputKey |= getBit(inputKey, i);
		outputKey <<= 1;
	}
	outputKey |= temp; outputKey <<= 1;
	
	// Shifting the right half bits from 28 to 47
	temp = getBit(inputKey, 28);
	for (i = 29; i < 56; i++) {
		outputKey |= getBit(inputKey, i);
		outputKey <<= 1;
	}
	outputKey |= temp;
	
	// Shift the key 8 bits to fix the length issue
	outputKey <<= 8;
	
	// If NOT rounds, 1, 2, 9, or 16 .. Shift again!
	switch (round) {
		case 1: case 2: case 9: case 16: break;
		default: outputKey = shift_key(outputKey, 1); break;
	}

	return outputKey;
}

// Substitute the input according to the s-boxes, converting it from 48-bit to 32-bit
uint64 s_box (uint64 inputBlock) {
	uint64 outputBlock = 0;
	
	// Dividing the input into blocks of 6 bits
	int i = 0; for (; i < 8; i ++) {
		int x = i * 6;
		// Selecting the row with the first and last bit in the 6-bit block
		int row = getBit(inputBlock, x) * 2 + getBit(inputBlock, x + 5);

		// Selecting the column with the remaining bits in the middle
		int col = getBit(inputBlock, x + 1) * 8 + getBit(inputBlock, x + 2) * 4 + getBit(inputBlock, x + 3) * 2 + getBit(inputBlock, x + 4);
		
		// Getting the value from the s-box and preparing it
		uint64 temp = S[i][row][col];
		temp <<= 60;
		
		// Adding the bits to the output
		int j = 0; for (; j < 4; j++) {
			outputBlock |= getBit(temp, j);
			if (!(j == 3 && i == 7))
				outputBlock <<= 1;
		}
	}
			
	outputBlock <<= 32;
	
	return outputBlock;
}

// Do one DES round to the input using the enterd key
// InputBlock of length 64bit, and key of length 48bit
uint64 des_round (uint64 inputBlock, uint64 key) {
	uint64 outputBlock = 0;
	
	// Adding the right half of the old cipher to the new one
	int i = 32; for (; i < 64; i++) {
		outputBlock |= getBit(inputBlock, i);
		outputBlock <<= 1;
	}
	
	// Expanding the right half of the old cipher into 48 bits and XOR it with the key
	key = key ^ permute(inputBlock, 48, E, 32);
		
	// Substitute the key using the S-Box, converting it into 32 bit again
	key = s_box(key);
		
	// Permutating the key for the last damn time using P table
	key = permute(key, 32, P, 0);
	
	// XORing the permutated text with the left half of the input
	key = key ^ inputBlock;
	
	// Appending the left half XORed with the edited key to the output
	for (i = 0; i < 32; i++) {
		outputBlock |= getBit(key, i);
		if (i != 31)
			outputBlock <<= 1;
	}
	
	return outputBlock;
}

// Function to encrypt/decrypt
uint64 cryptBlock (uint64 input, uint64 *subkey, char *mode) {
	uint64 output = 0;
	int round = 1;
	
	// Initial permutating the block
	output = permute(input, 64, IP, 0);
	
	// Permutating the subkeys and doing the DES 16 encryption rounds
	for (round = 0; round <= 15; round++) {
		// Encrypt
		if (strncmp(mode, "e", 1) == 0) {
			output = des_round(output, permute(subkey[round], 48, PC2, 0));
		}
		// Decrypt
		else if (strncmp(mode, "d", 1) == 0) {
			output = des_round(output, permute(subkey[15 - round], 48, PC2, 0));
		// Error
		} else {
			printf("Error: Invalid [mode] argument!\n");
			printf("%s", usage_msg);
			exit(1);
		}
	}
	
	// Swap the two halves of the text
	int i = 0; for(; i < 32; i++) {
		int temp = getBit(output, 0);
		output <<= 1; output |= temp;
	}
		
	// Inverse the initial permutation
	output = permute(output, 64, FP, 0);
		
	return output;
}

// Do DES encryption/decryption based on the mode
void des (char *mode, char *inputfile, char *outputfile) {
	FILE *read_fp, *write_fp;
	char ch[8], outCh[8]; int i = 0;
	uint64 inputBlock = 0, outputBlock = 0, subkey[16];
	
	// Open input file
	read_fp = fopen(inputfile, "rb");
	if (read_fp == NULL) {
		printf("Error: Couldn't open the input file '%s'!\n", inputfile);
		printf("%s", usage_msg);
		exit(1);
	}
	
	// Open output file
	write_fp = fopen(outputfile, "wb+");
	if (write_fp == NULL) {
		printf("Error: Could't open the output file '%s'!\n", outputfile);
		printf("%s", usage_msg);
		exit(0);
	}
	
	// Permutate the key, converting it from 64-bit to 56-bit
	encKey = permute(encKey, 56, PC1, 0);
			
	// Generating the subkeys
	subkey[0] = shift_key(encKey, 1);
	for (i = 1; i <= 15; i++)
		subkey[i] = shift_key(subkey[i - 1], i + 1);
	
	int bytes_read = 1;	
	while (!feof(read_fp)) {
		// Read 8 bytes from the input file
		bytes_read = fread(&inputBlock, 1, 8, read_fp);
		
		// Encrypt/Decrypt the input block
		outputBlock = cryptBlock(inputBlock, subkey, mode);
		
		// Print 8 bytes to the output file
		fwrite(&outputBlock, 1, 8, write_fp);
	}
	
	// Closing files
	fclose(read_fp);
	fclose(write_fp);		
}

int main (int argc, char *argv[]) {
	char *mode, *inputfile, *outputfile;
	
	// Reading the plain text file
	if (argc == 4) {
		mode = argv[1];
		inputfile = argv[2];
		outputfile = argv[3];
	} else {
		printf("Error: Invalid number of parameters!\n");
		printf("%s", usage_msg);
		exit(1);
	}
	
	// Execute DES
	des(mode, inputfile, outputfile);

	// Return and end main :)
	return 0;
}
