/**
	File: bchoc.cpp
	Purpose:
		
*/

//standard support libraries
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
//library supporting hashes
#include <openssl/md5.h>
#include <openssl/sha.h>

//indicate the "std" namesapce is in use for this file scope
using namespace std;

//define the fundamental Block struct
const int BLOCK_PREV_HASH_SIZE = 64; //directions say "32 bytes" but also a SHA-256 hash which is 64 bytes
const int BLOCK_TIMESTAMP_SIZE = 8;
const int BLOCK_CASE_ID_SIZE = 32;
const int BLOCK_ITEM_ID_SIZE = 32;
const int BLOCK_STATE_SIZE = 12;
const int BLOCK_CREATOR_SIZE = 12;
const int BLOCK_OWNER_SIZE = 12;
const int BLOCK_DATA_LEN_SIZE = 4;

//define the fields of the Block
unsigned char blockPrevHash[BLOCK_PREV_HASH_SIZE];
unsigned char blockTimestamp[BLOCK_TIMESTAMP_SIZE];
unsigned char blockCaseID[BLOCK_CASE_ID_SIZE];
unsigned char blockItemID[BLOCK_ITEM_ID_SIZE];
unsigned char blockState[BLOCK_STATE_SIZE];
unsigned char blockCreator[BLOCK_CREATOR_SIZE];
unsigned char blockOwner[BLOCK_OWNER_SIZE];
//make a union to simplify data access in memory
union
{
	unsigned int  intLen;
	unsigned char byteLen[4];
} blockDataLen;
//after these defined sections will be a dynamic data field that can
//be 0 - 2^32 bytes long per the value in dataLen

//each block will be followed by it's SHA-256 hash (32bytes)
unsigned char blockCurHash[BLOCK_PREV_HASH_SIZE];

//define constants for this effort (all of the following are in bytes)
const string COC_FILE = "CoC.txt";
//Size & offset constants for each block (before variable data field)
/*
	Data Layout
	Byte 0-63	= Previous Hash
	Byte 64-71	= Timestamp
	Byte 72-103	= Case ID
	Byte 104-135= Evidence Item ID
	Byte 136-147= State
	Byte 148-159= Creator
	Byte 160-171= Owner
	Byte 172-175= Data Length
*/
const int BLOCK_PREV_HASH_OFFSET = 0;
const int BLOCK_TIMESTAMP_OFFSET = BLOCK_PREV_HASH_OFFSET + BLOCK_PREV_HASH_SIZE;
const int BLOCK_CASE_ID_OFFSET = BLOCK_TIMESTAMP_OFFSET + BLOCK_TIMESTAMP_SIZE;
const int BLOCK_ITEM_ID_OFFSET = BLOCK_CASE_ID_OFFSET + BLOCK_CASE_ID_SIZE;
const int BLOCK_STATE_OFFSET = BLOCK_ITEM_ID_OFFSET + BLOCK_ITEM_ID_SIZE;
const int BLOCK_CREATOR_OFFSET = BLOCK_STATE_OFFSET + BLOCK_STATE_SIZE;
const int BLOCK_OWNER_OFFSET = BLOCK_CREATOR_OFFSET + BLOCK_CREATOR_SIZE;
const int BLOCK_DATA_LEN_OFFSET = BLOCK_OWNER_OFFSET + BLOCK_OWNER_SIZE;
const int BLOCK_DATA_OFFSET = BLOCK_DATA_LEN_OFFSET + BLOCK_DATA_LEN_SIZE;
const int BLOCK_MIN_SIZE = BLOCK_DATA_OFFSET;

//to simplify state checking create an enumeration
enum evidenceState { INITIAL, CHECKEDIN, CHECKEDOUT, DISPOSED, DESTROYED, RELEASED };

//password constants
const string BCHOC_PASSWORD_POLICE = "P80P";
const string BCHOC_PASSWORD_LAWYER = "L76L";
const string BCHOC_PASSWORD_ANALYST = "A65A";
const string BCHOC_PASSWORD_EXECUTIVE = "E69E";
const string BCHOC_PASSWORD_CREATOR = "C67C";
//data encryption key
const char* AES_KEY = "R0chLi4uLi4uLi4";

/*
 * =============
 * Methods providing supporting functionality
 * =============
 */

 /**
 * @dev 
 */
bool fileExists()
{
	bool exists = false;
	//get the current contents of the blockchain
	FILE *fPtr;
	fPtr = fopen( COC_FILE.c_str(), "r" );
	//confirm the file exists before attempting to read it
	if( fPtr )
	{
		exists = true;
	}
	return exists;
}
 
/**
 * @dev file write method
 */
void writeToFile(string writeText)
{
	//append the passed text to the end of the file
	ofstream outFile;
	outFile.open( COC_FILE, std::ios::app );
	outFile << writeText;
	outFile.close();
}

/**
 * @dev Compute and return a SHA-256 hash
 */
string computeHash( string &contents )
{
	string hashResult;
	//use OpenSSL to compute the SHA256 hash
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, contents.c_str(), contents.size());
	SHA256_Final(hash, &sha256);
	stringstream ss;
	for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		ss << hex << setw(2) << setfill('0') << (int)hash[i];
	}
	//store the hash result
	hashResult = ss.str();
	
	return hashResult;
}

/**
 * @dev 
 */
bool cocIsInit()
{
	bool validInit = true;
	//confirm the file exists before attempting to read it
	validInit = fileExists();
	if( validInit )
	{
		//get the current contents of the blockchain
		FILE *fPtr;
		fPtr = fopen( COC_FILE.c_str(), "rb" );
		//get the state of the first block (SEEK_SET = start of file)
		fseek( fPtr, BLOCK_STATE_OFFSET, SEEK_SET );
		//copy the content into a local array
		unsigned char readState[BLOCK_STATE_SIZE];
		fread( readState, sizeof(char), BLOCK_STATE_SIZE, fPtr );
		//Compare to expected Init value
		unsigned char expectedState[] = {'I','N','I','T','I','A','L',
										'\0','\0','\0','\0','\0'};
		for( int pos = 0; pos < BLOCK_STATE_SIZE; pos++ )
		{
			//if any byte does not match, it is an invalid init block
			if( readState[pos] != expectedState[pos] )
			{
				validInit = false;
			}
		}
		//alert user of invalid INITIAL blocks
		if( false == validInit )
		{
			printf("Blockchain file found without an INITIAL block\n");
		}
		
		fclose(fPtr);
	}
	
	//return the result
	return validInit;
}

/**
 * @dev 
 */
void resetBlockBytes()
{
	//Initialize the fields
	memset( &blockPrevHash[0], 0, BLOCK_PREV_HASH_SIZE);
	memset( &blockTimestamp[0], 0, BLOCK_TIMESTAMP_SIZE);
	memset( &blockCaseID[0], 0, BLOCK_CASE_ID_SIZE);
	memset( &blockItemID[0], 0, BLOCK_ITEM_ID_SIZE);
	for( int i = 0; i < BLOCK_STATE_SIZE; i++ )
	{
		blockState[i] = '\0';
	}
	for( int i = 0; i < BLOCK_CREATOR_SIZE; i++ )
	{
		blockCreator[i] = '\0';
	}
	for( int i = 0; i < BLOCK_OWNER_SIZE; i++ )
	{
		blockOwner[i] = '\0';
	}
	blockDataLen.intLen = 0;
}

/**
 * @dev 
 */
string blockToString( string dataField )
{
	string completeBlock = "";
	//append the sections in order
	completeBlock.append((const char*)&blockPrevHash[0], BLOCK_PREV_HASH_SIZE);
	completeBlock.append((const char*)&blockTimestamp[0], BLOCK_TIMESTAMP_SIZE);
	completeBlock.append((const char*)&blockCaseID[0], BLOCK_CASE_ID_SIZE);
	completeBlock.append((const char*)&blockItemID[0], BLOCK_ITEM_ID_SIZE);
	completeBlock.append((const char*)&blockState[0], BLOCK_STATE_SIZE);
	completeBlock.append((const char*)&blockCreator[0], BLOCK_CREATOR_SIZE);
	completeBlock.append((const char*)&blockOwner[0], BLOCK_OWNER_SIZE);
	completeBlock.append((const char*)&blockDataLen.byteLen[0], BLOCK_DATA_LEN_SIZE);
	
	//append the data field (passed as an arg)
	completeBlock.append( dataField );
	//compute and append the hash value of this block
	completeBlock.append( computeHash(completeBlock) );
	
	return completeBlock;
}

/**
 * @dev 
 */
int getEvidenceState( unsigned char* itemToCheck )
{
	int latestState = -1;
	//confirm the file exists before attempting to read it
	if( fileExists() )
	{
		//store the reads of data
		unsigned char readPrevHash[BLOCK_PREV_HASH_SIZE];
		unsigned char readItem[BLOCK_ITEM_ID_SIZE];
		unsigned char readState[BLOCK_STATE_SIZE];
		unsigned int sizeOfBlock = 0;
		union
		{
			unsigned int intLen;
			unsigned char byteLen[4];
		} readDataLen;
		
		//get the current contents of the blockchain
		FILE* fPtr;
		fPtr = fopen( COC_FILE.c_str(), "rb" );
		fseek( fPtr, 0, SEEK_SET );
		//store the end of the file location
		FILE* endPtr;
		endPtr = fopen( COC_FILE.c_str(), "rb" );
		fseek( endPtr, 0, SEEK_END );
		
		//get the state of the first block (SEEK_SET = start of file)
		fseek( fPtr, BLOCK_DATA_LEN_OFFSET, SEEK_SET );
		//Initial block can be skipped, compute the offset to skip it
		//read the length of this data field
		fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
		//advance from the DataLen field to the end of the data field
		//(recall the "fread" advances the fPtr)
		fseek( fPtr, readDataLen.intLen, SEEK_CUR );
		//read the hash of this block before advancing to the next
		//and store it in the Previous Hash global variable
		fread( blockPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr );
		//we need to sequentially check every block to determine the latest
		//state of this evidence item
		while( (ftell(fPtr) + BLOCK_MIN_SIZE) < ftell(endPtr) )
		{
			printf("fPtr %d\n", ftell(fPtr));
			printf("endPtr %d\n", ftell(endPtr));
			//check hash on last block matches logged prevHash in current block
			fread( readPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr );
			bool hashMatch = true;
			if( 0 != memcmp(&blockPrevHash[0], &readPrevHash[0], BLOCK_PREV_HASH_SIZE) )
			{
				hashMatch = false;
			}
			
			//proceed with efforts if the hashes match
			if( hashMatch )
			{
				printf("Good chain link\n");
				//reset the Item ID to compare variable
				memset( &readItem[0], 0, BLOCK_ITEM_ID_SIZE);
				int offsetToNextField = 0;
				//advance from the end of the previous hash to the item id
				offsetToNextField = BLOCK_ITEM_ID_OFFSET - (BLOCK_PREV_HASH_OFFSET + BLOCK_PREV_HASH_SIZE);
				fseek( fPtr, offsetToNextField, SEEK_CUR );
				//read out the Item ID in this block
				fread( readItem, sizeof(char), BLOCK_ITEM_ID_SIZE, fPtr);
				bool itemMatch = true;
				for( int i = 0; i < BLOCK_STATE_SIZE; i++ )
				{
					if( readItem[i] != itemToCheck[i] )
					{
						itemMatch = false;
					}
				}
				if( itemMatch )
				{
					printf("Matching IDs\n");
					//advance from the end of the previous hash to the item id
					offsetToNextField = BLOCK_STATE_OFFSET - (BLOCK_ITEM_ID_OFFSET + BLOCK_ITEM_ID_SIZE);
					fseek( fPtr, offsetToNextField, SEEK_CUR );
					//read out the State in this block
					fread( readState, sizeof(char), BLOCK_STATE_SIZE, fPtr);
					//check for: CHECKEDIN, CHECKEDOUT, DESTROYED, DISPOSED, RELEASED
					if( 'C' == readState[0] )
					{
						if( 'I' == readState[7] )
						{
							latestState = (int)CHECKEDIN;
						}
						else if( 'O' == readState[7] )
						{
							latestState = (int)CHECKEDOUT;
						}
					}
					else if( 'D' == readState[0] )
					{
						if( 'E' == readState[1] )
						{
							latestState = (int)DESTROYED;
						}
						else if( 'I' == readState[1] )
						{
							latestState = (int)DISPOSED;
						}
					}
					else if( 'R' == readState[0] )
					{
						latestState = (int)RELEASED;
					}
					//After checking the state, advance to the data length field
					//from the end of the state field
					offsetToNextField = BLOCK_DATA_LEN_OFFSET - (BLOCK_STATE_OFFSET + BLOCK_STATE_SIZE);
					fseek( fPtr, offsetToNextField, SEEK_CUR );
				}
				else
				{
					//On no Item ID match, advance to the data length field
					//from the end of the Item ID field
					offsetToNextField = BLOCK_DATA_LEN_OFFSET - (BLOCK_ITEM_ID_OFFSET + BLOCK_ITEM_ID_SIZE);
					fseek( fPtr, offsetToNextField, SEEK_CUR );
				}
				
				//the fPtr has already been moved to the DataLen area by now
				fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
				//advance from the DataLen field to the end of the data field
				//(recall the "fread" advances the fPtr)
				fseek( fPtr, readDataLen.intLen, SEEK_CUR );
				//read the hash of this block before advancing to the next
				//and store it in the Previous Hash global variable
				fread( blockPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr );
			}
			else
			{
				printf("Blockchain corruption detected\n");
				//skip to end, bad blockchain
				fseek( fPtr, 0, SEEK_END );
				latestState = -2;
			}
		}
		fclose(fPtr);
	}
	return latestState;
}

/*
/**
 * @dev Encrypt an input byte array using the constant AES_KEY
 * @param Bytes to encrypt
 *
function encryptBytes( inputBytes )
{
	console.log( "Encrypting..." );
	let AES_KEY_length = byteEncoded.length; //how many unique bytes are in the key for XOR processing
	let encryptedBytes = [];
	//Perform byte-by-byte XOR operation to convert the input
	//into an encrypted byte value
	for( var i = 0; i < inputBytes.length; i++ )
	{
		let keyPos = i % AES_KEY_length;
		encryptedBytes = encryptedBytes.concat( byteEncoded[keyPos] ^ inputBytes[i] );
	}
	return encryptedBytes;
}

/**
 * @dev Decrypt an input byte array using the constant AES_KEY
 * @param Bytes to decrypt
 *
function decryptBytes( inputBytes )
{
	console.log( "Decrypting..." );
	let AES_KEY_length = byteEncoded.length; //how many unique bytes are in the key for XOR processing
	let decryptedBytes = [];
	//Perform byte-by-byte XOR operation to convert the input
	//back to its original byte value
	for( var i = 0; i < inputBytes.length; i++ )
	{
		let keyPos = i % AES_KEY_length;
		decryptedBytes = decryptedBytes.concat( byteEncoded[keyPos] ^ inputBytes[i] );
	}
	return decryptedBytes;
}
*/

/*
 * =============
 * Methods providing core functionality
 * =============
 */

/**
 * @dev 
 */
void addItemToCase()
{
	//before attempting to add a block,
	//clear out any existing data i nthe arrays
	resetBlockBytes();
	string tmpStr = "";
	//prepare garbage values
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	tmpStr = "Bababooey";
	memcpy( &itemID[0], tmpStr.c_str(), tmpStr.size() );
	
	string dataField = "Wowie";
	blockDataLen.intLen = dataField.size();
	
	int evidenceState = getEvidenceState( &itemID[0] );
	if( -1 == evidenceState)
	{
		printf("This is new evidence\n");
		
		memcpy( &blockItemID[0], &itemID[0], BLOCK_ITEM_ID_SIZE );
		tmpStr = "CHECKEDIN";
		memcpy( &blockState[0], tmpStr.c_str(), tmpStr.size() );
		
		string nextBlock = blockToString( dataField );
		writeToFile( nextBlock );
	}
	else
	{
		printf("Evidence already exists\n");
	}
}

/**
 * @dev 
 */
void checkoutItem()
{
	//before attempting to add a block,
	//clear out any existing data i nthe arrays
	resetBlockBytes();
	string tmpStr = "";
	//prepare garbage values
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	tmpStr = "Bababooey";
	memcpy( &itemID[0], tmpStr.c_str(), tmpStr.size() );
	
	int evidenceState = getEvidenceState( &itemID[0] );
	//operation only permitted if evidence is CHECKEDIN
	if( CHECKEDIN == evidenceState)
	{
		printf("Evidence can be Checked Out\n");
		
		memcpy( &blockItemID[0], &itemID[0], BLOCK_ITEM_ID_SIZE );
		tmpStr = "CHECKEDOUT";
		memcpy( &blockState[0], tmpStr.c_str(), tmpStr.size() );
		
		string nextBlock = blockToString( "" );
		writeToFile( nextBlock );
	}
	else
	{
		printf("Evidence CANNOT be Checked Out\n");
	}
}

/**
 * @dev 
 */
void checkinItem()
{
	//before attempting to add a block,
	//clear out any existing data i nthe arrays
	resetBlockBytes();
	string tmpStr = "";
	//prepare garbage values
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	tmpStr = "Bababooey";
	memcpy( &itemID[0], tmpStr.c_str(), tmpStr.size() );
	
	int evidenceState = getEvidenceState( &itemID[0] );
	//operation only permitted if evidence is CHECKEDOUT
	if( CHECKEDOUT == evidenceState)
	{
		printf("Evidence can be Checked In\n");
		
		memcpy( &blockItemID[0], &itemID[0], BLOCK_ITEM_ID_SIZE );
		tmpStr = "CHECKEDIN";
		memcpy( &blockState[0], tmpStr.c_str(), tmpStr.size() );
		
		string nextBlock = blockToString( "" );
		writeToFile( nextBlock );
	}
	else
	{
		printf("Evidence CANNOT be Checked In\n");
	}
}

/**
 * @dev 
 */
void removeItem()
{
	
}

/**
 * @dev 
 */
void showCases()
{
	
}

/**
 * @dev 
 */
void showItems()
{
	
}

/**
 * @dev 
 */
void showHistory()
{
	
}

/**
 * @dev 
 */
void init()
{
	bool prevInit = cocIsInit();
	if( prevInit )
	{
		//INITIAL block exists, do not create another
		printf("Blockchain file found with INITIAL block\n");
	}
	else
	{
		//Confirm we reached here because no blockchain file
		//exists, and not because the file has a first block that
		//is something other than INITIAL
		if( !(fileExists()) )
		{
			//INITIAL block does not exist, create one
			printf("Blockchain file not found. Created INITIAL block\n");
			//Initialize the fields (reset 0s everything as deired)
			resetBlockBytes();
			//set specific fields
			string setValue = "INITIAL";
			memcpy( &blockState[0], setValue.c_str(), setValue.size() );
			setValue = "Initial block";
			blockDataLen.intLen = setValue.size();
			//create the INITAL block and append it
			string initialBlock = blockToString( setValue );
			writeToFile( initialBlock );
		}
		//else we have a block chain without an INITIAL block
	}
}

/**
 * @dev 
 */
void verify()
{
	
}

/*
 * =============
 * Main Method
 * =============
 */

/**
 * @dev main method that performs the bulk of computation for this file
 */
int main( int argc, char* argv[] )
{
	//Get the command from the command line
	string inputCommand;
	
	/*
		Parse the command line arguments. Valid Options are:
			add -c case_id -i item_id [-i item_id ...] -g creator -p password(creator’s)
			checkout -i item_id -p password
			checkin -i item_id -p password
			show cases 
			show items -c case_id
			show history [-c case_id] [-i item_id] [-n num_entries] [-r] -p password
			remove -i item_id -y reason -p password(creator’s)
			init
			verify
	*/
	//Get the first CLI argument and navigate to the correct method
	if( argc > 1 )
	{
		inputCommand = argv[1];
		printf("Input: %s\n", inputCommand.c_str() );
		//determine what the first (case sensitive) command word on the CLI is
		if( 0 == inputCommand.compare("add") )
		{
			addItemToCase();
		}
		else if( 0 == inputCommand.compare("checkout") )
		{
			checkoutItem();
		}
		else if( 0 == inputCommand.compare("checkin") )
		{
			checkinItem();
		}
		else if( 0 == inputCommand.compare("remove") )
		{
			removeItem();
		}
		else if( 0 == inputCommand.compare("show") )
		{
			if( argc > 2 )
			{
				inputCommand = argv[2];
				if( 0 == inputCommand.compare("cases") )
				{
					showCases();
				}
				else if( 0 == inputCommand.compare("items") )
				{
					showItems();
				}
				else if( 0 == inputCommand.compare("history") )
				{
					showHistory();
				}
			}
		}
		else if( 0 == inputCommand.compare("init") )
		{
			init();
		}
		else if( 0 == inputCommand.compare("verify") )
		{
			verify();
		}
		else
		{
			//User passed in unspoort/unknown inputs. Alert them
			printf("Unknown Input Command\n" );
			printf("Program supports (where [] indicates optionality):\n" );
			printf("\tadd -c case_id -i item_id [-i item_id ...] -g creator -p password(creator’s)\n" );
			printf("\tcheckout -i item_id -p password\n" );
			printf("\tcheckin -i item_id -p password\n" );
			printf("\tshow cases \n" );
			printf("\tshow items -c case_id\n" );
			printf("\tshow history [-c case_id] [-i item_id] [-n num_entries] [-r] -p password\n" );
			printf("\tremove -i item_id -y reason -p password(creator’s)\n" );
			printf("\tinit\n" );
			printf("\tverify\n" );
		}
	}
	
	//exit with success
	return 0;
}