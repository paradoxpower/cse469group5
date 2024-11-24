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
#include <vector>
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
	unsigned char byteLen[BLOCK_DATA_LEN_SIZE];
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
const char* AES_KEY = "R0chLi4uLi4uLi4=";

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
 * @dev Encrypt an input byte array using the constant AES_KEY
 * @param Bytes to encrypt
 * @param Length of the value
 */
void encryptBytes( unsigned char* itemToEncrypt, int itemLength )
{
	//how many unique bytes are in the key for XOR processing
	int AES_KEY_length = 16;
	//encrypt byte by bte
	for( int i = 0; i < itemLength; i++ )
	{
		int keyPosition = i % AES_KEY_length;
		itemToEncrypt[i] = itemToEncrypt[i] ^ AES_KEY[keyPosition];
	}
}

/**
 * @dev Decrypt an input byte array using the constant AES_KEY
 * @param Bytes to decrypt
 * @param Length of the value
 */
void decryptBytes( unsigned char* itemToDecrypt, int itemLength )
{
	//how many unique bytes are in the key for XOR processing
	int AES_KEY_length = 16;
	//encrypt byte by bte
	for( int i = 0; i < itemLength; i++ )
	{
		int keyPosition = i % AES_KEY_length;
		itemToDecrypt[i] = itemToDecrypt[i] ^ AES_KEY[keyPosition];
	}
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
			/*printf("fPtr %d\n", ftell(fPtr));
			printf("endPtr %d\n", ftell(endPtr));*/
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
				//printf("Good chain link\n");
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
					//printf("Matching IDs\n");
					//for convenience, copy the Case ID of this evidence item
					//into the blockCaseId array (helpful for checkins, checkouts, removes)
					//first, backup from the end of the evidence id to the start of the case id
					offsetToNextField = -(BLOCK_ITEM_ID_SIZE + BLOCK_CASE_ID_SIZE);
					fseek( fPtr, offsetToNextField, SEEK_CUR );
					fread( blockCaseID, sizeof(char), BLOCK_CASE_ID_SIZE, fPtr);
					//advance from the end of the Case Id to the Evidence state
					offsetToNextField = BLOCK_STATE_OFFSET - (BLOCK_CASE_ID_OFFSET + BLOCK_CASE_ID_SIZE);
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
					//for convenience, copy the Case ID of this evidence item
					//into the blockCaseId array (helpful for checkins, checkouts, removes)
					//first, backup from the end of the evidence id to the start of the case id
					offsetToNextField = BLOCK_CREATOR_OFFSET - (BLOCK_STATE_OFFSET + BLOCK_STATE_SIZE);
					fseek( fPtr, offsetToNextField, SEEK_CUR );
					fread( blockCreator, sizeof(char), BLOCK_CREATOR_SIZE, fPtr);
					//After all of the above, advance to the data length field
					//from the end of the creator field
					offsetToNextField = BLOCK_DATA_LEN_OFFSET - (BLOCK_CREATOR_OFFSET + BLOCK_CREATOR_SIZE);
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

/**
 * @dev 
 */
int checkPassword( string cmpPassword )
{
	int passwordsMatch = -1;
	if( 0 == cmpPassword.compare( BCHOC_PASSWORD_CREATOR ) )
	{
		passwordsMatch = 0;
	}
	else if( 0 == cmpPassword.compare( BCHOC_PASSWORD_POLICE ) )
	{
		passwordsMatch = 1;
	}
	else if( 0 == cmpPassword.compare( BCHOC_PASSWORD_LAWYER ) )
	{
		passwordsMatch = 2;
	}
	else if( 0 == cmpPassword.compare( BCHOC_PASSWORD_ANALYST ) )
	{
		passwordsMatch = 3;
	}
	else if( 0 == cmpPassword.compare( BCHOC_PASSWORD_EXECUTIVE ) )
	{
		passwordsMatch = 4;
	}
	return passwordsMatch;
}

/*
 * =============
 * Methods providing core functionality
 * =============
 */

/**
 * @dev 
 */
void addItemToCase( string inCaseId, string inItemId, string inCreator )
{
	//before attempting to add a block,
	//clear out any existing data i nthe arrays
	resetBlockBytes();
	//prepare item for uniqueness check against entries in blockchain
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	memcpy( &itemID[0], inItemId.c_str(), inItemId.size() );
	
	//encrypt the data for simple comparison in the getEvidenceState()
	encryptBytes( &itemID[0], BLOCK_ITEM_ID_SIZE );
	int evidenceState = getEvidenceState( &itemID[0] );
	if( -1 == evidenceState)
	{
		printf("This is new evidence\n");
		
		//evidence ID is unique and should be added
		//(TODO) Capture timestamp and store
		
		//copy Case Id (then encrypt the bytes)
		memcpy( &blockCaseID[0], inCaseId.c_str(), inCaseId.size() );
		encryptBytes( &blockCaseID[0], BLOCK_CASE_ID_SIZE );
		//copy Item Id (bytes already encrypted)
		memcpy( &blockItemID[0], &itemID[0], BLOCK_ITEM_ID_SIZE );
		//set default state
		string defaultState = "CHECKEDIN";
		memcpy( &blockState[0], defaultState.c_str(), defaultState.size() );
		//copy creator id
		memcpy( &blockCreator[0], inCreator.c_str(), inCreator.size() );
		//Owner is set to creator since this is a creation event
		memcpy( &blockOwner[0], inCreator.c_str(), inCreator.size() );
		//DataLen is left as 0 and Data field is empty
		
		//BCHOC does not support comments in the data field during adds
		string nextBlock = blockToString( "" );
		//append new block to end
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
void checkoutItem( string inItemId, int checkoutPassword )
{
	//before attempting to checkout an item
	//clear out any existing data in the arrays
	resetBlockBytes();
	//prepare item for check against entries in blockchain
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	memcpy( &itemID[0], inItemId.c_str(), inItemId.size() );
	
	//encrypt the data for simple comparison in the getEvidenceState()
	encryptBytes( &itemID[0], BLOCK_ITEM_ID_SIZE );
	int evidenceState = getEvidenceState( &itemID[0] );
	//operation only permitted if evidence is CHECKEDIN
	if( CHECKEDIN == evidenceState)
	{
		printf("Evidence can be Checked Out\n");
		
		//evidence Id is valid and in a CHECKEDIN state, make checkout entry
		//(TODO) Capture timestamp and store
		
		//--getEvidenceState() has already stored the Case Id in the blockCaseId after finding a matching Item ID
		//Copy the Item ID (already encrypted)
		memcpy( &blockItemID[0], &itemID[0], BLOCK_ITEM_ID_SIZE );
		//set checkout state
		string checkoutState = "CHECKEDOUT";
		memcpy( &blockState[0], checkoutState.c_str(), checkoutState.size() );
		//--getEvidenceState() has already stored the Creator in the blockCreator after finding a matching Item ID
		//Set the owner according to the password used
		string Owner = "";
		switch( checkoutPassword )
		{
			case 1: Owner = "POLICE";
				break;
			case 2: Owner = "LAWYER";
				break;
			case 3: Owner = "ANALYST";
				break;
			case 4: Owner = "EXECUTIVE";
				break;
		}
		memcpy( &blockOwner[0], Owner.c_str(), Owner.size() );
		//DataLen is left as 0 and Data field is empty
		
		//BCHOC does not support comments in the data field during checkouts
		string nextBlock = blockToString( "" );
		//append new block to end
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
void checkinItem( string inItemId, int checkoutPassword )
{
	//before attempting to checkin an item,
	//clear out any existing data in the arrays
	resetBlockBytes();
	//prepare item for check against entries in blockchain
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	memcpy( &itemID[0], inItemId.c_str(), inItemId.size() );
	
	//encrypt the data for simple comparison in the getEvidenceState()
	encryptBytes( &itemID[0], BLOCK_ITEM_ID_SIZE );
	int evidenceState = getEvidenceState( &itemID[0] );
	//operation only permitted if evidence is CHECKEDOUT
	if( CHECKEDOUT == evidenceState)
	{
		printf("Evidence can be Checked In\n");
		
		//evidence Id is valid and in a CHECKEDOUT state, make checkin entry
		//(TODO) Capture timestamp and store
		
		//--getEvidenceState() has already stored the Case Id in the blockCaseId after finding a matching Item ID
		//Copy the Item ID (already encrypted)
		memcpy( &blockItemID[0], &itemID[0], BLOCK_ITEM_ID_SIZE );
		//set checkin state
		string checkinState = "CHECKEDIN";
		memcpy( &blockState[0], checkinState.c_str(), checkinState.size() );
		//--getEvidenceState() has already stored the Creator in the blockCreator after finding a matching Item ID
		//Set the owner according to the password used
		string Owner = "";
		switch( checkoutPassword )
		{
			case 1: Owner = "POLICE";
				break;
			case 2: Owner = "LAWYER";
				break;
			case 3: Owner = "ANALYST";
				break;
			case 4: Owner = "EXECUTIVE";
				break;
		}
		memcpy( &blockOwner[0], Owner.c_str(), Owner.size() );
		//DataLen is left as 0 and Data field is empty
		
		//BCHOC does not support comments in the data field during checkins
		string nextBlock = blockToString( "" );
		//append new block to end
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
void removeItem( string inItemId, int removalType, string removalReason )
{
	//before attempting to checkin an item,
	//clear out any existing data in the arrays
	resetBlockBytes();
	//prepare item for check against entries in blockchain
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	memcpy( &itemID[0], inItemId.c_str(), inItemId.size() );
	
	//encrypt the data for simple comparison in the getEvidenceState()
	encryptBytes( &itemID[0], BLOCK_ITEM_ID_SIZE );
	int evidenceState = getEvidenceState( &itemID[0] );
	//operation only permitted if evidence is CHECKEDIN
	if( CHECKEDIN == evidenceState)
	{
		printf("Evidence can be Removed\n");
		
		//evidence Id is valid and in a CHECKEDIN state, make removal entry
		//(TODO) Capture timestamp and store
		
		//--getEvidenceState() has already stored the Case Id in the blockCaseId after finding a matching Item ID
		//Copy the Item ID
		memcpy( &blockItemID[0], &itemID[0], BLOCK_ITEM_ID_SIZE );
		//set removal state based on argument
		string removalState = "";
		switch( removalType )
		{
			case 1: removalState = "DISPOSED";
				break;
			case 2: removalState = "DESTROYED";
				break;
			case 3: removalState = "RELEASED";
				break;
		}
		memcpy( &blockState[0], removalState.c_str(), removalState.size() );
		//--getEvidenceState() has already stored the Creator in the blockCreator after finding a matching Item ID
		//Owner is set to creator since this is a removal event
		memcpy( &blockOwner[0], &blockCreator[0], BLOCK_CREATOR_SIZE );
		//check if a comment has been added to the data field
		string nextBlock;
		if( 0 != removalReason.compare("") )
		{
			//get the string length
			blockDataLen.intLen = removalReason.size();
			//create the block with this addition
			nextBlock = blockToString( removalReason );
		}
		else
		{
			//DataLen is left as 0 and Data field is empty
			nextBlock = blockToString( "" );
		}
		//append new block to end
		writeToFile( nextBlock );
	}
	else
	{
		printf("Evidence CANNOT be Removed\n");
	}
}

/**
 * @dev 
 */
void showCases()
{
	//track the list of unique Case IDs
	vector<string> caseIdList;
	//confirm the file exists before attempting to read it
	if( fileExists() )
	{
		//store the reads of data
		unsigned char readCaseId[BLOCK_CASE_ID_SIZE];
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
		//Compute the offset to read the length of this data field
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
			//notice, this method does no verification of blockchain integrity
			//offset computational support
			int offsetToNextField = 0;
			string tmpString = "";
			
			//advance from the head of the block to the Case ID field
			offsetToNextField = BLOCK_CASE_ID_OFFSET;
			fseek( fPtr, offsetToNextField, SEEK_CUR );
			fread( readCaseId, sizeof(char), BLOCK_CASE_ID_SIZE, fPtr);
			//convert the caseId bytes to a string
			tmpString.append((const char*)&readCaseId[0], BLOCK_CASE_ID_SIZE);
			//check to see if it should be appended to the list of unique cases
			bool newCase = true;
			for( int i = 0; i < caseIdList.size(); i++ )
			{
				if( 0 == tmpString.compare( caseIdList[i] ) )
				{
					//case id already listed, do not add again
					newCase = false;
				}
			}
			if( newCase )
			{
				caseIdList.push_back(tmpString);
			}
			
			//advance from the end of the case id to the Data Length field
			offsetToNextField = BLOCK_DATA_LEN_OFFSET - (BLOCK_CASE_ID_OFFSET + BLOCK_CASE_ID_SIZE);
			fseek( fPtr, offsetToNextField, SEEK_CUR );
			//Compute the offset to read the length of this data field
			fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
			//advance from the DataLen field to the end of the data field
			//(recall the "fread" advances the fPtr)
			fseek( fPtr, readDataLen.intLen, SEEK_CUR );
			//read the hash of this block before advancing to the next
			//and store it in the Previous Hash global variable
			fread( blockPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr );
		}
		fclose(fPtr);
	}
	
	//print all found cases
	char* casePtr = new char[BLOCK_CASE_ID_SIZE];
	for( int i = 0; i < caseIdList.size(); i++ )
	{
		//decrypt the data for human readable output
		strcpy( casePtr, caseIdList[i].c_str() );
		decryptBytes( (unsigned char*)casePtr, BLOCK_CASE_ID_SIZE );
		printf("Case: %s\n", casePtr );
	}
	delete casePtr;
}

/**
 * @dev 
 */
void showItems( string inCaseId )
{
	//track the list of unique item IDs for this case
	vector<string> itemIdList;
	//translate input to a full length string for proper comparisons
	//This is because when reading from the byte array the string will always
	//be of length 32 (even if it is only "1234"). We need to translate the
	//input to be length 32 otherwise comparison will flag false by string
	//length even if its contents are matching
	unsigned char tmpCaseId[BLOCK_CASE_ID_SIZE];
	memset( &tmpCaseId[0], 0, BLOCK_CASE_ID_SIZE );
	memcpy( &tmpCaseId[0], inCaseId.c_str(), inCaseId.size() );
	//then we need to encrypt the bytes to match the blockchain sotrage
	encryptBytes( &tmpCaseId[0], BLOCK_CASE_ID_SIZE );
	inCaseId = "";
	inCaseId.append((const char*)&tmpCaseId[0], BLOCK_CASE_ID_SIZE);
	//confirm the file exists before attempting to read it
	if( fileExists() )
	{
		//store the reads of data
		unsigned char readCaseId[BLOCK_CASE_ID_SIZE];
		unsigned char readItemId[BLOCK_ITEM_ID_SIZE];
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
		//Compute the offset to read the length of this data field
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
			//notice, this method does no verification of blockchain integrity
			//offset computational support
			int offsetToNextField = 0;
			string tmpCase = "";
			string tmpItem = "";
			
			//advance from the head of the block to the Case ID field
			offsetToNextField = BLOCK_CASE_ID_OFFSET;
			fseek( fPtr, offsetToNextField, SEEK_CUR );
			fread( readCaseId, sizeof(char), BLOCK_CASE_ID_SIZE, fPtr);
			//convert the caseId bytes to a string
			tmpCase.append((const char*)&readCaseId[0], BLOCK_CASE_ID_SIZE);
			//advance from the Case ID to the Item ID field
			offsetToNextField = BLOCK_ITEM_ID_OFFSET - (BLOCK_CASE_ID_OFFSET + BLOCK_CASE_ID_SIZE);
			fseek( fPtr, offsetToNextField, SEEK_CUR );
			fread( readItemId, sizeof(char), BLOCK_ITEM_ID_SIZE, fPtr);
			//convert the caseId bytes to a string
			tmpItem.append((const char*)&readItemId[0], BLOCK_ITEM_ID_SIZE);
			//check to see if it should be appended to the list of unique items
			bool newItem = true;
			for( int i = 0; i < itemIdList.size(); i++ )
			{
				if( 0 == tmpItem.compare( itemIdList[i] ) )
				{
					//case id already listed, do not add again
					newItem = false;
				}
			}
			//confirm its a new item for the proper case
			if( (newItem) && (0 == tmpCase.compare(inCaseId)) )
			{
				itemIdList.push_back(tmpItem);
			}
			
			//advance from the end of the item id to the Data Length field
			offsetToNextField = BLOCK_DATA_LEN_OFFSET - (BLOCK_ITEM_ID_OFFSET + BLOCK_ITEM_ID_SIZE);
			fseek( fPtr, offsetToNextField, SEEK_CUR );
			//Compute the offset to read the length of this data field
			fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
			//advance from the DataLen field to the end of the data field
			//(recall the "fread" advances the fPtr)
			fseek( fPtr, readDataLen.intLen, SEEK_CUR );
			//read the hash of this block before advancing to the next
			//and store it in the Previous Hash global variable
			fread( blockPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr );
		}
		fclose(fPtr);
	}
	
	//print all found cases
	char* itemPtr = new char[BLOCK_ITEM_ID_SIZE];
	for( int i = 0; i < itemIdList.size(); i++ )
	{
		//decrypt the data for human readable output
		strcpy( itemPtr, itemIdList[i].c_str() );
		decryptBytes( (unsigned char*)itemPtr, BLOCK_ITEM_ID_SIZE );
		printf("Item: %s\n", itemPtr );
	}
	delete itemPtr;
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
	bool allGood = false;
	int transCount = 0;
	//track the Hash of the bad block and the reason it is bad
	vector<string> badBlocks;
	vector<string> findingInfo;
	//confirm the file exists before attempting to read it
	if( fileExists() )
	{
		//a file does exist to verify
		allGood = true;
		//store the reads of data
		unsigned char readPrevHash[BLOCK_PREV_HASH_SIZE];
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
		//Compute the offset to read the length of this data field
		fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
		//advance from the DataLen field to the end of the data field
		//(recall the "fread" advances the fPtr)
		fseek( fPtr, readDataLen.intLen, SEEK_CUR );
		//read the hash of this block before advancing to the next
		//and store it in the Previous Hash global variable
		fread( blockPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr );
		transCount++; //increment after reading a hash
		//we need to sequentially check every block to determine the latest
		//state of this evidence item
		while( (ftell(fPtr) + BLOCK_MIN_SIZE) < ftell(endPtr) )
		{
			//check hash on last block matches logged prevHash in current block
			fread( readPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr );
			bool hashMatch = true;
			if( 0 != memcmp(&blockPrevHash[0], &readPrevHash[0], BLOCK_PREV_HASH_SIZE) )
			{
				hashMatch = false;
				allGood = false;
			}
			
			//proceed to next block
			int offsetToNextField = 0;
			//advance from the end of the previous hash to the Data Length field
			offsetToNextField = BLOCK_DATA_LEN_OFFSET - (BLOCK_PREV_HASH_OFFSET + BLOCK_PREV_HASH_SIZE);
			fseek( fPtr, offsetToNextField, SEEK_CUR );
			//Compute the offset to read the length of this data field
			fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
			//advance from the DataLen field to the end of the data field
			//(recall the "fread" advances the fPtr)
			fseek( fPtr, readDataLen.intLen, SEEK_CUR );
			//read the hash of this block before advancing to the next
			//and store it in the Previous Hash global variable
			fread( blockPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr );
			transCount++; //increment after reading a hash
			
			//Store the hash of the bad block
			if( !hashMatch )
			{
				//add the block has
				string bytesToString = "";
				bytesToString.append((const char*)&blockPrevHash[0], BLOCK_PREV_HASH_SIZE);
				badBlocks.push_back( bytesToString );
			}
		}
		fclose(fPtr);
	}
	
	printf("Transactions in blockchain: %d\n", transCount);
	if( allGood )
	{
		printf("State of blockchain: CLEAN\n");
	}
	else
	{
		//Error TODOs
	}
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
			/*
			 * ==== ADD OPERATION ====
			 */
			//forward declare needed variables
			string cmdCaseId = "";
			string cmdItemId = "";
			string cmdCreator = "";
			string cmdPassword = "";
			
			//Find the Case ID
			for( int arg = 0; arg < argc; arg++ )
			{
				if( 0 == strcmp("-c", argv[arg]) )
				{
					cmdCaseId = argv[arg+1];
					//do not exceed 32char length
					if( cmdCaseId.size() > 32 )
					{
						cmdCaseId = cmdCaseId.substr(0, 12);
					}
				}
			}
			//Find the Creator
			for( int arg = 0; arg < argc; arg++ )
			{
				if( 0 == strcmp("-g", argv[arg]) )
				{
					cmdCreator = argv[arg+1];
					//do not exceed 12char length
					if( cmdCreator.size() > 12 )
					{
						cmdCreator = cmdCreator.substr(0, 12);
					}
				}
			}
			//Find the Password
			for( int arg = 0; arg < argc; arg++ )
			{
				if( 0 == strcmp("-p", argv[arg]) )
				{
					cmdPassword = argv[arg+1];
					//do not exceed 4char length
					if( cmdPassword.size() > 4 )
					{
						cmdPassword = cmdPassword.substr(0, 4);
					}
				}
			}
			
			//Confirm Password is that of "CREATOR"
			if( 0 == checkPassword( cmdPassword ) )
			{
				//Confirm non-empty other strings
				if( ( 0 != cmdCaseId.compare("") ) &&
					( 0 != cmdCreator.compare("") ) )
				{
					//There may be multiple items, so iterate the full list
					for( int arg = 0; arg < argc; arg++ )
					{
						if( 0 == strcmp("-i", argv[arg]) )
						{
							cmdItemId = argv[arg+1];
							//do not exceed 32char length
							if( cmdItemId.size() > 32 )
							{
								cmdItemId = cmdItemId.substr(0, 32);
							}
							//(TODO) encrypt Case & Item here
							addItemToCase( cmdCaseId, cmdItemId, cmdCreator );
						}
					}
				}
			}
		}
		else if( 0 == inputCommand.compare("checkout") )
		{
			/*
			 * ==== CHECKOUT OPERATION ====
			 */
			//forward declare needed variables
			string cmdItemId = "";
			string cmdPassword = "";
			
			//Find the Password
			for( int arg = 0; arg < argc; arg++ )
			{
				if( 0 == strcmp("-p", argv[arg]) )
				{
					cmdPassword = argv[arg+1];
					//do not exceed 4char length
					if( cmdPassword.size() > 4 )
					{
						cmdPassword = cmdPassword.substr(0, 4);
					}
				}
			}
			//Confirm Password is POLICE, LAWYER, ANALYST, or EXECUTIVE
			int passwordId = checkPassword( cmdPassword );
			if( 0 < passwordId )
			{
				//Get the Item ID to checkout
				for( int arg = 0; arg < argc; arg++ )
				{
					if( 0 == strcmp("-i", argv[arg]) )
					{
						cmdItemId = argv[arg+1];
						//do not exceed 32char length
						if( cmdItemId.size() > 32 )
						{
							cmdItemId = cmdItemId.substr(0, 32);
						}
						checkoutItem( cmdItemId, passwordId );
					}
				}
			}
		}
		else if( 0 == inputCommand.compare("checkin") )
		{
			/*
			 * ==== CHECKIN OPERATION ====
			 */
			//forward declare needed variables
			string cmdItemId = "";
			string cmdPassword = "";
			
			//Find the Password
			for( int arg = 0; arg < argc; arg++ )
			{
				if( 0 == strcmp("-p", argv[arg]) )
				{
					cmdPassword = argv[arg+1];
					//do not exceed 4char length
					if( cmdPassword.size() > 4 )
					{
						cmdPassword = cmdPassword.substr(0, 4);
					}
				}
			}
			//Confirm Password is POLICE, LAWYER, ANALYST, or EXECUTIVE
			int passwordId = checkPassword( cmdPassword );
			if( 0 < passwordId )
			{
				//Get the Item ID to checkout
				for( int arg = 0; arg < argc; arg++ )
				{
					if( 0 == strcmp("-i", argv[arg]) )
					{
						cmdItemId = argv[arg+1];
						//do not exceed 32char length
						if( cmdItemId.size() > 32 )
						{
							cmdItemId = cmdItemId.substr(0, 32);
						}
						checkinItem( cmdItemId, passwordId );
					}
				}
			}
		}
		else if( 0 == inputCommand.compare("remove") )
		{
			/*
			 * ==== REMOVE OPERATION ====
			 */
			//forward declare needed variables
			string cmdItemId = "";
			string cmdRemovalType = "";
			string cmdReason = "";
			string cmdPassword = "";
			
			//Find the Item
			for( int arg = 0; arg < argc; arg++ )
			{
				if( 0 == strcmp("-i", argv[arg]) )
				{
					cmdItemId = argv[arg+1];
					//do not exceed 32char length
					if( cmdItemId.size() > 32 )
					{
						cmdItemId = cmdItemId.substr(0, 32);
					}
				}
			}
			//Find the Removal Type
			for( int arg = 0; arg < argc; arg++ )
			{
				if( 0 == strcmp("-y", argv[arg]) )
				{
					cmdRemovalType = argv[arg+1];
					//do not exceed 12char length
					if( cmdRemovalType.size() > 12 )
					{
						cmdRemovalType = cmdRemovalType.substr(0, 12);
					}
				}
			}
			//Find the Creator
			for( int arg = 0; arg < argc; arg++ )
			{
				//guidelines specify "-o" and "--why" as reason flags
				if( (0 == strcmp("-o", argv[arg])) || (0 == strcmp("--why", argv[arg])) )
				{
					//append the imediate next string
					arg++;
					cmdReason.append(argv[arg]);
					//the reason can be a sentence, keep getting args until reaching
					//the end of another flag appears
					arg++;
					while( (arg < argc) && (0 != strcmp("-i", argv[arg])) &&
						(0 != strcmp("-y", argv[arg])) && (0 != strcmp("-p", argv[arg])) )
					{
						cmdReason.append(" ");
						cmdReason.append(argv[arg]);
						//reason can be 2^32 bytes long of reasoning, don't length check
						arg++;
					}
				}
			}
			//Find the Password
			for( int arg = 0; arg < argc; arg++ )
			{
				if( 0 == strcmp("-p", argv[arg]) )
				{
					cmdPassword = argv[arg+1];
					//do not exceed 4char length
					if( cmdPassword.size() > 4 )
					{
						cmdPassword = cmdPassword.substr(0, 4);
					}
				}
			}
			
			//Confirm Password is that of "CREATOR"
			if( 0 == checkPassword( cmdPassword ) )
			{
				//Confirm non-empty strings for mandatory checks
				if( 0 != cmdItemId.compare("") )
				{
					//RELEASED requires a non-empty reason
					if( 0 == cmdRemovalType.compare("RELEASED") )
					{
						if( 0 != cmdReason.compare("") )
						{
							removeItem( cmdItemId, 3, cmdReason );
						}
						else
						{
							printf("Attempted to RELEASE evidence without Reason\n");
						}
					}
					//the other 2 can have it filled out optionally
					else if( 0 == cmdRemovalType.compare("DISPOSED") )
					{
						removeItem( cmdItemId, 1, cmdReason );
					}
					else if( 0 == cmdRemovalType.compare("DESTROYED") )
					{
						removeItem( cmdItemId, 2, cmdReason );
					}
				}
			}
		}
		else if( 0 == inputCommand.compare("show") )
		{
			if( argc > 2 )
			{
				inputCommand = argv[2];
				if( 0 == inputCommand.compare("cases") )
				{
					/*
					 * ==== SHOW CASES OPERATION ====
					 */
					showCases();
				}
				else if( 0 == inputCommand.compare("items") )
				{
					/*
					 * ==== SHOW ITEMS OPERATION ====
					 */
					string cmdCaseId = "";
					//Find the Cae ID
					for( int arg = 0; arg < argc; arg++ )
					{
						if( 0 == strcmp("-c", argv[arg]) )
						{
							cmdCaseId = argv[arg+1];
							//do not exceed 32char length
							if( cmdCaseId.size() > 32 )
							{
								cmdCaseId = cmdCaseId.substr(0, 32);
							}
							showItems( cmdCaseId );
						}
					}
				}
				else if( 0 == inputCommand.compare("history") )
				{
					/*
					 * ==== SHOW HISTORY OPERATION ====
					 */
					showHistory();
				}
			}
		}
		else if( 0 == inputCommand.compare("init") )
		{
			/*
			 * ==== INIT OPERATION ====
			 */
			init();
		}
		else if( 0 == inputCommand.compare("verify") )
		{
			/*
			 * ==== VERIFY OPERATION ====
			 */
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