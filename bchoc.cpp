/**
	File: bchoc.cpp
	Purpose:
		
*/

//standard support libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <chrono>
#include <sys/stat.h>
#include <algorithm>
//library supporting hashes & encryption
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

//indicate the "std" namesapce is in use for this file scope
using namespace std;

//define the fundamental Block struct
const int BLOCK_PREV_HASH_SIZE = 32;
const int BLOCK_TIMESTAMP_SIZE = 8;
const int BLOCK_CASE_ID_SIZE = 32;
const int BLOCK_ITEM_ID_SIZE = 32;
const int BLOCK_STATE_SIZE = 12;
const int BLOCK_CREATOR_SIZE = 12;
const int BLOCK_OWNER_SIZE = 12;
const int BLOCK_DATA_LEN_SIZE = 4;

//define the fields of the Block
unsigned char blockPrevHash[BLOCK_PREV_HASH_SIZE];
unsigned char blockCaseID[BLOCK_CASE_ID_SIZE];
unsigned char blockItemID[BLOCK_ITEM_ID_SIZE];
unsigned char blockState[BLOCK_STATE_SIZE];
unsigned char blockCreator[BLOCK_CREATOR_SIZE];
unsigned char blockOwner[BLOCK_OWNER_SIZE];
//make a union to simplify data access in memory
union
{
	uint64_t dblTime;
	unsigned char byteTime[BLOCK_TIMESTAMP_SIZE];
} blockTimestamp;
union
{
	unsigned int  intLen;
	unsigned char byteLen[BLOCK_DATA_LEN_SIZE];
} blockDataLen;
//after these defined sections will be a dynamic data field that can
//be 0 - 2^32 bytes long per the value in dataLen

//define constants for this effort (all of the following are in bytes)
//Size & offset constants for each block (before variable data field)
/*
	Data Layout
	=============
	Byte 0-31	= Previous Hash
	Byte 32-39	= Timestamp
	Byte 40-71	= Case ID
	Byte 72-103	= Evidence Item ID
	Byte 104-115= State
	Byte 116-127= Creator
	Byte 128-139= Owner
	Byte 140-143= Data Length
	--variable length data field--
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

//to simplify state checking, create an enumeration
enum evidenceState { INITIAL, CHECKEDIN, CHECKEDOUT, DISPOSED, DESTROYED, RELEASED };

//password constants
const string BCHOC_PASSWORD_POLICE = "P80P";
const string BCHOC_PASSWORD_LAWYER = "L76L";
const string BCHOC_PASSWORD_ANALYST = "A65A";
const string BCHOC_PASSWORD_EXECUTIVE = "E69E";
const string BCHOC_PASSWORD_CREATOR = "C67C";
//data encryption key (per guidance)
const string AES_KEY = "R0chLi4uLi4uLi4=";

//declare a global filename to use (set during main)
string COC_FILE;

/*
 * =============
 * Methods providing supporting functionality
 * =============
 */

 /**
 * @dev Simple method that will check a files existence
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
		fclose(fPtr);
	}
	return exists;
}
 
/**
 * @dev method that writes the argument string to the end of the file
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
	string hashResult = "";
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
	//the above generates the SHA256 hash as a 64byte string
	//we need to translate the characters into their hex bytes
	//to create a 32 byte Hash
	unsigned char hexValues[BLOCK_PREV_HASH_SIZE];
	string holdingString = ss.str();
	for(int i = 0; i < BLOCK_PREV_HASH_SIZE; i++)
	{
		int idx = i*2;
		//this will take 2 characters and translate them into
		//their byte-length hex equivalent and store the value
		hexValues[i] = stoi( holdingString.substr(idx, 2), NULL, 16 );
	}
	hashResult.append((const char*)&hexValues[0], BLOCK_PREV_HASH_SIZE);
	
	return hashResult;
}

/**
 * @dev Convert UUID string to 16-byte array
 */
void uuidToBytes(const string& uuid, unsigned char* uuidBytes)
{
    string hexUuid = uuid;
	// Remove hyphens
    hexUuid.erase(remove(hexUuid.begin(), hexUuid.end(), '-'), hexUuid.end());

    for (size_t i = 0; i < 16; ++i) {
        string byteString = hexUuid.substr(i * 2, 2);
        uuidBytes[i] = static_cast<unsigned char>(stoul(byteString, nullptr, 16));
    }
}

/**
 * @dev Prepare 16-byte input for ItemID (12 leading zeros + 4-byte big-endian integer)
 */
void prepareItemBytes(uint32_t itemId, unsigned char* itemBytes)
{
    memset(itemBytes, 0, 16); // Initialize to zeros
    itemBytes[12] = (itemId >> 24) & 0xFF;
    itemBytes[13] = (itemId >> 16) & 0xFF;
    itemBytes[14] = (itemId >> 8) & 0xFF;
    itemBytes[15] = itemId & 0xFF;
}

/**
 * @dev Convert binary data to a byte string
 */
string bytesToByteString(const unsigned char* data, size_t length)
{
    stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)data[i];
    }
    return ss.str();
}

/**
 * @dev AES-ECB encryption using OpenSSL EVP interface
 */
string aesEncryptECB(const unsigned char* input, const std::string& key)
{
    unsigned char encrypted[16] = {0};
    int outlen = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // Disable padding

    EVP_EncryptUpdate(ctx, encrypted, &outlen, input, 16);

    EVP_CIPHER_CTX_free(ctx);

    return bytesToByteString(encrypted, 16);
}

/**
 * @dev Encrypt an input byte array using the constant AES_KEY
 * @param Bytes to encrypt
 * @param Length of the value
 */
void encryptBytes( unsigned char* itemToEncrypt, int itemLength, bool isCaseId )
{
	//translate the input into it's byte equivalent
    unsigned char encryptedBytes[16] = {0};
	if( isCaseId )
	{
		//translate the input into string
		string toEncrypt = "";
		toEncrypt.append((const char*)itemToEncrypt, itemLength);
		//format the string into bytes
		uuidToBytes(toEncrypt, encryptedBytes);
	}
	else
	{
		//translate the string into an int32_t
		uint32_t itemId = atoi( (const char*)itemToEncrypt );
		//format the int32_t into bytes
		prepareItemBytes(itemId, encryptedBytes);
	}

    string encryptedResult = aesEncryptECB(encryptedBytes, AES_KEY);
    //cout << "Encrypted Case ID: " << encryptedResult << std::endl;
	
	//clear the input char array and copy the encrypted string into it
	memset( &itemToEncrypt[0], 0, itemLength);
	memcpy( &itemToEncrypt[0], encryptedResult.c_str(), itemLength );
	
}

/**
 * @dev AES-ECB encryption using OpenSSL EVP interface
 */
std::string aesDecryptECB(const unsigned char* input, const std::string& key)
{
    unsigned char encrypted[16] = {0};
    int outlen = 0;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, reinterpret_cast<const unsigned char*>(key.data()), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx, 0); // Disable padding

    EVP_DecryptUpdate(ctx, encrypted, &outlen, input, 16);

    EVP_CIPHER_CTX_free(ctx);

    return bytesToByteString(encrypted, 16);
}

/**
 * @dev Decrypt an input byte array using the constant AES_KEY
 * @param Bytes to decrypt
 * @param Length of the value
 */
void decryptBytes( unsigned char* itemToDecrypt, int itemLength, bool isItemId )
{
	string toDecrypt = "";
	toDecrypt.append((const char*)itemToDecrypt, itemLength);
	//cout << "To Decrypt: " << toDecrypt << endl;
	
	unsigned char decryptedBytes[16] = {0};
	uuidToBytes(toDecrypt, decryptedBytes);
	string decryptedString = aesDecryptECB( decryptedBytes, AES_KEY );
	
	//cout << "Decrypted: " << decryptedString <<endl;
	
	//Item Ids have an extra step to complete the decryption
	if( isItemId )
	{
		uint32_t itemVal;
		stringstream ss;
		ss << hex << decryptedString;
		ss >> itemVal;
		decryptedString = to_string(itemVal);
	}
	
	//clear the input char array and copy the decrypted string into it
	memset( &itemToDecrypt[0], 0, itemLength);
	memcpy( &itemToDecrypt[0], decryptedString.c_str(), itemLength );
}

/**
 * @dev Single method to get time
 */
uint64_t unixTimestamp()
{
	auto curTime = chrono::system_clock::now().time_since_epoch();
	auto curTimeMs = chrono::duration_cast<chrono::microseconds>(curTime);
	uint64_t micro = curTimeMs.count();
	return micro;
}

/**
 * @dev Translate an Epoch into formatted time string
 * @param Count of microseconds since Epoch to format
 */
string translateTimestamp( uint64_t inTime )
{
	stringstream ss;
	string result;
	//extract the microseconds from the input Time
	int microseconds = inTime % 1000000;
	time_t remainder = inTime / 1000000;
	//format the remaining YYYY-MM-DD (%F) & HH:M:SS (%T) time
	struct tm* time = localtime(&remainder);
	char buffer[80];
	strftime( buffer, 80, "%FT%T.", time );
	//transalte to a string and trim off excess characters
	string tmpStr;
	tmpStr.append((const char*)&buffer[0], 80);
	tmpStr = tmpStr.substr(0, tmpStr.find("."));
	//concat the entire time measurement into a single string
	ss << tmpStr << "." << to_string(microseconds) << "Z";
	result = ss.str();
	//return the result
	return result;
}

/**
 * @dev Method to check if the blockchain is initialized
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
		unsigned char expectedState[] = {'I','N','I','T','I','A','L','\0','\0','\0','\0','\0'};
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
 * @dev Support method to clear any unexpected data from the block info
 */
void resetBlockBytes()
{
	//Initialize the fields
	memset( &blockPrevHash[0], 0, BLOCK_PREV_HASH_SIZE);
	memset( &blockTimestamp.byteTime[0], 0, BLOCK_TIMESTAMP_SIZE);
	//memset( &blockCaseID[0], 0, BLOCK_CASE_ID_SIZE);
	//memset( &blockItemID[0], 0, BLOCK_ITEM_ID_SIZE);
	for( int i = 0; i < BLOCK_CASE_ID_SIZE; i++ )
	{
		blockCaseID[i] = '0';
	}
	for( int i = 0; i < BLOCK_ITEM_ID_SIZE; i++ )
	{
		blockItemID[i] = '0';
	}
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
 * @dev This method takes all the block info and converts into a block that gets it's
 *		hash computed
 */
string recomputeHash( unsigned char* readPrevHash, unsigned char* readTimestamp, unsigned char* readCaseId,
						unsigned char* readItemId, unsigned char* readState, unsigned char* readCreator,
						unsigned char* readOwner, unsigned char* readDataLen, unsigned char* dataField, int dataFieldLen )
{
	string completeBlock = "";
	//append the sections in order
	completeBlock.append((const char*)readPrevHash, BLOCK_PREV_HASH_SIZE);
	completeBlock.append((const char*)readTimestamp, BLOCK_TIMESTAMP_SIZE);
	completeBlock.append((const char*)readCaseId, BLOCK_CASE_ID_SIZE);
	completeBlock.append((const char*)readItemId, BLOCK_ITEM_ID_SIZE);
	completeBlock.append((const char*)readState, BLOCK_STATE_SIZE);
	completeBlock.append((const char*)readCreator, BLOCK_CREATOR_SIZE);
	completeBlock.append((const char*)readOwner, BLOCK_OWNER_SIZE);
	completeBlock.append((const char*)readDataLen, BLOCK_DATA_LEN_SIZE);
	
	//append the data field (passed as an arg)
	completeBlock.append((const char*)dataField, dataFieldLen );
	//compute and append the hash value of this block
	string result = computeHash(completeBlock);
	
	return result;
}

/**
 * @dev This method takes all the block info and converts into a block that gets
 *		added to the end of the blockchain
 */
string blockToString( string dataField )
{
	string completeBlock = "";
	//append the sections in order
	completeBlock.append((const char*)&blockPrevHash[0], BLOCK_PREV_HASH_SIZE);
	completeBlock.append((const char*)&blockTimestamp.byteTime[0], BLOCK_TIMESTAMP_SIZE);
	completeBlock.append((const char*)&blockCaseID[0], BLOCK_CASE_ID_SIZE);
	completeBlock.append((const char*)&blockItemID[0], BLOCK_ITEM_ID_SIZE);
	completeBlock.append((const char*)&blockState[0], BLOCK_STATE_SIZE);
	completeBlock.append((const char*)&blockCreator[0], BLOCK_CREATOR_SIZE);
	completeBlock.append((const char*)&blockOwner[0], BLOCK_OWNER_SIZE);
	completeBlock.append((const char*)&blockDataLen.byteLen[0], BLOCK_DATA_LEN_SIZE);
	
	//append the data field (passed as an arg)
	completeBlock.append( dataField );
	
	return completeBlock;
}

/**
 * @dev This method iterates the blockchain for a given evidence item and returns it latest state
 * @param The item name to search for
 */
int getEvidenceState( unsigned char* itemToCheck )
{
	int latestState = -1;
	//confirm the file exists before attempting to read it
	if( fileExists() )
	{
		//get the current contents of the blockchain
		FILE* fPtr;
		fPtr = fopen( COC_FILE.c_str(), "rb" );
		fseek( fPtr, 0, SEEK_SET );
		//store the end of the file location
		FILE* endPtr;
		endPtr = fopen( COC_FILE.c_str(), "rb" );
		fseek( endPtr, 0, SEEK_END );
		
		//set an inital hash to compare (known to be all 0s)
		unsigned char initHash[BLOCK_PREV_HASH_SIZE];
		memset( &initHash[0], 0, BLOCK_PREV_HASH_SIZE);
		string recomputedHash = "";
		recomputedHash.append((const char*)&initHash[0], BLOCK_PREV_HASH_SIZE);
		//loop all blocks
		while( (ftell(fPtr) + BLOCK_MIN_SIZE) <= ftell(endPtr) )
		{
			/*printf("fPtr %d\n", ftell(fPtr));
			printf("endPtr %d\n", ftell(endPtr));*/
			//store the reads of data (Data field will be allocated for each block)
			unsigned char readPrevHash[BLOCK_PREV_HASH_SIZE];
			unsigned char readCase[BLOCK_CASE_ID_SIZE];
			unsigned char readItem[BLOCK_ITEM_ID_SIZE];
			unsigned char readState[BLOCK_STATE_SIZE];
			unsigned char readCreator[BLOCK_CREATOR_SIZE];
			unsigned char readOwner[BLOCK_OWNER_SIZE];
			union
			{
				uint64_t dblTime;
				unsigned char byteTime[BLOCK_TIMESTAMP_SIZE];
			} readTimestamp;
			union
			{
				unsigned int intLen;
				unsigned char byteLen[4];
			} readDataLen;
			unsigned char readCurHash[BLOCK_PREV_HASH_SIZE];
			
			//from the start of the block, read the data
			fread( readPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr);
			fread( readTimestamp.byteTime, sizeof(char), BLOCK_TIMESTAMP_SIZE, fPtr);
			fread( readCase, sizeof(char), BLOCK_CASE_ID_SIZE, fPtr);
			fread( readItem, sizeof(char), BLOCK_ITEM_ID_SIZE, fPtr);
			fread( readState, sizeof(char), BLOCK_STATE_SIZE, fPtr );
			fread( readCreator, sizeof(char), BLOCK_CREATOR_SIZE, fPtr );
			fread( readOwner, sizeof(char), BLOCK_OWNER_SIZE, fPtr );
			fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
			int lengthOfData = readDataLen.intLen;
			unsigned char dataField[lengthOfData];
			if( lengthOfData > 0 )
			{
				fread( &dataField[0], sizeof(char), lengthOfData, fPtr );
			}
			
			//check computed hash on last block matches logged prevHash in current block
			string prevHashResult = "";
			prevHashResult.append((const char*)&readPrevHash[0], BLOCK_PREV_HASH_SIZE);
			bool hashMatch = true;
			if( 0 != recomputedHash.compare(prevHashResult) )
			{
				hashMatch = false;
			}
			
			//proceed with efforts if the hashes match
			if( hashMatch )
			{
				//check if the read item matches the one we're looking for
				bool itemMatch = true;
				for( int i = 0; i < BLOCK_ITEM_ID_SIZE; i++ )
				{
					if( readItem[i] != itemToCheck[i] )
					{
						itemMatch = false;
					}
				}
				if( itemMatch )
				{
					//for convenience, copy the Case ID & Creator of this evidence item
					memcpy( &blockCaseID[0], &readCase[0], BLOCK_CASE_ID_SIZE );
					memcpy( &blockCreator[0], &readCreator[0], BLOCK_CREATOR_SIZE );
					//now check the state of this item
					//check for: CHECKEDIN, CHECKEDOUT, DESTROYED, DISPOSED, RELEASED
					unsigned char tmpCI[] = {'C','H','E','C','K','E','D','I','N','\0','\0','\0'};
					unsigned char tmpCO[] = {'C','H','E','C','K','E','D','O','U','T','\0','\0'};
					unsigned char tmpDE[] = {'D','E','S','T','R','O','Y','E','D','\0','\0','\0'};
					unsigned char tmpDI[] = {'D','I','S','P','O','S','E','D','\0','\0','\0','\0'};
					unsigned char tmpRE[] = {'R','E','L','E','A','S','E','D','\0','\0','\0','\0'};
					//CHECKEDIN check
					bool stateMatch = true;
					for( int i = 0; i < BLOCK_STATE_SIZE; i++ )
					{
						if( readState[i] != tmpCI[i] )
						{
							stateMatch = false;
						}
					}
					if( stateMatch )
					{
						latestState = (int)CHECKEDIN;
					}
					//CHECKEDOUT check
					stateMatch = true;
					for( int i = 0; i < BLOCK_STATE_SIZE; i++ )
					{
						if( readState[i] != tmpCO[i] )
						{
							stateMatch = false;
						}
					}
					if( stateMatch )
					{
						latestState = (int)CHECKEDOUT;
					}
					//DISPOSED check
					stateMatch = true;
					for( int i = 0; i < BLOCK_STATE_SIZE; i++ )
					{
						if( readState[i] != tmpDI[i] )
						{
							stateMatch = false;
						}
					}
					if( stateMatch )
					{
						latestState = (int)DISPOSED;
					}
					//DESTROYED check
					stateMatch = true;
					for( int i = 0; i < BLOCK_STATE_SIZE; i++ )
					{
						if( readState[i] != tmpDE[i] )
						{
							stateMatch = false;
						}
					}
					if( stateMatch )
					{
						latestState = (int)DESTROYED;
					}
					//RELEASED check
					stateMatch = true;
					for( int i = 0; i < BLOCK_STATE_SIZE; i++ )
					{
						if( readState[i] != tmpRE[i] )
						{
							stateMatch = false;
						}
					}
					if( stateMatch )
					{
						latestState = (int)RELEASED;
					}
				}
				//proceed to next block in chain after computing hash to check
				recomputedHash = recomputeHash( &readPrevHash[0], &readTimestamp.byteTime[0],
						&readCase[0], &readItem[0], &readState[0], &readCreator[0],
						&readOwner[0], &readDataLen.byteLen[0], &dataField[0], lengthOfData);
				//for convenience, store this has in the blockPrevHash
				memcpy( &blockPrevHash[0], recomputedHash.c_str(), BLOCK_PREV_HASH_SIZE );
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
 * @dev This method compares a password against known allowable passwords and
 *		returns a number reflecting who's password it belongs to
 * @param The password to check
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
 * @dev Method to create an INITIAL block if none exists
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
			//create the folder per BCHOC_FILE_PATH (first check it doesnt already exist)
			struct stat existence;
			int idxOfNameStart = -1;
			for( int i = strlen(COC_FILE.c_str()); i >= 0; i-- )
			{
				//find the first instance of "/"
				if( '/' == COC_FILE[i] )
				{
					idxOfNameStart = i + 1;
					i = -1;
				}
			}
			//FILE_PATH includes more than just filename
			if( -1 != idxOfNameStart )
			{
				//take the substring containing the folder path
				string folderPath = COC_FILE.substr( 0, idxOfNameStart );
				//if it doesnt exist, create it
				if( 0 != stat(folderPath.c_str(), &existence) )
				{
					mkdir( folderPath.c_str(), 0777 );
				}
			}
			//Initialize the fields (reset 0s everything as deired)
			resetBlockBytes();
			//set specific fields
			//get time of creation
			blockTimestamp.dblTime = unixTimestamp();;
			//case-id can remain all 0s
			//item-id can remain all 0s
			//set state to INITIAL
			string setValue = "INITIAL";
			memcpy( &blockState[0], setValue.c_str(), setValue.size() );
			//do some ridiculous data manipulation to get the exact bytes "Initial Block\0"
			setValue = "Initial block";
			int valByteLen = setValue.size() + 1;
			unsigned char dataBytes[setValue.size() + 1];
			for( int i = 0; i < valByteLen; i++ )
			{
				dataBytes[i] = '\0';
				if( i < setValue.size() )
				{
					dataBytes[i] = setValue[i];
				}
			}
			setValue = "";
			setValue.append((const char*)&dataBytes[0], valByteLen);
			blockDataLen.intLen = valByteLen;
			//create the INITIAL block and append it
			string initialBlock = blockToString( setValue );
			//make first entry in file
			writeToFile( initialBlock );
		}
		//else we have a block chain witha 1st block other than an INITIAL
	}
}
 
/**
 * @dev Method to add a new evidence item t othe blockchain
 * @param The case to associate to the item
 * @param The item to attempt to add
 * @param The Creator name to asosciate to the item
 */
int addItemToCase( string inCaseId, string inItemId, string inCreator )
{
	//check if method successfully added (0 = success / 1 = failure)
	int result = 0;
	//if we add before creating an INITIAL block, create one
	init();
	
	//before attempting to add a block,
	//clear out any existing data i nthe arrays
	resetBlockBytes();
	//prepare item for uniqueness check against entries in blockchain
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	memcpy( &itemID[0], inItemId.c_str(), inItemId.size() );
	
	//encrypt the data for simple comparison in the getEvidenceState()
	encryptBytes( &itemID[0], BLOCK_ITEM_ID_SIZE, false );
	int evidenceState = getEvidenceState( &itemID[0] );
	if( -1 == evidenceState)
	{
		//get the time the evidence was added
		uint64_t timeOfEvent = unixTimestamp();
		
		//evidence ID is unique and should be added
		//Capture timestamp and store
		blockTimestamp.dblTime = timeOfEvent;
		//copy Case Id (then encrypt the bytes)
		memcpy( &blockCaseID[0], inCaseId.c_str(), inCaseId.size() );
		encryptBytes( &blockCaseID[0], BLOCK_CASE_ID_SIZE, true );
		//copy Item Id (bytes already encrypted befoer checking evidence state)
		memcpy( &blockItemID[0], &itemID[0], BLOCK_ITEM_ID_SIZE );
		//set default state
		string defaultState = "CHECKEDIN";
		memcpy( &blockState[0], defaultState.c_str(), defaultState.size() );
		//copy creator id
		memcpy( &blockCreator[0], inCreator.c_str(), inCreator.size() );
		//Owner is left in default empty state
		//set the data length to 0 since there is no data field value
		blockDataLen.intLen = 0;
		
		//BCHOC does not support comments in the data field during adds
		string nextBlock = blockToString( "" );
		//append new block to end
		writeToFile( nextBlock );
		
		//event completed successfully, perform stdout operations
		printf("Added item: %s\n", inItemId.c_str());
		printf("Status: CHECKEDIN\n");
		printf("Time of Action: %s\n", translateTimestamp(timeOfEvent).c_str() );
	}
	else
	{
		printf("Evidence already exists\n");
		result = 1;
	}
	
	return result;
}

/**
 * @dev This method will attempt to checkout an item if it is in the checkedin state
 * @param The item id to attempt to checkout
 * @param The password will set the owner based on the password used to complete the action
 */
int checkoutItem( string inItemId, int checkoutPassword )
{
	//check if method successfully added (0 = success / 1 = failure)
	int result = 0;
	//before attempting to checkout an item
	//clear out any existing data in the arrays
	resetBlockBytes();
	//prepare item for check against entries in blockchain
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	memcpy( &itemID[0], inItemId.c_str(), inItemId.size() );
	
	//encrypt the data for simple comparison in the getEvidenceState()
	encryptBytes( &itemID[0], BLOCK_ITEM_ID_SIZE, false );
	int evidenceState = getEvidenceState( &itemID[0] );
	//operation only permitted if evidence is CHECKEDIN
	if( CHECKEDIN == evidenceState)
	{
		//get the time the evidence was checked out
		uint64_t timeOfEvent = unixTimestamp();
		
		//evidence Id is valid and in a CHECKEDIN state, make checkout entry
		//Capture timestamp and store
		blockTimestamp.dblTime = timeOfEvent;
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
		
		//event completed successfully, perform stdout operations
		string tmpCaseId = "";
		unsigned char tmpCaseIdBytes[BLOCK_CASE_ID_SIZE];
		memcpy(&tmpCaseIdBytes[0], &blockCaseID[0], BLOCK_CASE_ID_SIZE);
		decryptBytes( &tmpCaseIdBytes[0], BLOCK_CASE_ID_SIZE, false );
		tmpCaseId.append((const char*)&tmpCaseIdBytes[0], BLOCK_CASE_ID_SIZE);
		printf("Case: %s\n", tmpCaseId.c_str());
		printf("Checked out item: %s\n", inItemId.c_str());
		printf("Status: CHECKEDOUT\n");
		printf("Time of Action: %s\n", translateTimestamp(timeOfEvent).c_str() );
	}
	else
	{
		printf("Evidence CANNOT be Checked Out\n");
		result = 1; //return 1 on error
	}
	
	//return result
	return result;
}

/**
 * @dev This item looks for an item, and if it is checked out then it will make a checkin block
 * @param The item to attempt to checkin
 * @param The password used to complete the action will set the Owner field to POLICE/LAWYER/ANALYST/EXECUTIVE
 */
int checkinItem( string inItemId, int checkoutPassword )
{
	//check if method successfully added (0 = success / 1 = failure)
	int result = 0;
	//before attempting to checkin an item,
	//clear out any existing data in the arrays
	resetBlockBytes();
	//prepare item for check against entries in blockchain
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	memcpy( &itemID[0], inItemId.c_str(), inItemId.size() );
	
	//encrypt the data for simple comparison in the getEvidenceState()
	encryptBytes( &itemID[0], BLOCK_ITEM_ID_SIZE, false );
	int evidenceState = getEvidenceState( &itemID[0] );
	//operation only permitted if evidence is CHECKEDOUT
	if( CHECKEDOUT == evidenceState)
	{
		//get the time the evidence was checked in
		uint64_t timeOfEvent = unixTimestamp();
		
		//evidence Id is valid and in a CHECKEDOUT state, make checkin entry
		//Capture timestamp and store
		blockTimestamp.dblTime = timeOfEvent;
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
		
		//event completed successfully, perform stdout operations
		string tmpCaseId = "";
		unsigned char tmpCaseIdBytes[BLOCK_CASE_ID_SIZE];
		memcpy(&tmpCaseIdBytes[0], &blockCaseID[0], BLOCK_CASE_ID_SIZE);
		decryptBytes( &tmpCaseIdBytes[0], BLOCK_CASE_ID_SIZE, false );
		tmpCaseId.append((const char*)&tmpCaseIdBytes[0], BLOCK_CASE_ID_SIZE);
		printf("Case: %s\n", tmpCaseId.c_str());
		printf("Checked out item: %s\n", inItemId.c_str());
		printf("Status: CHECKEDIN\n");
		printf("Time of Action: %s\n", translateTimestamp(timeOfEvent).c_str() );
	}
	else
	{
		printf("Evidence CANNOT be Checked In\n");
		result = 1;
	}
	
	return result;
}

/**
 * @dev This method "removes" an evidence item from the Chain of Custody by updating its state
 * @param inItemId specifies which item to remove
 * @param removalType is the state change to DESTROYED/DISPOSED/RELEASED
 * @param removalReason is the string to put in the data field for the event (optional for all but RELEASED)
 */
int removeItem( string inItemId, int removalType, string removalReason , int checkoutPassword )
{
	//check if method successfully added (0 = success / 1 = failure)
	int result = 0;
	//before attempting to checkin an item,
	//clear out any existing data in the arrays
	resetBlockBytes();
	//prepare item for check against entries in blockchain
	unsigned char itemID[BLOCK_ITEM_ID_SIZE];
	memset( &itemID[0], 0, BLOCK_ITEM_ID_SIZE);
	memcpy( &itemID[0], inItemId.c_str(), inItemId.size() );
	
	//encrypt the data for simple comparison in the getEvidenceState()
	encryptBytes( &itemID[0], BLOCK_ITEM_ID_SIZE, false );
	int evidenceState = getEvidenceState( &itemID[0] );
	//operation only permitted if evidence is CHECKEDIN
	if( CHECKEDIN == evidenceState)
	{
		//get the time the evidence was removed
		uint64_t timeOfEvent = unixTimestamp();
		
		//evidence Id is valid and in a CHECKEDIN state, make removal entry
		//Capture timestamp and store
		blockTimestamp.dblTime = timeOfEvent;
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
		
		//event completed successfully, perform stdout operations
		string tmpCaseId = "";
		unsigned char tmpCaseIdBytes[BLOCK_CASE_ID_SIZE];
		memcpy(&tmpCaseIdBytes[0], &blockCaseID[0], BLOCK_CASE_ID_SIZE);
		decryptBytes( &tmpCaseIdBytes[0], BLOCK_CASE_ID_SIZE, false );
		tmpCaseId.append((const char*)&tmpCaseIdBytes[0], BLOCK_CASE_ID_SIZE);
		printf("Case: %s\n", tmpCaseId.c_str() );
		printf("Checked out item: %s\n", inItemId.c_str() );
		printf("Status: %s\n", removalState.c_str() );
		printf("Time of Action: %s\n", translateTimestamp(timeOfEvent).c_str() );
	}
	else
	{
		printf("Evidence CANNOT be Removed\n");
		result = 1;
	}
	
	return result;
}

/**
 * @dev Method that shows all unique cases in the blockchain
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
		//we need to sequentially check every block to determine the latest
		//state of this evidence item
		while( (ftell(fPtr) + BLOCK_MIN_SIZE) <= ftell(endPtr) )
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
		}
		fclose(fPtr);
	}
	
	//print all found cases
	for( int i = 0; i < caseIdList.size(); i++ )
	{
		//decrypt the data for human readable output
		decryptBytes( (unsigned char*)caseIdList[i].c_str(), BLOCK_CASE_ID_SIZE, false );
		caseIdList[i].insert(20, "-");
		caseIdList[i].insert(16, "-");
		caseIdList[i].insert(12, "-");
		caseIdList[i].insert(8, "-");
		printf("%s\n", caseIdList[i].c_str() );
	}
}

/**
 * @dev This method prints all Evidence items associated to the specified case
 * @param the case to find all items for
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
	encryptBytes( &tmpCaseId[0], BLOCK_CASE_ID_SIZE, true );
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
		//we need to sequentially check every block to determine the latest
		//state of this evidence item
		while( (ftell(fPtr) + BLOCK_MIN_SIZE) <= ftell(endPtr) )
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
		}
		fclose(fPtr);
	}
	
	//print all found cases
	for( int i = 0; i < itemIdList.size(); i++ )
	{
		//decrypt the data for human readable output
		decryptBytes( (unsigned char*)itemIdList[i].c_str(), BLOCK_ITEM_ID_SIZE, true );
		printf("%s\n", itemIdList[i].c_str() );
	}
}

/**
 * @dev Show's the individual blocks in the blockchain
 * @param inCaseId is an argument to filter the history by a specific Case ("" applies no filter)
 * @param inItemId is an argument to filter the history by a specific item ("" applies no filter)
 * @param numEntries defines how many entries to print (-1 prints all)
 * @param By default it prints oldest to newest, but reverse=true prints newest to oldest
 */
void showHistory( string inCaseId, string inItemId, int numEntries, bool reverse )
{
	//track the list of unique items to return
	vector<string> caseIdList;
	vector<string> itemIdList;
	vector<string> stateList;
	vector<uint64_t> timeList;
	//store the original strings for a simply empty compare later
	string origCaseId = inCaseId;
	string origItemId = inItemId;
	//translate inputs to a full length string for proper comparisons
	//This is because when reading from the byte array the string will always
	//be of length 32 (even if it is only "1234"). We need to translate the
	//input to be length 32 otherwise comparison will flag false by string
	//length even if its contents are matching
	unsigned char tmpCaseId[BLOCK_CASE_ID_SIZE];
	memset( &tmpCaseId[0], 0, BLOCK_CASE_ID_SIZE );
	memcpy( &tmpCaseId[0], inCaseId.c_str(), inCaseId.size() );
	//encrypting an empty string has errors, don't allow it
	if( 0 != inCaseId.compare("") )
	{
		//then we need to encrypt the bytes to match the blockchain sotrage
		encryptBytes( &tmpCaseId[0], BLOCK_CASE_ID_SIZE, true );
	}
	inCaseId = "";
	inCaseId.append((const char*)&tmpCaseId[0], BLOCK_CASE_ID_SIZE);
	//repeat process for Item ID
	unsigned char tmpItemId[BLOCK_ITEM_ID_SIZE];
	memset( &tmpItemId[0], 0, BLOCK_ITEM_ID_SIZE );
	memcpy( &tmpItemId[0], inItemId.c_str(), inItemId.size() );
	//encrypting an empty string has errors, don't allow it
	if( 0 != inItemId.compare("") )
	{
		//then we need to encrypt the bytes to match the blockchain sotrage
		encryptBytes( &tmpItemId[0], BLOCK_ITEM_ID_SIZE, false );
	}
	inItemId = "";
	inItemId.append((const char*)&tmpItemId[0], BLOCK_ITEM_ID_SIZE);	
	
	//confirm the file exists before attempting to read it
	if( fileExists() )
	{
		//store the reads of data
		unsigned char readCaseId[BLOCK_CASE_ID_SIZE];
		unsigned char readItemId[BLOCK_ITEM_ID_SIZE];
		unsigned char readState[BLOCK_STATE_SIZE];
		union
		{
			uint64_t dblTime;
			unsigned char byteTime[BLOCK_TIMESTAMP_SIZE];
		} readTimestamp;
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
		
		//we need to sequentially check every block to determine the latest
		//state of this evidence item
		while( (ftell(fPtr) + BLOCK_MIN_SIZE) <= ftell(endPtr) )
		{
			//notice, this method does no verification of blockchain integrity
			//offset computational support
			int offsetToNextField = 0;
			string tmpCase = "";
			string tmpItem = "";
			string tmpState = "";
			uint64_t tmpTime = 0;
			
			//advance from the head of the block to the timestamp field
			offsetToNextField = BLOCK_TIMESTAMP_OFFSET;
			fseek( fPtr, offsetToNextField, SEEK_CUR );
			fread( readTimestamp.byteTime, sizeof(char), BLOCK_TIMESTAMP_SIZE, fPtr);
			//save the timestamp to a uint64_t
			tmpTime = readTimestamp.dblTime;
			
			//advance from the end of the timestamp to the case id
			offsetToNextField = BLOCK_CASE_ID_OFFSET - (BLOCK_TIMESTAMP_OFFSET + BLOCK_TIMESTAMP_SIZE);
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
			
			//check to see if it should be appended to the list of matches
			//by comparing it to the Case ID & Item ID filter (guaranteed
			//add to list if both are "")
			bool addToList = true;
			if( 0 != origCaseId.compare("") )
			{
				//if the current case & filter case do not
				//match, then do not add to the list
				if(0 != tmpCase.compare(inCaseId))
				{
					addToList = false;
				}
			}
			if( 0 != origItemId.compare("") )
			{
				//if the current item & filter item do not
				//match, then do not add to the list
				if(0 != tmpItem.compare(inItemId))
				{
					addToList = false;
				}
			}
			//we will add to the list later, we don't have the state & time yet
			
			//advance from the end of the Item Id to the State
			offsetToNextField = BLOCK_STATE_OFFSET - (BLOCK_ITEM_ID_OFFSET + BLOCK_ITEM_ID_SIZE);
			fseek( fPtr, offsetToNextField, SEEK_CUR );
			fread( readState, sizeof(char), BLOCK_STATE_SIZE, fPtr );
			//convert the caseId bytes to a string
			tmpState.append((const char*)&readState[0], BLOCK_STATE_SIZE);
			
			//add the captured data from the block chain to the history list to show
			if( addToList )
			{
				caseIdList.push_back( tmpCase );
				itemIdList.push_back( tmpItem );
				stateList.push_back( tmpState );
				timeList.push_back( tmpTime );
			}
			
			//advance from the end of the State to the Data Length field
			offsetToNextField = BLOCK_DATA_LEN_OFFSET - (BLOCK_STATE_OFFSET + BLOCK_STATE_SIZE);
			fseek( fPtr, offsetToNextField, SEEK_CUR );
			//Compute the offset to read the length of this data field
			fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
			//advance from the DataLen field to the end of the data field
			//(recall the "fread" advances the fPtr)
			fseek( fPtr, readDataLen.intLen, SEEK_CUR );
		}
		fclose(fPtr);
	}
	
	//print all found cases
	//If -1 entries specified, show all of them. Also prevent out of bounds access.
	if( (-1 == numEntries) || (numEntries > itemIdList.size()) )
	{
		numEntries = itemIdList.size();
	}
	//the INITIAL block isn't encrypted, so we shouldn't
	//decrypt the results if it is among the list
	bool listContainsInitialBlock = false;
	if( (0 == origCaseId.compare("")) && (0 == origItemId.compare("")) )
	{
		listContainsInitialBlock = true;
	}
	//If "reverse" is true, print latest to oldest order
	if( reverse )
	{
		int bottom = itemIdList.size() - numEntries;
		if( bottom < 0 )
		{
			bottom = 0;
		}
		for( int i = itemIdList.size()-1; i >= bottom; i-- )
		{
			//INITIAL block is not encrypted
			if( !listContainsInitialBlock )
			{
				//decrypt the case id for human readable output
				decryptBytes( (unsigned char*)caseIdList[i].c_str(), BLOCK_CASE_ID_SIZE, false );
				//decrypt the item id for human readable output
				decryptBytes( (unsigned char*)itemIdList[i].c_str(), BLOCK_ITEM_ID_SIZE, true );
			}
			else if( 0 != i )
			{
				//decrypt the case id for human readable output
				decryptBytes( (unsigned char*)caseIdList[i].c_str(), BLOCK_CASE_ID_SIZE, false );
				//decrypt the item id for human readable output
				decryptBytes( (unsigned char*)itemIdList[i].c_str(), BLOCK_ITEM_ID_SIZE, true );
			}
			else
			{
				//For INITIAL block, expected to print "0" instead of "0000..."
				itemIdList[i] = "0";
			}
			//re-apply hifens
			caseIdList[i].insert(20, "-");
			caseIdList[i].insert(16, "-");
			caseIdList[i].insert(12, "-");
			caseIdList[i].insert(8, "-");
			//Time is a double of microseconds since Epoch, translate to human readable
			//NOTICE - autograder expects a single string output
			printf("Case: %s\nItem: %s\nAction: %s\nTime: %s\n\n",
						caseIdList[i].c_str(),
						itemIdList[i].c_str(),
						stateList[i].c_str(),
						translateTimestamp( timeList[i] ).c_str() );
		}
	}
	else
	{
		for( int i = 0; i < numEntries; i++ )
		{
			//INITIAL block is not encrypted
			if( !listContainsInitialBlock )
			{
				//decrypt the case id for human readable output
				decryptBytes( (unsigned char*)caseIdList[i].c_str(), BLOCK_CASE_ID_SIZE, false );
				//decrypt the item id for human readable output
				decryptBytes( (unsigned char*)itemIdList[i].c_str(), BLOCK_ITEM_ID_SIZE, true );
			}
			else if( 0 != i )
			{
				//decrypt the case id for human readable output
				decryptBytes( (unsigned char*)caseIdList[i].c_str(), BLOCK_CASE_ID_SIZE, false );
				//decrypt the item id for human readable output
				decryptBytes( (unsigned char*)itemIdList[i].c_str(), BLOCK_ITEM_ID_SIZE, true );
			}
			else
			{
				//For INITIAL block, expected to print "0" instead of "0000..."
				itemIdList[i] = "0";
			}
			//re-apply hifens
			caseIdList[i].insert(20, "-");
			caseIdList[i].insert(16, "-");
			caseIdList[i].insert(12, "-");
			caseIdList[i].insert(8, "-");
			//Time is a double of microseconds since Epoch, translate to human readable
			//NOTICE - autograder expects a single string output
			printf("Case: %s\nItem: %s\nAction: %s\nTime: %s\n\n",
						caseIdList[i].c_str(),
						itemIdList[i].c_str(),
						stateList[i].c_str(),
						translateTimestamp( timeList[i] ).c_str() );
		}
	}
	
}

/**
 * @dev Verify method that will check the blockchain for a set of potential errors
 */
int verify()
{
	int result = 0;
	bool allGood = true;
	int transCount = 0;
	//track all Hashes, it has been expressed that each hash will be unique
	vector<string> monitoredHash;
	//create dynamic lists to track linkage of case/item/states/creator
	vector<string> monitoredCaseId;
	vector<string> monitoredItemId;
	vector<string> monitoredState;
	vector<string> monitoredCreator;
	//track the Hash of the bad block and the reason it is bad
	vector<string> badBlocks;
	vector<int> failureCondition;
	//confirm the file exists before attempting to read it
	if( fileExists() )
	{
		//store the reads of data (Data field will be allocated for each block)
		unsigned char readPrevHash[BLOCK_PREV_HASH_SIZE];
		unsigned char readCaseId[BLOCK_CASE_ID_SIZE];
		unsigned char readItemId[BLOCK_ITEM_ID_SIZE];
		unsigned char readState[BLOCK_STATE_SIZE];
		unsigned char readCreator[BLOCK_CREATOR_SIZE];
		unsigned char readOwner[BLOCK_OWNER_SIZE];
		union
		{
			uint64_t dblTime;
			unsigned char byteTime[BLOCK_TIMESTAMP_SIZE];
		} readTimestamp;
		union
		{
			unsigned int intLen;
			unsigned char byteLen[4];
		} readDataLen;
		unsigned char readCurHash[BLOCK_PREV_HASH_SIZE];
		
		//additional variables to assist with verification
		uint64_t lastBlockTime = 0;
		unsigned char tmpINI[] = {'I','N','I','T','I','A','L','\0','\0','\0','\0','\0'};
		string initialState = "";
		initialState.append((const char*)&tmpINI[0], BLOCK_STATE_SIZE);
		unsigned char tmpCI[] = {'C','H','E','C','K','E','D','I','N','\0','\0','\0'};
		string checkinState = "";
		checkinState.append((const char*)&tmpCI[0], BLOCK_STATE_SIZE);
		unsigned char tmpCO[] = {'C','H','E','C','K','E','D','O','U','T','\0','\0'};
		string checkoutState = "";
		checkoutState.append((const char*)&tmpCO[0], BLOCK_STATE_SIZE);
		unsigned char tmpDE[] = {'D','E','S','T','R','O','Y','E','D','\0','\0','\0'};
		string destroyedState = "";
		destroyedState.append((const char*)&tmpDE[0], BLOCK_STATE_SIZE);
		unsigned char tmpDI[] = {'D','I','S','P','O','S','E','D','\0','\0','\0','\0'};
		string disposedState = "";
		disposedState.append((const char*)&tmpDI[0], BLOCK_STATE_SIZE);
		unsigned char tmpRE[] = {'R','E','L','E','A','S','E','D','\0','\0','\0','\0'};
		string releasedState = "";
		releasedState.append((const char*)&tmpRE[0], BLOCK_STATE_SIZE);
		
		//get the current contents of the blockchain
		FILE* fPtr;
		fPtr = fopen( COC_FILE.c_str(), "rb" );
		fseek( fPtr, 0, SEEK_SET );
		//store the end of the file location
		FILE* endPtr;
		endPtr = fopen( COC_FILE.c_str(), "rb" );
		fseek( endPtr, 0, SEEK_END );
		
		//since we are reading all fields, we can read them in order
		//and leverage that fread will advance the pointer with each read
		fread( readPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr);
		fread( readTimestamp.byteTime, sizeof(char), BLOCK_TIMESTAMP_SIZE, fPtr);
		fread( readCaseId, sizeof(char), BLOCK_CASE_ID_SIZE, fPtr);
		fread( readItemId, sizeof(char), BLOCK_ITEM_ID_SIZE, fPtr);
		fread( readState, sizeof(char), BLOCK_STATE_SIZE, fPtr );
		fread( readCreator, sizeof(char), BLOCK_CREATOR_SIZE, fPtr );
		fread( readOwner, sizeof(char), BLOCK_OWNER_SIZE, fPtr );
		fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
		
		//#1 check the integrity of the INITIAL block
		string actualIniState = "";
		actualIniState.append((const char*)&readState[0], BLOCK_STATE_SIZE);
		bool validIniBlock = true;
		if( 0 != actualIniState.compare( initialState ) )
		{
			//Initial block is not marked as initial, flag error
			validIniBlock = false;
			allGood = false;
		}
		int lengthOfData = readDataLen.intLen;
		unsigned char initDataField[lengthOfData];
		if( lengthOfData > 0 )
		{
			fread( &initDataField[0], sizeof(char), lengthOfData, fPtr );
		}
		//after reading the dat field, increment transaction counter
		transCount++;
		
		//compute the hash of the INITIAL block
		string recomputedHash = recomputeHash( &readPrevHash[0], &readTimestamp.byteTime[0],
						&readCaseId[0], &readItemId[0], &readState[0], &readCreator[0],
						&readOwner[0], &readDataLen.byteLen[0], &initDataField[0], lengthOfData);
		
		//log if the INITIAL block had errors
		if( !validIniBlock )
		{
			//convert the bytes back to human readable Hash value
			//for reporting purposes
			std::stringstream ss;
			ss << hex;
			for(int i = 0; i < BLOCK_PREV_HASH_SIZE; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << (int)recomputedHash[i];
			}
			string stringHash = ss.str();
			badBlocks.push_back(stringHash);
			failureCondition.push_back(1);
		}
		
		//we need to sequentially check every block to determine the latest
		//state of this evidence item
		while( (ftell(fPtr) + BLOCK_MIN_SIZE) <= ftell(endPtr) )
		{
			
			//variables to assist with field verification
			string tmpCase = "";
			string tmpItem = "";
			string tmpState = "";
			string tmpCreator = "";
			uint64_t tmpTime = 0;
			string tmpData = "";
			
			//since we are reading all fields, we can read them in order
			//and leverage that fread will advance the pointer with each read
			int blockHeadPtr = ftell(fPtr);
			fread( readPrevHash, sizeof(char), BLOCK_PREV_HASH_SIZE, fPtr);
			fread( readTimestamp.byteTime, sizeof(char), BLOCK_TIMESTAMP_SIZE, fPtr);
			fread( readCaseId, sizeof(char), BLOCK_CASE_ID_SIZE, fPtr);
			fread( readItemId, sizeof(char), BLOCK_ITEM_ID_SIZE, fPtr);
			int blockStatePtr = ftell(fPtr);
			fread( readState, sizeof(char), BLOCK_STATE_SIZE, fPtr );
			fread( readCreator, sizeof(char), BLOCK_CREATOR_SIZE, fPtr );
			fread( readOwner, sizeof(char), BLOCK_OWNER_SIZE, fPtr );
			int blockDataLenPtr = ftell(fPtr);
			fread( &readDataLen.byteLen[0], sizeof(char), BLOCK_DATA_LEN_SIZE, fPtr );
			//now we need to scan whatever data may be in the data field
			unsigned char readDataField[readDataLen.intLen];
			if( readDataLen.intLen > 0 )
			{
				fread( readDataField, sizeof(char), readDataLen.intLen, fPtr );
				tmpData.append((const char*)&readDataField[0], readDataLen.intLen);
			}
			//after reading the data field, increment transaction counter
			transCount++;
			
			
			//Then we translate the data fields we intend to do futher tracking/comparisons
			//of into other data types instead of raw bytes
			tmpTime = readTimestamp.dblTime;
			tmpCase.append((const char*)&readCaseId[0], BLOCK_CASE_ID_SIZE);
			tmpItem.append((const char*)&readItemId[0], BLOCK_ITEM_ID_SIZE);
			tmpState.append((const char*)&readState[0], BLOCK_STATE_SIZE);
			tmpCreator.append((const char*)&readCreator[0], BLOCK_CREATOR_SIZE);
			
			//--- Verification Checks ---
			//	2) Previous Hash matches the hash of the parent block
			//	3) 2 Blocks have same parent Hash
			//	4) Strictly Increasing Time
			//	5) Unique Item ID has unchanged Case ID
			//	6) Unique Item ID has unchanged Creator
			//	7) Item has appropriate state changes
			//		(Initial is Checkin || Checkin > Checkout || Checkout > Checkin || Checkin > Removed)
			
			//#2
			bool parentHashMatch = true;
			string prevHashResult = "";
			prevHashResult.append((const char*)&readPrevHash[0], BLOCK_PREV_HASH_SIZE);
			if( 0 != recomputedHash.compare(prevHashResult) )
			{
				parentHashMatch = false;
				allGood = false;
			}
			
			//#3
			bool uniqueHash = true;
			for( int i = 0; i < monitoredHash.size(); i++ )
			{
				//on match, 2 blocks have same parent
				if( 0 == prevHashResult.compare( monitoredHash[i] ) )
				{
					uniqueHash = false;
					allGood = false;
				}
			}
			//in all cases, append the hash to the list of monitored hashes
			monitoredHash.push_back( prevHashResult );
			
			//#4
			bool increasingTime = true;
			if( lastBlockTime > tmpTime )
			{
				increasingTime = false;
				allGood = false;
			}
			lastBlockTime = tmpTime;
			
			//#5/6/7
			bool unchangedCaseId = true;
			bool unchangedCreator = true;
			bool validInitialState = true;
			//check if this item is being tracked yet
			int itemMonitored = -1;
			for( int i = 0; i < monitoredItemId.size(); i++ )
			{
				if( 0 == tmpItem.compare( monitoredItemId[i] ) )
				{
					itemMonitored = i;
				}
			}
			if( -1 != itemMonitored )
			{
				//item is on the monitoring block, do verification
				if( 0 != tmpCase.compare( monitoredCaseId[itemMonitored] ) )
				{
					unchangedCaseId = false;
					allGood = false;
				}
				if( 0 != tmpCreator.compare( monitoredCreator[itemMonitored] ) )
				{
					unchangedCreator = false;
					allGood = false;
				}
			}
			else
			{
				//first instance of the item, add its values to the list
				monitoredCaseId.push_back( tmpCase );
				monitoredItemId.push_back( tmpItem );
				monitoredCreator.push_back( tmpCreator );
				monitoredState.push_back( tmpState );
				//partial check of #7, check initial value is CHECKEDIN
				if( 0 != checkinState.compare( tmpState ) )
				{
					validInitialState = false;
					allGood = false;
				}
			}
			
			//#7
			//leverage previous check for item existence in moitoring yet
			bool validStateChange = true;
			if( (-1 != itemMonitored) && (validInitialState) )
			{
				//determine previous state of the item
				if( 0 == checkinState.compare( monitoredState[itemMonitored] ) )
				{
					//previously CHECKEDIN
					//Allowable next states: CHECKEDOUT, DESTROYED, DISPOSED, RELEASED
					if( 0 == tmpState.compare( checkoutState ) )
					{
						validStateChange = true;
					}
					else if( 0 == tmpState.compare( destroyedState ) )
					{
						validStateChange = true;
					}
					else if( 0 == tmpState.compare( disposedState ) )
					{
						validStateChange = true;
					}
					else if( 0 == tmpState.compare( releasedState ) )
					{
						validStateChange = true;
					}
					else
					{
						validStateChange = false;
					}
				}
				else if( 0 == checkoutState.compare( monitoredState[itemMonitored] ) )
				{
					//previously CHECKEDOUT
					//Allowable next states: CHECKEDIN
					if( 0 == tmpState.compare( checkinState ) )
					{
						validStateChange = true;
					}
					else
					{
						validStateChange = false;
					}
				}
				else
				{
					//previously DESTROYED, DISPOSED, RELEASED
					//Allowable next states: N/A (any transition is illegal)
					validStateChange = false;
				}
				if( !validStateChange )
				{
					//there was an invalid state change
					allGood = false;
				}
				//in all cases, update the monitored state to what was read
				monitoredState[itemMonitored] = tmpState;
			}
			
			// --- End of Verification ---
			
			string thisBlock = "";
			//recreate the block to compute it's hash and compare to the stored hash
			thisBlock.append((const char*)&readPrevHash[0], BLOCK_PREV_HASH_SIZE);
			thisBlock.append((const char*)&readTimestamp.byteTime[0], BLOCK_TIMESTAMP_SIZE);
			thisBlock.append((const char*)&readCaseId[0], BLOCK_CASE_ID_SIZE);
			thisBlock.append((const char*)&readItemId[0], BLOCK_ITEM_ID_SIZE);
			thisBlock.append((const char*)&readState[0], BLOCK_STATE_SIZE);
			thisBlock.append((const char*)&readCreator[0], BLOCK_CREATOR_SIZE);
			thisBlock.append((const char*)&readOwner[0], BLOCK_OWNER_SIZE);
			thisBlock.append((const char*)&readDataLen.byteLen[0], BLOCK_DATA_LEN_SIZE);
			thisBlock.append( tmpData );
			//compute and append the hash value of this block as a string
			recomputedHash = computeHash(thisBlock);
			
			//convert the bytes back to human readable Hash value
			//for reporting purposes
			std::stringstream ss;
			ss << hex;
			unsigned char tmpCurHash[BLOCK_PREV_HASH_SIZE];
			memcpy( &tmpCurHash[0], recomputedHash.c_str(), BLOCK_PREV_HASH_SIZE );
			for(int i = 0; i < BLOCK_PREV_HASH_SIZE; ++i)
			{
				ss << std::setw(2) << std::setfill('0') << (int)tmpCurHash[i];
			}
			string stringHash = ss.str();
			
			//Catalog all failures for this Block
			if( !parentHashMatch )
			{
				badBlocks.push_back(stringHash);
				failureCondition.push_back(2);
			}
			if( !uniqueHash )
			{
				badBlocks.push_back(stringHash);
				failureCondition.push_back(3);
			}
			if( !increasingTime )
			{
				badBlocks.push_back(stringHash);
				failureCondition.push_back(4);
			}
			if( !unchangedCaseId )
			{
				badBlocks.push_back(stringHash);
				failureCondition.push_back(5);
			}
			if( !unchangedCreator )
			{
				badBlocks.push_back(stringHash);
				failureCondition.push_back(6);
			}
			if( (!validStateChange) || (!validInitialState) )
			{
				badBlocks.push_back(stringHash);
				failureCondition.push_back(7);
			}
			
		}
		//finally, check no incomplete blocks exist
		//meaning the end of the last block equals end of file
		if( ftell(fPtr) != ftell(endPtr) )
		{
			//no specific block to call out
			badBlocks.push_back("NULL");
			failureCondition.push_back(8);
		}
		
		fclose(fPtr);
	}
	else
	{
		printf("File not found\n");
	}
	
	/*
		CONDITIONS VERIFIED
		1) Invalid INITIAL block
		2) Previous Hash field matches the hash of the parent block
		3) 2 Blocks have same parent block hash
		4) Strictly Increasing Time
		5) Unique Item ID has unchanged Case ID
		6) Unique Item ID has unchanged Creator
		7) Item has appropriate state changes
		8) Trailing bytes near end of file (incomplete block risk)
	*/
	//print how many transactions are in the blockchain
	printf("Transactions in blockchain: %d\n", transCount);
	if( allGood )
	{
		printf("State of blockchain: CLEAN\n");
	}
	else
	{
		result = 1;
		//Errors were detected
		printf("State of blockchain: ERROR\n");
		for( int i = 0; i < badBlocks.size(); i++ )
		{
			//print the hash of the block with the error
			printf("Bad block: %s\n", badBlocks[i].c_str());
			//print a description of the identified error
			switch( failureCondition[i] )
			{
				case 1:
						printf("Invalid INITIAL block fields\n");
					break;
				case 2:
						printf("Previous Hash block content does not match parent block hash\n");
					break;
				case 3:
						printf("2 Blocks have same parent Hash\n");
					break;
				case 4:
						printf("Time not strictly increasing block chain events\n");
					break;
				case 5:
						printf("Case ID changed for Evidence Item\n");
					break;
				case 6:
						printf("Creator changed for Evidence Item\n");
					break;
				case 7:
						printf("Evidence Item had invalid State Change\n");
					break;
				case 8:
						printf("Incomplete block detected at end of file\n");
					break;
			}
			printf("\n");
		}
	}
	
	return result;
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
	//method result
	int mainResult = 0;
	//Get the command from the command line
	string inputCommand;
	
	//set a default file specification in case the env can't be read
	COC_FILE = "./blockchain";
	try
	{
		if( NULL != getenv("BCHOC_FILE_PATH") )
		{
			COC_FILE = getenv("BCHOC_FILE_PATH");
		}
		else
		{
			printf("Use default\n");
		}
	}
	catch( exception e )
	{
		printf("Failure using getenv()\n");
	}
	
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
					//trim out hifens before storing
					cmdCaseId.erase(23, 1);
					cmdCaseId.erase(18, 1);
					cmdCaseId.erase(13, 1);
					cmdCaseId.erase(8, 1);
					//do not exceed 32char length
					if( cmdCaseId.size() > 32 )
					{
						//printf("Case ID longer than 32 characters. Trimming input.\n");
						cmdCaseId = cmdCaseId.substr(0, 32);
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
						//printf("Creator longer than 12 characters. Trimming input.\n");
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
								//printf("Item ID longer than 32 characters. Trimming input.\n");
								cmdItemId = cmdItemId.substr(0, 32);
							}
							mainResult = addItemToCase( cmdCaseId, cmdItemId, cmdCreator );
						}
					}
					if( 0 == cmdItemId.compare("") )
					{
						//printf("No Item ID provided\n");
						mainResult = 1;
					}
				}
				else
				{
					if( 0 == cmdCaseId.compare("") )
					{
						//printf("No Case ID provided\n");
						mainResult = 1;
					}
					if( 0 == cmdCreator.compare("") )
					{
						//printf("No Creator provided\n");
						mainResult = 1;
					}
				}
			}
			else
			{
				//printf("Invalid Password\n");
				mainResult = 1;
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
							//printf("Item ID longer than 32 characters. Trimming input.\n");
							cmdItemId = cmdItemId.substr(0, 32);
						}
						mainResult = checkoutItem( cmdItemId, passwordId );
					}
				}
				if( 0 == cmdItemId.compare("") )
				{
					//printf("No Item ID provided\n");
					mainResult = 1;
				}
			}
			else
			{
				//printf("Invalid Password\n");
				mainResult = 1;
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
							//printf("Item ID longer than 32 characters. Trimming input.\n");
							cmdItemId = cmdItemId.substr(0, 32);
						}
						mainResult = checkinItem( cmdItemId, passwordId );
					}
				}
				if( 0 == cmdItemId.compare("") )
				{
					//printf("No Item ID provided\n");
					mainResult = 1;
				}
			}
			else
			{
				//printf("Invalid Password\n");
				mainResult = 1;
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
						//printf("Item ID longer than 32 characters. Trimming input.\n");
						cmdItemId = cmdItemId.substr(0, 32);
					}
				}
			}
			//Find the Removal Type
			for( int arg = 0; arg < argc; arg++ )
			{
				//guidelines specify "-y" and "--why" as inputs here
				if( (0 == strcmp("-y", argv[arg])) || (0 == strcmp("--why", argv[arg])) )
				{
					cmdRemovalType = argv[arg+1];
					//do not exceed 12char length
					if( cmdRemovalType.size() > 12 )
					{
						cmdRemovalType = cmdRemovalType.substr(0, 12);
					}
				}
			}
			//Find the reason for removal text
			for( int arg = 0; arg < argc; arg++ )
			{
				if( 0 == strcmp("-o", argv[arg]) )
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
				}
			}
			
			//Confirm Password is that of "CREATOR"
			int usedPassword = checkPassword( cmdPassword );
			if( 0 <= usedPassword )
			{
				//Confirm non-empty strings for mandatory checks
				if( 0 != cmdItemId.compare("") )
				{
					//RELEASED requires a non-empty reason
					if( 0 == cmdRemovalType.compare("RELEASED") )
					{
						mainResult = removeItem( cmdItemId, 3, cmdReason, usedPassword );
						/*if( 0 != cmdReason.compare("") )
						{
							mainResult = removeItem( cmdItemId, 3, cmdReason );
						}
						else
						{
							//printf("Attempted to RELEASE evidence without Reason\n");
							mainResult = 1;
						}*/
					}
					//the other 2 can have it filled out optionally
					else if( 0 == cmdRemovalType.compare("DISPOSED") )
					{
						mainResult = removeItem( cmdItemId, 1, cmdReason, usedPassword );
					}
					else if( 0 == cmdRemovalType.compare("DESTROYED") )
					{
						mainResult = removeItem( cmdItemId, 2, cmdReason, usedPassword );
					}
					else
					{
						//printf("Uknown Removal command\n");
						mainResult = 1;
					}
				}
				if( 0 == cmdItemId.compare("") )
				{
					//printf("No Item ID provided\n");
					mainResult = 1;
				}
			}
			else
			{
				//printf("Invalid Password\n");
				mainResult = 1;
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
							//trim out hifens before comparing
							cmdCaseId.erase(23, 1);
							cmdCaseId.erase(18, 1);
							cmdCaseId.erase(13, 1);
							cmdCaseId.erase(8, 1);
							//do not exceed 32char length
							if( cmdCaseId.size() > 32 )
							{
								//printf("Case ID longer than 32 characters. Trimming input.\n");
								cmdCaseId = cmdCaseId.substr(0, 32);
							}
							showItems( cmdCaseId );
						}
					}
					if( 0 == cmdCaseId.compare("") )
					{
						//printf("No Case ID provided\n");
						mainResult = 1;
					}
				}
				else if( 0 == inputCommand.compare("history") )
				{
					/*
					 * ==== SHOW HISTORY OPERATION ====
					 */
					//forward declare needed variables
					string cmdCaseId = ""; //optional
					string cmdItemId = ""; //optional
					string cmdPassword = ""; //NOT optional
					int numEntry = -1; //optional
					bool reverse = false; //optional
					
					//Find the Case
					for( int arg = 0; arg < argc; arg++ )
					{
						if( 0 == strcmp("-c", argv[arg]) )
						{
							cmdCaseId = argv[arg+1];
							//trim out hifens before comparing
							cmdCaseId.erase(23, 1);
							cmdCaseId.erase(18, 1);
							cmdCaseId.erase(13, 1);
							cmdCaseId.erase(8, 1);
							//do not exceed 32char length
							if( cmdItemId.size() > 32 )
							{
								//printf("Case ID longer than 32 characters. Trimming input.\n");
								cmdItemId = cmdItemId.substr(0, 32);
							}
						}
					}
					//Find the Item
					for( int arg = 0; arg < argc; arg++ )
					{
						if( 0 == strcmp("-i", argv[arg]) )
						{
							cmdItemId = argv[arg+1];
							//do not exceed 32char length
							if( cmdItemId.size() > 32 )
							{
								//printf("Item ID longer than 32 characters. Trimming input.\n");
								cmdItemId = cmdItemId.substr(0, 32);
							}
						}
					}
					//Find the Password
					for( int arg = 0; arg < argc; arg++ )
					{
						if( 0 == strcmp("-p", argv[arg]) )
						{
							cmdPassword = argv[arg+1];
						}
					}
					//Find the Number of Entries to print
					for( int arg = 0; arg < argc; arg++ )
					{
						if( 0 == strcmp("-n", argv[arg]) )
						{
							numEntry = stoi(argv[arg+1]);
						}
					}
					//Find the Reverse Flag
					for( int arg = 0; arg < argc; arg++ )
					{
						if( (0 == strcmp("-r", argv[arg])) || (0 == strcmp("--reverse", argv[arg])) )
						{
							reverse = true;
						}
					}
					
					
					//Confirm Password is POLICE, LAWYER, ANALYST, or EXECUTIVE
					int passwordId = checkPassword( cmdPassword );
					if( 0 < passwordId )
					{
						showHistory( cmdCaseId, cmdItemId, numEntry, reverse );
					}
					else
					{
						//printf("Invalid Password\n");
						mainResult = 1;
					}
				}
			}
		}
		else if( 0 == inputCommand.compare("init") )
		{
			/*
			 * ==== INIT OPERATION ====
			 */
			if( 2 == argc )
			{
				init();
			}
			else
			{
				//init should reject any additional arguments
				mainResult = 1;
			}
		}
		else if( 0 == inputCommand.compare("verify") )
		{
			/*
			 * ==== VERIFY OPERATION ====
			 */
			if( 2 == argc )
			{
				mainResult = verify();
			}
			else
			{
				//verify should reject any additional arguments
				mainResult = 1;
			}
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
	
	//exit accordingly
	return mainResult;
}