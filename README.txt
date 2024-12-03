
====
Developer Information
====
Name & ASU IDs
--------------
Ansh Vinod Motwani	|	1228892342
Jackson Nichols 	|	1209023942
Naman Sharma		|	1230090591


====
Compilation Environment
====
Ubuntu 16.04 (or newer)
g++ version 5.4.0 20160609 (or newer)

====
C++ Library Dependencies
====
Standard: stdio.h, string.h, vector, chrono
I/O: iostream, fstream, iomanip, sstream
SSL/Cypto: openssl/md5.h, openssl/sha.h

====
Execution Steps
====
make clean
make
./bchoc [desired operation]


====
Execution Description
====
Program has multiple execution methods including:
	add -c case_id -i item_id [-i item_id ...] -g creator -p password(creator’s)
	checkout -i item_id -p password
	checkin -i item_id -p password
	show cases 
	show items -c case_id
	show history [-c case_id] [-i item_id] [-n num_entries] [-r] -p password
	remove -i item_id -y reason -p password(creator’s)
	init
	verify
	
Description in order

init
----
This method checks to see if an INITIAL block exists and has 3 paths of execution
	1) It cannot find the blockchain file, so it creates one and inserts a new INITIAL block
	2) It finds an existing blockchain file. It checks the first block and confirms that
		the block is an INITIAL block
	3) It finds an existing blockchain file. It checks the first block and alerts the user
		that the block is not an INITIAL block


add
----
Before performing this operation, the method checks all 4 arguments are present.
Then it confirms the input password is that of the Creator. If that all passes then it
continues with execution.

This method opens the blockchain file and reads it block-by-block, looking for the input
item id. If it finds the item already in the blockchain it will reject the addition of
the evidence item due to a non-unique item id. If the item is not in the blockchain yet,
it will append the item to the end with the provided case id, item id, and creator. It will
timestamp just before the append, set the owner to the creator, and then set the state
to CHECKEDIN.


checkout
----
Before performing this operation, the method checks both arguments are present.
Then it confirms the input password is that of the LAWYER, ANALYST, POLICE, or EXECUTIVE.
If that all passes then it continues with execution.

This method opens the blockchain file and reads it block-by-block, looking for the input
item id. If it finds the item it will note its current state and keep going to make sure this
block is the latest block in the chain. Once the state of the latest block is found it will
check that the state is CHECKEDIN. If that matches then the blockchain will create a CHECKOUT
block to append. It will use the same case id, item id, and creator data fro mthe found block.
It will append the Owner to the person who checked it out, timestamp it, and then set the state
to CHECKEDOUT.


checkin
----
Before performing this operation, the method checks both arguments are present.
Then it confirms the input password is that of the LAWYER, ANALYST, POLICE, or EXECUTIVE.
If that all passes then it continues with execution.

This method opens the blockchain file and reads it block-by-block, looking for the input
item id. If it finds the item it will note its current state and keep going to make sure this
block is the latest block in the chain. Once the state of the latest block is found it will
check that the state is CHECKEDOUT. If that matches then the blockchain will create a CHECKIN
block to append. It will use the same case id, item id, and creator data from the found block.
It will append the Owner to the person who checked it out, timestamp it, and then set the state
to CHECKEDIN.


remove
----
Before performing this operation, the method checks all required arguments are present.
If the "reason" for removal is "RELEASED" then an additional field explaining the release is
required. Then it confirms the input password is that of the Creator. If that all passes
then it continues with execution.

This method opens the blockchain file and reads it block-by-block, looking for the input
item id. If it finds the item it will note its current state and keep going to make sure this
block is the latest block in the chain. Once the state of the latest block is found it will
check that the state is CHECKEDIN. If that matches then the blockchain will create a removal
block. It will use the same case id, item id, and creator data from the found block. It will
append the Creator as the Owner, timestamp it, and append the specified removal command as the
state (DISPOSED / DESTROYED / RELEASED). Any of these can have additional information appended
to the data field, but only RELEASED expects it.


show cases
----
This operation does no preliminary argument verification.

This method opens the blockchain file and reads it block-by-block, looking for unique case ids.
Once it finds a case id, it checks the current list to see if it has already been added, and if
it hasn't it will be appended to the end. Once all unique cases in the blockchain are found they
are displayed in order to the console.


show items
----
Before performing this operation, the method checks it has a specified Case ID to check.

This method opens the blockchain file and reads it block-by-block, looking for the input
case id. On match it checks the item id against the existing list of logged items. If this
is a new unique item associated to the case, it will add it to the list of results. Once the
blockchain has been fully iterated, the method prints all findings to the screen.


show history
----
Before performing this operation, the method checks it has a valid password of either CREATOR,
POLICE, LAWYER, ANALYST, or EXECUTIVE. the restof the arguments are optional.

This method goes block by block in the blockchain and captures the case id, item id, Action
(such as CHECKEDOUT/CHECKEDIN), and time of action. Once every block in the blockchain is captured
it is printed to the console from oldest to newest (and the timestamp is formatted to not be
in microsecond counts since epoch).
The optional arguments will dictate what is added to the history and how the history is presented.
The Case Id will filter the history to only cases matching the ID.
The Item Id will filter the history to only item matching the ID.
The R flag will reverse the display order to print newest ot oldest.
The Number of entries will limit the count of displayed entries to this number (as long as there are enough entries).
These optional flags can be applied together in any combination.


verify
----
This operation does no preliminary argument verification.

It iterates the blockchain block-by-block looking for a set of invalid operations that could exist
in the blockchain. The set includes:
	1) Previous Hash field matches the hash of the parent block
	2) Strictly Increasing Time
	3) Unique Item ID has unchanged Case ID
	4) Unique Item ID has unchanged Creator
	5) Item has appropriate state changes
	6) Recompute the hash of the stored data and compare to the stored hash
If a violation is found, the block hash and vilation are logged. Once the entire chain has been
checked the method will print out the total count of blocks in the chain and the violations found
in the order they were found. If no violations are found, it will report CLEAN.

