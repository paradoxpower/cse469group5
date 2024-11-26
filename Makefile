
#Specify a default build dependency set
default: bchoc

#Build the "boot_info" binary
bchoc: FORCE
	g++ -std=c++11 bchoc.cpp -o bchoc -lssl -lcrypto
	chmod +x bchoc

#By including "FORCE" this will cause the "make" command to
#rebuild the bchoc target even if the binary exists
FORCE:

#clean up any binaries or logs. The "|| true" will cause
#the process to continue cleaning even if a file of that
#name is not found
clean:
	rm bchoc || true
	rm CoC.bin || true
