
# Developer Information
Group 5
	Ansh
	Jackson
	Margaret
	Naman

# Environment Configurations
Ubuntu 16.04 (or newer)

NVM v0.40.1

NPM v6.14.12

Node v10.24.1

HTML 5.0

Solidity v0.5.0

Truffle v5.0.2

Ganache

MetaMask (Chrome extension)

# Installation Instructions
## npm
sudo apt install npm

## nvm
curl -k -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash

## Node
nvm install 10

nvm use 10

## Truffle
npm install -g truffle@5.0.2

## Ganache
https://archive.trufflesuite.com/ganache/

# Execution Steps
1) Ensure Ganache is open and running

2) Configure MetaMask [this step only needs to be done once]

3) Compile Smart Contract [this step only needs to be done when the contract changes]

4) Migrate Smart Contract [this step only needs to be done when the contract changes]

5) Launch Browser


## Configure MetaMask
A) Create a private Network in MetaMask if one does not exist

	a) Top left of the chrome extension drop down
	
	b) Add network
	
	c) In the next window, add network manually
	
	d) Network name, chain id, & currency symbol can be anything (Set my chain id to 1337 & currency to ETH for consistency)
	
	e) The "RPC URL"  should match the "RPC Server" in your Ganache instance (most likely "HTTP://127.0.0.1:7545")
	
		e.1) If the network is not "HTTP://127.0.0.1:7545", then the top-level truffle-config.js will need so the "host" aand "port" match the local configuration
		
	f) Save, and it should be an accessible account in the chrome extension drop down
	
B) Ensure MetaMask is connected to the private network

C) Connect to the configured local ganache account in MetaMask (do the substeps if such an account is not yet configured)

	a) In Ganahce, select key icon for the first contract
	
	b) Copy the listed private key to this contract
	
	c) Navigate to MetaMask in browser and open the account options
	
	d) Select the "Add Account"
	
	e) Select "Import"
	
	f) Import by private key and then paste the copied private key
	
	g) Click "Import"
	

## Compile Smart Contract
truffle compile

## Migrate Contract Updates
truffle migrate

## Launch Browser
npm run dev

	**NOTE** -- If the above launches in the wrong browser (for example one without MetaMask) you can navigate to "http://localhost:3000/" in the correct browser to continue
	
You will now be able to interact with the Chain of Custody Blockchain

# Functional Description
TODO
