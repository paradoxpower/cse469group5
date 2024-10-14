
/*
 * Object containing all the variables and methods involving the smart contracts
 */
App = {
	loading: false,
	contracts: {},

	/**
	 * @dev Initialization method
	 */
	load: async () => {
		console.log("load async...")
		//check Web3 requirements met
		await App.loadWeb3()
		//specify the blockchain account to use
		await App.loadAccount()
		//create or load the COC contract
		await App.loadContract()
	},

	/**
	 * @dev Verify the browser supports Web3 technology (specifically MetaMask)
	 *		before loading things
	 *
	 * Note -- sourced from: https://medium.com/metamask/https-medium-com-metamask-breaking-change-injecting-web3-7722797916a8
	 */
	loadWeb3: async () => {
		console.log("loadWeb3 async...") //DEBUG
		if (typeof web3 !== 'undefined') {
			App.web3Provider = web3.currentProvider
			web3 = new Web3(web3.currentProvider)
		} else {
			window.alert("Please connect to Metamask.")
		}
		// Modern dapp browsers...
		if (window.ethereum) {
			window.web3 = new Web3(ethereum)
			try {
				// Request account access if needed
				await ethereum.enable()
				// Acccounts now exposed
				web3.eth.sendTransaction({/* ... */})
			} catch (error) {
				// User denied account access...
			}
		}
		// Legacy dapp browsers...
		else if (window.web3) {
			App.web3Provider = web3.currentProvider
			window.web3 = new Web3(web3.currentProvider)
			// Acccounts always exposed
			web3.eth.sendTransaction({/* ... */})
		}
		// Non-dapp browsers...
		else {
			console.log('Non-Ethereum browser detected. Project targets MetaMask Web3 browser.')
		}
		console.log("loadAccount done") //DEBUG
	},

	/**
	 * @dev Function to access the first account configured by Ganache
	 */
	loadAccount: async () => {
		console.log("loadAccount async...") //DEBUG
		// Set the current blockchain account
		App.account = web3.eth.accounts[0]
		console.log("loadWeb3 done") //DEBUG
	},

	/**
	 * @dev Function to load smart contract data from the blockchain
	 */
	loadContract: async () => {
		console.log("loadContract async...") //DEBUG
		
		// Create a JavaScript version of the smart contract
		const cocList = await $.getJSON('ChainOfCustody.json')
		App.contracts.ChainOfCustody = TruffleContract(cocList)
		App.contracts.ChainOfCustody.setProvider(App.web3Provider)
		// Populate the smart contract with values from the blockchain
		App.cocList = await App.contracts.ChainOfCustody.deployed()
		
		console.log("loadContract done") //DEBUG
	},
	
	/**
	 * @dev Function to put Case items in the blockchain
	 * @param caseId The ID of the case to which evidence is being added.
	 * @param itemIds Array of evidence item IDs being added.
	 */
	addCaseItems: async ( caseId, itemIds ) => {
		console.log("App.addCaseItems()") //DEBUG
		console.log("APP case id: " + caseId)
		for( let i = 0; i < itemIds.length; i++ )
			console.log("APP item id " + i + ": " + itemIds[i] )
		//get the deployed Chain of Custody
		const cocList = await App.contracts.ChainOfCustody.deployed()
		//add the items to the specified case
		await cocList.addEvidenceItems.call( caseId, itemIds );
	},
	
}

/*
 * Create method calls for each button on click
 * (TODO) - Add fields to get the desired information to use when buttons are clicked
 */

/**
 * @dev Add new evidence item(s) to the blockchain
 */
var addCaseElement = document.getElementById("addCaseButton")
addCaseElement.addEventListener( 'click', function(){
	console.log("Add Case...") //DEBUG
	//define arguments to pass
	let caseID = 1
	let itemIds = [2]
	let validInputs = true;
	
	//do necessary input/operation verification
	if( !("number" === typeof caseID) )
	{
		validInputs = false;
	}
	if( !(Array.isArray(itemIds)) )
	{
		validInputs = false;
	}
	//Notice -- Each item must have a unique ID, and that uniqueness is
	//			checked as part of the Contract (not by the web app)
	
	//call he method
	if( validInputs )
	{
		App.addCaseItems( caseID, itemIds )
	}
});

/**
 * @dev 
 */
var checkoutElement = document.getElementById("checkoutItemButton")
checkoutElement.addEventListener( 'click', function(){
	console.log("Checkout Item...") //DEBUG
	//define arguments to pass
	
	//do necessary input/operation verification
	
	//call the method
	
});

/**
 * @dev 
 */
var checkinElement = document.getElementById("checkinItemButton")
checkinElement.addEventListener( 'click', function(){
	console.log("Checkin Item...") //DEBUG
	//define arguments to pass
	
	//do necessary input/operation verification
	
	//call the method
	
});

/**
 * @dev 
 */
var showCasesElement = document.getElementById("showCasesButton")
showCasesElement.addEventListener( 'click', function(){
	console.log("Show Cases...") //DEBUG
	//define arguments to pass
	
	//do necessary input/operation verification
	
	//call the method
	
});

/**
 * @dev 
 */
var showItemsElement = document.getElementById("showItemsButton")
showItemsElement.addEventListener( 'click', function(){
	console.log("Show Items...") //DEBUG
	//define arguments to pass
	
	//do necessary input/operation verification
	
	//call the method
	
});

/**
 * @dev 
 */
var showHistoryElement = document.getElementById("showHistoryButton")
showHistoryElement.addEventListener( 'click', function(){
	console.log("Show History...") //DEBUG
	//define arguments to pass
	
	//do necessary input/operation verification
	
	//call the method
	
});

/**
 * @dev 
 */
var removeItemElement = document.getElementById("removeItemButton")
removeItemElement.addEventListener( 'click', function(){
	console.log("Remove Item...") //DEBUG
	//define arguments to pass
	
	//do necessary input/operation verification
	
	//call the method
	
});

/**
 * @dev 
 */
var initElement = document.getElementById("initButton")
initElement.addEventListener( 'click', function(){
	console.log("Initialize...") //DEBUG
	//define arguments to pass
	
	//do necessary input/operation verification
	
	//call the method
	
});

/**
 * @dev 
 */
var verifyElement = document.getElementById("verifyButton")
verifyElement.addEventListener( 'click', function(){
	console.log("Verify...") //DEBUG
	//define arguments to pass
	
	//do necessary input/operation verification
	
	//call the method
	
});

/**
 * @dev Main entry point for the app.js file as called by the index.html
 */
$(() => {
	$(window).load(() => {
		console.log("On load...") //DEBUG
		App.load()
	})
})