
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
		await App.loadWeb3()
		await App.loadAccount()
		await App.loadContract()
	},

	/**
	 * @dev 
	 *
	 * Note -- sourced from: https://medium.com/metamask/https-medium-com-metamask-breaking-change-injecting-web3-7722797916a8
	 */
	loadWeb3: async () => {
		console.log("loadWeb3 async...")
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
	},

	/**
	 * @dev Function to access the first account configured by Ganache
	 */
	loadAccount: async () => {
		console.log("loadAccount async...")
		// Set the current blockchain account
		App.account = web3.eth.accounts[0]
	},

	/**
	 * @dev Function to load smart contract data from the blockchain
	 */
	loadContract: async () => {
		console.log("loadContract async...")
		// Create a JavaScript version of the smart contract
		const cocList = await $.getJSON('ChainOfCustody.json')
		App.contracts.ChainOfCustody = TruffleContract(cocList)
		App.contracts.ChainOfCustody.setProvider(App.web3Provider)

		// Populate the smart contract with values from the blockchain
		App.cocList = await App.contracts.ChainOfCustody.deployed()
	},
	
}

//get all the html buttons and associate them to functions on click
document.getElementById("addCaseButton").onclick = addCaseFunc;
document.getElementById("checkoutItemButton").onclick = checkoutItemFunc;
document.getElementById("checkinItemButton").onclick = checkinItemFunc;
document.getElementById("showCasesButton").onclick = showCasesFunc;
document.getElementById("showItemsButton").onclick = showItemsFunc;
document.getElementById("showHistoryButton").onclick = showHistoryFunc;
document.getElementById("removeItemButton").onclick = removeFunc;
document.getElementById("initButton").onclick = initFunc;
document.getElementById("verifyButton").onclick = verifyFunc;

/**
 * @dev 
 */
function addCaseFunc() {
	console.log("Case Add...")
}

/**
 * @dev 
 */
function checkoutItemFunc() {
	console.log("Checkout Item...")
}

/**
 * @dev 
 */
function checkinItemFunc() {
	console.log("Checkin Item...")
}

/**
 * @dev 
 */
function showCasesFunc() {
	console.log("Show Cases...")
}

/**
 * @dev 
 */
function showItemsFunc() {
	console.log("Show Items...")
}

/**
 * @dev 
 */
function showHistoryFunc() {
	console.log("Show History...")
}

/**
 * @dev 
 */
function removeFunc() {
	console.log("Remove Item...")
}

/**
 * @dev 
 */
function initFunc() {
	console.log("Initialize...")
}

/**
 * @dev 
 */
function verifyFunc() {
	console.log("Verify...")
}

/**
 * @dev Main entry point for the app.js file as called by the index.html
 */
$(() => {
	$(window).load(() => {
		console.log("On load...");
		App.load()
	})
})