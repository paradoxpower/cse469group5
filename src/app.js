
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
	addCaseItems: async ( caseId, itemIds, creatorName ) => {
		console.log("App.addCaseItems()") //DEBUG
		console.log("APP case id: " + caseId)
		console.log("APP creator id: " + creatorName)
		for( let i = 0; i < itemIds.length; i++ )
			console.log("APP item id " + i + ": " + itemIds[i] )
		//get the deployed Chain of Custody
		const cocList = await App.contracts.ChainOfCustody.deployed()
		//add the items to the specified case
		await cocList.addEvidenceItems.call( caseId, itemIds, creatorName );
		return true;
	},
	
	/**
	 * @dev Function to update an item to CHECKEDOUT state
	 * @param itemId The item attempted to be checked out
	 */
	checkoutItem: async ( itemId ) => {
		console.log("App.checkoutItem()") //DEBUG
		console.log("APP item id: " + itemId)
		//get the deployed Chain of Custody
		const cocList = await App.contracts.ChainOfCustody.deployed()
		//checkout the specified item if possible
		//await cocList.???.call( itemId );
		return true;
	},
	
	/**
	 * @dev Function to update an item to CHECKEDIN state
	 * @param itemId The item attempted to be checked out
	 */
	checkinItem: async ( itemId ) => {
		console.log("App.checkinItem()") //DEBUG
		console.log("APP item id: " + itemId)
		//get the deployed Chain of Custody
		const cocList = await App.contracts.ChainOfCustody.deployed()
		//checkout the specified item if possible
		//await cocList.???.call( itemId );
		return true;
	},
	
}

// Define Password Constants
const BCHOC_PASSWORD_POLICE		= "P80P";
const BCHOC_PASSWORD_LAWYER		= "L76L";
const BCHOC_PASSWORD_ANALYST	= "A65A";
const BCHOC_PASSWORD_EXECUTIVE	= "E69E";
const BCHOC_PASSWORD_CREATOR	= "C67C";	//note -- creator can have many user-names,
											//Creator is a user archetype
const AES_KEY = "R0chLi4uLi4uLi4="; //TODO - confirm this is byte storage

/*
 * Create supporting methods that multiple buttons will leverage
 * for functionality (such as password checking)
 */

/**
 * @dev Check the input password is valid from the list
 * @param Password string
 */
function checkPassword( inputPassword )
{
	//default to an invalid match
	validPassword = false;
	//check input against valid passwords
	if( BCHOC_PASSWORD_POLICE === inputPassword )
	{
		validPassword = true;
	}
	if( BCHOC_PASSWORD_LAWYER === inputPassword )
	{
		validPassword = true;
	}
	if( BCHOC_PASSWORD_ANALYST === inputPassword )
	{
		validPassword = true;
	}
	if( BCHOC_PASSWORD_EXECUTIVE === inputPassword )
	{
		validPassword = true;
	}
	if( BCHOC_PASSWORD_CREATOR === inputPassword )
	{
		validPassword = true;
	}
	//return results (will only be true if a match was found)
	return validPassword;
}

/**
 * @dev Function to append output to the textarea on the web page
 * @param String ot append
 * @param Boolean of whether this string should be indented
 */
function appendTextarea( inputString, addIndent )
{
	let txtArea = document.getElementById("textOutput");
	if( addIndent )
	{
		txtArea.value += "\n\t" + inputString;
	}
	else
	{
		txtArea.value += "\n" + inputString;
	}
	//scroll to bottom of textarea with update
	txtArea.scrollTop = txtArea.scrollHeight;
}

/**
 * @dev Date Formatting method
 */
function getDateTime()
{
    var now     = new Date();
    var year    = now.getFullYear();
    var month   = now.getMonth()+1;
    var day     = now.getDate();
    var hour    = now.getHours();
    var minute  = now.getMinutes();
    var second  = now.getSeconds();
    if(month.toString().length == 1)
	{
         month = '0'+month;
    }
    if(day.toString().length == 1)
	{
         day = '0'+day;
    }   
    if(hour.toString().length == 1)
	{
         hour = '0'+hour;
    }
    if(minute.toString().length == 1)
	{
         minute = '0'+minute;
    }
    if(second.toString().length == 1)
	{
         second = '0'+second;
    }
    var dateTime = year+'-'+month+'-'+day+'T'+hour+':'+minute+':'+second+"Z";
    return dateTime;
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
	let tmpVal = "";
	
	//get case ID
	let caseID = "";
	tmpVal = document.getElementById("addCaseID").value;
	//only translate if field is non-empty
	if( !((null == tmpVal) || ("" == tmpVal) ) )
	{
		caseID = document.getElementById("addCaseID").value;
	}
	//get password
	let inputPassword = document.getElementById("addPassword").value;
	//get the full list of items
	let rawItemIds = "";
	let itemIds;
	tmpVal = document.getElementById("addItemID").value;
	if( !((null == tmpVal) || ("" == tmpVal) ) )
	{
		rawItemIds = document.getElementById("addItemID").value;
		//remove any spaces
		rawItemIds = rawItemIds.split(' ').join('');
		//delimit them by ","
		itemIds = rawItemIds.split(",");
	}
	//get Creator Name
	let creatorName = "";
	tmpVal = document.getElementById("addCreatorId").value;
	//only translate if field is non-empty
	if( !((null == tmpVal) || ("" == tmpVal) ) )
	{
		creatorName = document.getElementById("addCreatorId").value;
		//take only the first 12 characters
		if( creatorName.length > 12 )
		{
			creatorName = creatorName.substring(0,12);
		}
	}
	
	//booleans to check validity of operation
	let validCaseId = true;
	let validItemIds = true;
	let validPassword = checkPassword( inputPassword );
	let validCreator = true;
	
	//do necessary input/operation verification
	if( "" === caseID )
	{
		validCaseId = false;
	}
	if( "" === creatorName )
	{
		validCreator = false;
	}
	if( !(Array.isArray(itemIds)) )
	{
		validItemIds = false;
	}
	else
	{
		//ensure no ids are non-number
		for( var i = 0; i < itemIds.length; i++ )
		{
			itemIds[i] = Number(itemIds[i]);
			if( isNaN(itemIds[0]) )
			{
				validItemIds = false;
				i = itemIds.length; //quick exit
			}
		}
	}
	//Notice -- Each item must have a unique ID, and that uniqueness is
	//			checked as part of the Contract (not by the web app)
	
	//call he method
	if( validCaseId && validItemIds && validPassword && validCreator )
	{
		var addSuccess = App.addCaseItems( caseID, itemIds, creatorName )
		//follow project guidelines of expect output
		if( addSuccess )
		{
			var fmtDate = getDateTime();
			for( var i = 0; i < itemIds.length; i++ )
			{
				appendTextarea( ("Added Item " + itemIds[i]), false);
				appendTextarea("Status: CHECKEDIN", false);
				appendTextarea( ("Time of action: " + fmtDate), false);
			}
		}
	}
	else
	{
		appendTextarea("Add Evidence Error: ", false);
		if( !validCaseId )
		{
			appendTextarea("Invalid Case ID", true);
		}
		if( !validItemIds )
		{
			appendTextarea("Invalid Item ID", true);
		}
		if( !validPassword )
		{
			appendTextarea("Invalid Password", true);
		}
		if( !validCreator )
		{
			appendTextarea("Invalid Creator", true);
		}
	}
});

/**
 * @dev Attempt to add a Checkout log for an evidence item to the blockchain
 */
var checkoutElement = document.getElementById("checkoutItemButton")
checkoutElement.addEventListener( 'click', function(){
	console.log("Checkout Item...") //DEBUG
	let tmpVal = "";
	
	//get item ID
	let itemID = "";
	tmpVal = document.getElementById("checkoutItemID").value;
	//only translate if field is non-empty
	if( !((null == tmpVal) || ("" == tmpVal) ) )
	{
		itemID = document.getElementById("checkoutItemID").value;
	}
	//get password
	let inputPassword = document.getElementById("checkoutPassword").value;
	
	//booleans to check validity of operation
	let validItemId = true;
	let validPassword = checkPassword( inputPassword );
	
	//do necessary input/operation verification
	if( "" === itemID )
	{
		validItemId = false;
	}
	
	//call the method
	if( validItemId && validPassword )
	{
		var checkoutSuccess = App.checkoutItem( itemID )
		//follow project guidelines of expect output
		if( checkoutSuccess )
		{
			var fmtDate = getDateTime();
			appendTextarea( ("Checkedout Item " + itemID), false);
			appendTextarea( ("Time of action: " + fmtDate), false);
		}
	}
	else
	{
		appendTextarea("Checkout Evidence Error: ", false);
		if( !validItemId )
		{
			appendTextarea("Invalid Item ID", true);
		}
		if( !validPassword )
		{
			appendTextarea("Invalid Password", true);
		}
	}
});

/**
 * @dev Attempt to add a Checkin log for an evidence item to the blockchain
 */
var checkinElement = document.getElementById("checkinItemButton")
checkinElement.addEventListener( 'click', function(){
	console.log("Checkin Item...") //DEBUG
	let tmpVal = "";
	
	//get item ID
	let itemID = "";
	tmpVal = document.getElementById("checkinItemID").value;
	//only translate if field is non-empty
	if( !((null == tmpVal) || ("" == tmpVal) ) )
	{
		itemID = document.getElementById("checkinItemID").value;
	}
	//get password
	let inputPassword = document.getElementById("checkinPassword").value;
	
	//booleans to check validity of operation
	let validItemId = true;
	let validPassword = checkPassword( inputPassword );
	
	//do necessary input/operation verification
	if( "" === itemID )
	{
		validItemId = false;
	}
	
	//call the method
	if( validItemId && validPassword )
	{
		var checkinSuccess = App.checkinItem( itemID )
		//follow project guidelines of expect output
		if( checkinSuccess )
		{
			var fmtDate = getDateTime();
			appendTextarea( ("Checkedin Item " + itemID), false);
			appendTextarea( ("Time of action: " + fmtDate), false);
		}
	}
	else
	{
		appendTextarea("Checkin Evidence Error: ", false);
		if( !validItemId )
		{
			appendTextarea("Invalid Item ID", true);
		}
		if( !validPassword )
		{
			appendTextarea("Invalid Password", true);
		}
	}
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