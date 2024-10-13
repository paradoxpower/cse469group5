
//process to redploy the contracts
var cocList = artifacts.require("./ChainOfCustody.sol");

module.exports = function(deployer) {
  deployer.deploy(cocList);
};