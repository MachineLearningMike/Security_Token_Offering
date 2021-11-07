const { expect, assert } = require("chai");
const { ethers, upgrades } = require("hardhat");
const {delay, fromBigNum, toBigNum} = require("./utils.js")


describe("Testing", function () {

	it("get owner as a signer. Signers are defined by the networks section in your hardhat.config.js.", async function () {
		[owner] = await ethers.getSigners();
		console.log("\towner's address = %s.", await owner.getAddress());
	});


  it("liquify, swapForEth, addLiquidity test", async function () {
		try {
			userWallet = ethers.Wallet.createRandom();
			userWallet = userWallet.connect(ethers.provider);
			var tx = await owner.sendTransaction({
				to: userWallet.address,
				value: ethers.utils.parseUnits("10",18)
			});
			await tx.wait();
		} catch(err) {
			assert.fail('User account was not created');
		}
  });

});