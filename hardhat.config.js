require('dotenv').config();
require("@nomiclabs/hardhat-waffle"); // For mocha to be able to compare big numbers.
//require("@nomiclabs/hardhat-etherscan");
require('hardhat-deploy');
require('@openzeppelin/hardhat-upgrades');

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task("accounts", "Prints the list of accounts", async (taskArgs, hre) => {
  const accounts = await hre.ethers.getSigners();

  for (const account of accounts) {
    console.log(account.address);
  }
});

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
	networks: {
		rinkeby: {
			url: "https://rinkeby.infura.io/v3/" + process.env.Infura_Key,
			accounts: []
		},
		mainnet: {
			url: "https://mainnet.infura.io/v3/" + process.env.Infura_Key,
			accounts: []
		},
	},
	etherscan: {
		// Your API key for Etherscan
		// Obtain one at https://etherscan.io/
		apiKey: process.env.Etherscan_API_Key
	},
  solidity: {
    compilers: [
      {
        version: '0.5.8',
        settings: {
          optimizer: {
            enabled: true,
            runs: 0 //ORG 800
          },
          metadata: {
            // do not include the metadata hash, since this is machine dependent
            // and we want all generated code to be deterministic
            // https://docs.soliditylang.org/en/v0.7.6/metadata.html
            bytecodeHash: 'none',
          },
        },
      },
			{
				version: "0.8.0",
				settings: {
					optimizer: {
						enabled: true,
						runs: 200,
					}
				},
			},
			{
				version: "0.4.24",
				settings: {
					optimizer: {
						enabled: true,
						runs: 200,
					}
				},
			},
      {
				version: "0.4.18", // for WETH
				settings: {
					optimizer: {
						enabled: true,
						runs: 200,
					}
				},
			},
    ],
  },
};
