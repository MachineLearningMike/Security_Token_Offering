# Basic Sample Hardhat Project

This project demonstrates a basic Hardhat use case. It comes with a sample contract, a test for that contract, a sample script that deploys that contract, and an example of a task implementation, which simply lists the available accounts.

Try running some of the following tasks:

```shell
npx hardhat accounts
npx hardhat compile
npx hardhat clean
npx hardhat test
npx hardhat node
node scripts/sample-script.js
npx hardhat help
```


<b>II. Installation</b>

1. Clone this repository to your local machine.

2. Setup compilation/testing env in the local folder (All are necessary and nothing is optional):

    - Do not - npm init --yes //, unless you are now creating a new project.
    - npm install --save-dev hardhat
    - Do not - npx hardhat (Select Create a sample project), //, unless you are now creating a new project.
    - npm install --save dotenv
    - npm install --save @nomiclabs/hardhat-waffle

    - npm install --save @nomiclabs/hardhat-ethers
    - npm install --save--dev @nomiclabs/hardhat-etherscan
    - npm install --save-dev hardhat-deploy

    - npm install --save-dev chai
    - npm install --save ethers 
    - npm install --save ethereum-waffle

    - npm install --save-dev @openzeppelin/hardhat-upgrades
    - npm install --save-dev @openzeppelin/contracts-upgradeable

    - Do not - npm install --save @nomiclabs/hardhat-web3 web3 //, as you wont be using web3 for this project.

3. Install API keys in the following environmental variable names (See the configuration file for more):

    - "Infura_Key" : your Infura project key.
    - "Etherscan_API_Key" : you etherscan API key.