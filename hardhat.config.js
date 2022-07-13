/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: "0.8.14",
  networks: {
    ganache: {
      url: "127.0.0.1",
      port: 7545
    }
  }
};
