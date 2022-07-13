import Caverjs, { AbiItem } from 'caver-js'
import * as env from 'dotenv'
import path from 'path'
import fs from 'fs';
import didRegistry from '../artifacts/contracts/DIDRegistry.sol/DIDRegistry.json';

const runProc = async function()
{
  try{
    if(process.argv.length !== 3){
      throw new Error('Usage Error : npx ts-node src/deploy.ts passwd');
    }
    env.config({path:path.join(__dirname,'./.env')});

    const deployKeystore = `${process.env.KEYSTORE_PATH}${process.env.DEPLOY_KEYSTORE}`;

    if(deployKeystore === undefined){
      throw new Error('There is no "DEPLOY_KEYSTORE" in .env file');
    }
    const keystore = JSON.parse(fs.readFileSync(deployKeystore).toString());

    const passwd = process.argv[2];

    const caver = new Caverjs(process.env.RPCURL);

    const keyring = caver.wallet.keyring.decrypt(keystore, passwd);

    caver.wallet.add(keyring);

    let contract = caver.contract.create(didRegistry.abi as AbiItem[]);

    let data = contract.deploy({data:didRegistry.bytecode}).encodeABI();

    const address = keyring.address;

    const rawTx = {from:address, data, gas:4500000};

    let tx = caver.transaction.smartContractDeploy.create(rawTx);

    await caver.wallet.sign(address, tx);

    await caver.rpc.klay.sendRawTransaction(tx)
    .on('receipt', function(receipt){
        console.log(receipt);
    });
  }
  catch(error){
    console.log(error);
  }
}

runProc();