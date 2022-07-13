import {createAccount, makeKeyring, compressPublicKey,
  getChainId, getContract, sendRawTransaction,toChecksumAddress, getKeyringFromKeystore, addKeyring, publicKeyToAddress, gas, defaultRegistry} from './caver'
import DIDResolver from './Resolver/resolver';
import {publicKeyFromDID, stringToBytes, stringToBytes32} from './utils'
import fs from 'fs'

import * as env from 'dotenv'
import path from 'path'

env.config({path:path.join(__dirname,'./.env')});

class DIDManager{
  private didResolver:DIDResolver;
  private eip1056Contract;
  constructor(){
    this.didResolver = new DIDResolver();
    this.eip1056Contract = getContract();
  }
  create(passwd:string){
    try{
      const {address, privateKey} = createAccount();

      const keyring = makeKeyring(address, privateKey);
      
      const keystore = keyring.encrypt(passwd);

      const publicKey = keyring.getPublicKey();

      const did = `did:klay:${compressPublicKey(publicKey)}`;

      const keystoreStr = JSON.stringify(keystore);

      fs.writeFileSync(`./keystore/${address}.txt`,keystoreStr)
      fs.appendFileSync('./dids.txt',did+'\n');

      return did;
    }
    catch (error){
      console.log('createDID Error '+error);
    }
  }

  list(){
    const dids = fs.readFileSync('./dids.txt','utf-8');
    return dids.split('\n').filter(
      (element, i) => element != ''
    );
  }

  delete(did:string){
    try{
      const dids = fs.readFileSync('./dids.txt','utf-8');
      const didArray = dids.split('\n');
      const indexDID = didArray.indexOf(did);
      if(indexDID < 0)
      {
        throw new Error(`There is no did ${did}`);
      }
      didArray.splice(indexDID,1);

      fs.writeFileSync('./dids.txt','');
      for(const did of didArray){
        if(did){
          fs.appendFileSync('./dids.txt', `${did}\n`);
        }
      }

      const publicKey = publicKeyFromDID(did);
      const address = publicKeyToAddress(publicKey);
      fs.unlinkSync(`./keystore/${address}.txt`);
    }
    catch (error){
      console.log(error);
      return false;
    }
  }

  private async transactionExecution(func:any, from:string, passwd:string){
    const input = await func.encodeABI();

    const keystore = fs.readFileSync(`./keystore/${from}.txt`);
    
    const keyring = getKeyringFromKeystore(keystore.toString(), passwd);
    
    addKeyring(keyring);

    const rawTx = {
      from,
      to:toChecksumAddress(defaultRegistry!),
      input,
      gas:gas.execution,
    };

    return await sendRawTransaction(from, rawTx);
  }

  async addDelegate(subjectDID:string, passwd:string, fromDID:string, delegateType:string, expireSecond:number){
    try{
      const subjectPublicKey = publicKeyFromDID(subjectDID);
      const subjectAddress = publicKeyToAddress(subjectPublicKey);

      const fromPublicKey = publicKeyFromDID(fromDID);
      const fromAddress = publicKeyToAddress(fromPublicKey);

      const func = this.eip1056Contract.methods.addDelegate(subjectAddress, stringToBytes32(delegateType), fromAddress, expireSecond);
      
      await this.transactionExecution(func,subjectAddress,passwd);
    }
    catch(error){
      console.log(error);
      return false;
    }
  }

  async changeOwner(subjectDID:string, passwd:string, ownerDID:string){
    try{
      const subjectPublicKey = publicKeyFromDID(subjectDID);
      const subjectAddress = publicKeyToAddress(subjectPublicKey);

      const ownerPublicKey = publicKeyFromDID(ownerDID);
      const ownerAddress = publicKeyToAddress(ownerPublicKey);

      const func = this.eip1056Contract.methods.changeOwner(subjectAddress, ownerAddress);
    
      await this.transactionExecution(func,subjectAddress, passwd);
    }
    catch(error){
      console.log(error);
      return false;
    }
  }

  private async setAttribute(did:string, passwd:string, name:string, value:string, expireSecond:number){
    try{
      const publicKey = publicKeyFromDID(did);
      const address = publicKeyToAddress(publicKey);

      const func = this.eip1056Contract.methods.setAttribute(address,stringToBytes32(name), stringToBytes(value), expireSecond);

      await this.transactionExecution(func, address, passwd);
    }
    catch(error){
      console.log(error);
      return false;
    }
  }

  async addKey(did:string, passwd:string, newPasswd:string, type:string, expireSecond:number){   //key타입은 Secp256k1으로 고정
    const {address, privateKey} = createAccount();

    const keyring = makeKeyring(toChecksumAddress(address), privateKey);

    const keystore = keyring.encrypt(newPasswd);

    const keystoreStr = JSON.stringify(keystore);

    fs.writeFileSync(`./keystore/${address}.txt`,keystoreStr)

    const usg = type;
    const encoding = 'hex'; 
    const name = `did/key/Secp256k1/${usg}/${encoding}`;
    const value = keyring.getPublicKey();

    await this.setAttribute(did,passwd,name,value, expireSecond);
  }

  async addService(did:string, passwd:string, type:string='DIDCommMessaging', endpoint:string, expireSecond:number){
    try{
      const name = `did/svc/${type}`;
      const value = endpoint;

      const result = await this.setAttribute(did,passwd,name,value,expireSecond);
      return result;
    }
    catch(error){
      console.log('addService fail',error);
      return false;
    }
  }

  async resolve(did:string){
    if(did.indexOf('#')!==-1){
      did = did.substring(0,did.indexOf('#'));
    }
    const publicKey = publicKeyFromDID(did);
    const address = publicKeyToAddress(publicKey);
    const chainId = await getChainId();

    const didDocument = await this.didResolver.resolve(did,address,publicKey,Number(chainId));
    return didDocument;
  }
}

export default DIDManager;