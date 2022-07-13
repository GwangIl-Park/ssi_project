import Caverjs, { SingleKeyring, Keyring } from 'caver-js'
import * as didRegistry from '../artifacts/contracts/DIDRegistry.sol/DIDRegistry.json'
import * as env from 'dotenv'
import path from 'path'

env.config({path:path.join(__dirname,'./.env')});

const abi:any = didRegistry.abi;
const rpcUrl = process.env.RPCURL;
export const defaultRegistry = process.env.REGISTRY_ADDRESS;

const caver:Caverjs = new Caverjs(rpcUrl);

export enum gas{
  deploy=5000000,
  execution=100000
}

/**
 * @notice account를 생성하여 address와 privateKey를 반환한다
 * @return object of (address, privateKey)
 */
export const createAccount = () => {
  const account = caver.klay.accounts.create();
  
  const address = account.address;
  const privateKey = account.privateKey;
  return {address, privateKey};
}

/**
 * @notice address와 privateKey로 keyring을 생성한다
 * @param address
 * @param privateKey
 * @return keyring
 */
export const makeKeyring = (address:string, privateKey:string) => {
  return caver.wallet.newKeyring(address,privateKey);
}

/**
 * @notice abi와 registry주소를 통해 contract객체를 생성한다
 * @return contract 객체
 */
export const getContract = () => {
  return caver.contract.create(abi, defaultRegistry);
}

/**
 * @notice address를 checksumaddress로 변환한다 (eip55, 주소의 무결성 검증)
 * @param address
 * @return checksumAddress
 */
export const toChecksumAddress = (address:string) => {
  return caver.utils.toChecksumAddress(address);
}

/**
 * @notice publicKey를 압축한다 (x좌표 + y좌표 => x좌표)
 * @param publicKey
 * @return 압축된 publicKey
 */
export const compressPublicKey = (publicKey:string) => {
  return caver.utils.compressPublicKey(publicKey);
}

/**
 * @notice 압축된 publickey를 decompress한다
 * @param compressedPublicKey 압축된 publicKey 
 * @returns publicKey
 */
export const decompressPublicKey = (compressedPublicKey:string) => {
  return caver.utils.decompressPublicKey(compressedPublicKey);
}

/**
 * @notice publicKey로 address를 추출한다
 * @param publicKey 
 * @returns address
 */
export const publicKeyToAddress = (publicKey:string) => {
  return caver.utils.publicKeyToAddress(publicKey);
}

/**
 * @notice provider의 chainid를 획득한다.
 * @returns chainId
 */
export const getChainId = async function(){
  return await caver.rpc.klay.getChainId();
}

/**
 * @notice keystore로 keyring을 생성한다.
 * @param keystore 
 * @param passwd keystore의 password
 * @returns keyring
 */
export const getKeyringFromKeystore = (keystore:string,passwd:string) => {
  return caver.wallet.keyring.decrypt(JSON.parse(keystore), passwd);
}

/**
 * @notice wallet에 keyring을 추가한다
 * @param keyring 
 */
export const addKeyring = (keyring:Keyring) => {
  caver.wallet.add(keyring as SingleKeyring);
}

/**
 * @notice hex값을 ascii로 변환한다
 * @param hex 변환할 hex값
 * @returns 변환한 ascii값
 */
export let hextoascii = (hex:string) =>{
  return caver.utils.hexToAscii(hex);
}

/**
 * @notice block정보를 가져온다
 * @param blockNumber 가져올 blocknumber
 * @returns object of (blocknumber, block생성시간)
 */
export const getBlock = async function(blockNumber:number){
  const block = await caver.rpc.klay.getBlock(blockNumber);
  return {
    height : block.number.toString(),
    isoDate : new Date(caver.utils.hexToNumber(block.timestamp)*1000).toISOString().replace('.000','')
  }
}

/**
 * @notice rawtransaction을 전송한다
 * @param from 
 * @param rawTx 
 * @returns 성공 여부
 */
export const sendRawTransaction = async function(from:string, rawTx:any){
  try{
    console.log("@@")
    let tx = caver.transaction.smartContractExecution.create(rawTx);

    await caver.wallet.sign(from,tx);

    await caver.rpc.klay.sendRawTransaction(tx).then(console.log);
    return true;
  }
  catch(e){
    console.log(e);
    return false;
  }
}

/**
 * @notice 메세지를 서명한다
 * @param address 
 * @param message 
 * @returns 성공 여부
 */
export const signMessage = (address:string,message:string) =>{
  return caver.wallet.signMessage(address, message, caver.wallet.keyring.role.roleTransactionKey);
}

/**
 * @notice 서명한 메세지를 검증한다
 * @param message 
 * @param signatures [v,r,s]
 * @param address 
 * @returns 성공 여부
 */
export const validateSignedMessage = async function(message:string,signatures:string[],address:string) {
  const result = await caver.validator.validateSignedMessage(message, signatures, address);
  return result;
}