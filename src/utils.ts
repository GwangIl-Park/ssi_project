import { decompressPublicKey, publicKeyToAddress, getKeyringFromKeystore } from "./caver"
import fs from 'fs';

export const strip0x = (input: string) => {
  return input.startsWith('0x') ? input.slice(2) : input
}

export const getDIDSpecificIdentifier = (did:string) => {
  let prefix = 'did:klay:'
  return did.substring(prefix.length);
}

export const publicKeyFromDID = (did:string) => {
  const didSpecificIdentifier = getDIDSpecificIdentifier(did);
  const publicKey = decompressPublicKey(didSpecificIdentifier);

  return publicKey;
}

export const getKeyringFromDID = (did:string, passwd:string) => {
  const publicKey = publicKeyFromDID(did);

  const address = publicKeyToAddress(publicKey);

  const keystorePath = `${process.env.KEYSTORE_PATH}${address}.txt`;

  const keystore = fs.readFileSync(keystorePath).toString();

  return getKeyringFromKeystore(keystore, passwd);
}

export const stringToBytes32 = (str: string) => {
  const buffStr = '0x' + Buffer.from(str).slice(0, 32).toString('hex')
  return buffStr + '0'.repeat(66 - buffStr.length)
}

export const stringToBytes = (str:string) => {
  return str.startsWith('0x') ? str : '0x' + Buffer.from(str, 'utf-8').toString('hex')
}

export const bytes32ToString = (str: string) => {
  str = strip0x(str);
  return Buffer.from(str.substring(0, str.indexOf('00')), 'hex').toString('utf-8');
}