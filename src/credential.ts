import { addKeyring, getKeyringFromKeystore, publicKeyToAddress, signMessage, toChecksumAddress, validateSignedMessage } from "./caver";
import { publicKeyFromDID } from "./utils";
import fs from 'fs';
import * as json5 from 'json5'
import { SingleKeyring } from "caver-js";
import { didManager,getDocumentLoader,suite } from "./common";
import * as vc from '@digitalcredentials/vc'
import {getKeyringFromDID} from './utils'
import { Issuer, CredentialSubject, CredentialStatus, CredentialPayload, CredentialProof, VerifiableCredential} from './interfaces'

class Credential{
  private async procLDSignature(credential:CredentialPayload, issuerPasswd:string){
    const documentLoader = getDocumentLoader();

    const issuerDocument = await didManager.resolve(credential.issuer.id);
    const keyring = getKeyringFromDID(credential.issuer.id, issuerPasswd);
    const issuerAddress = toChecksumAddress(keyring.address);
    const verificationMethodArray = issuerDocument.didDocument.verificationMethod;

    const verificationMethodId = verificationMethodArray!.filter(object => issuerAddress === object.blockchainAccountId?.substring("eip155:1000:".length));

    const verifiableCredential = await vc.issue({
      credential,
      suite:suite.getSuiteForSigning(keyring as SingleKeyring,credential.issuer.id, verificationMethodId![0].id),
      documentLoader,
      compactProof:false})

    return verifiableCredential;
  }

  /*private procKlaySignMessage(credential:CredentialPayload, issuerPasswd:string){
    const header = {
      alg: 'klay_signMessage'
    }

    const keyring = getKeyringFromDID(credential.issuer.id, issuerPasswd);

    addKeyring(keyring);

    const result = signMessage(keyring.address, json5.stringify(credential));

    const signature = result.signatures[0];

    const verifiableCredential:VerifiableCredential = {
      ...credential,
      proof:{
        v:signature.v,
        r:signature.r,
        s:signature.s
      }
    }

    console.log(verifiableCredential);
  }*/

  list(){
    const vcs:string[] = [];
    fs.readdirSync('./VCs/').forEach(file => {
      vcs.push(file);
    })
    return vcs;
  }

  async createCredential(issuer:string,issuerPasswd:string, subject:string,type:string,claimType:string,claimValue:string,proofFormat:string,algorithm:string){
    const credentialSubject:any={};
    credentialSubject.id = subject;
    credentialSubject[claimType] = claimValue;

    const issuanceDate = new Date().toISOString();
    const credential: CredentialPayload = {
      issuer: { id: issuer },
      '@context': ['https://www.w3.org/2018/credentials/v1', 'https://veramo.io/contexts/profile/v1'],
      type: type.split(','),
      issuanceDate,
      credentialSubject,
    }
    
    const vc = await this.procLDSignature(credential, issuerPasswd);

    fs.writeFileSync(`./VCs/${subject}_${issuer}_${claimType}_${issuanceDate}.txt`,json5.stringify(vc));
  }

  async verifyCredential(credentialFile:string){
    const credential = json5.parse(fs.readFileSync(`./VCs/${credentialFile}`,'utf-8'));

    const documentLoader = getDocumentLoader();

    const result = await vc.verifyCredential({
      credential,
      suite:suite.getSuiteForVerification(),
      documentLoader,
      compactProof:false,
      checkStatus:void 0,
    })
    console.log(result)
  }

  /*async verifyCredential(credentialFile:string){

    const credential = fs.readFileSync(credentialFile).toString();

    const credentialJSON = json5.parse(credential);

    const issuerDID = credentialJSON.issuer.id;

    const issuerAddress = publicKeyToAddress(issuerPublicKey);

    const proof = credentialJSON.proof;

    delete credentialJSON.proof;

    const result = await validateSignedMessage(json5.stringify(credentialJSON),Object.values(proof),issuerAddress);

    console.log(result)
  }*/
}

export default Credential;