import * as vc from '@digitalcredentials/vc'
import { didManager,suite, getDocumentLoader } from './common';
import {getKeyringFromDID} from './utils'
import {toChecksumAddress} from './caver'
import { SingleKeyring } from 'caver-js';

class Presentation
{
  async createPresentation(holder:string, holderPasswd:string, verifier:string, tag:string, type:string, vcs:string[]){
    const verifiableCredentials:string[] = [];
    vcs.forEach((vc) =>{
      verifiableCredentials.push(vc)
    });
    const presentation = {
      holder,
      verifier,
      //tag,
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type:type.split(','),
      //issuanceDate:new Date().toISOString(),
      verifiableCredential:verifiableCredentials
    }

    suite.preSigningCredModification(presentation);

    const holderDocument = await didManager.resolve(holder);
    const keyring = getKeyringFromDID(holder, holderPasswd);
    const holderAddress = toChecksumAddress(keyring.address);
    const verificationMethodArray = holderDocument.didDocument.verificationMethod;

    const verificationMethodId = verificationMethodArray!.filter(object => holderAddress === object.blockchainAccountId?.substring("eip155:1000:".length));

    const documentLoader = getDocumentLoader();

    return await vc.signPresentation({
      presentation,
      suite:suite.getSuiteForSigning(keyring as SingleKeyring, holder, verificationMethodId![0].id),
      challenge:'',
      domain:undefined,
      documentLoader,
      compactProof:false
    })
  }
  async verifyPresentation(){

  }
}

export default Presentation;