import * as u8a from 'uint8arrays'
import { ES256KSigner } from 'did-jwt'
import { arrayify, hexlify } from '@ethersproject/bytes'
import { SingleKeyring } from 'caver-js'
import {
  EcdsaSecp256k1RecoveryMethod2020,
  EcdsaSecp256k1RecoverySignature2020,
} from '@transmute/lds-ecdsa-secp256k1-recovery2020'


class Signer{
  private async signES256K(
    privateKeyHex: string,
    alg: string | undefined,
    data: Uint8Array,
  ): Promise<string> {
    const signer = ES256KSigner(arrayify(privateKeyHex, { allowMissingPrefix: true }), alg === 'ES256K-R')
    const signature = await signer(data)

    // base64url encoded string
    return signature as string
  }

  async sign(keyring:SingleKeyring,type:string,algorithm: string,encoding:string,data: string): Promise<string> {
    let dataBytes
    if (typeof data === 'string') {
      if (encoding === 'base16' || encoding === 'hex') {
        const preData = data.startsWith('0x') ? data.substring(2) : data
        dataBytes = u8a.fromString(preData, 'base16')
      } else {
        dataBytes = u8a.fromString(data, <'utf-8'>encoding)
      }
    } else {
      dataBytes = data
    }

    if (type === 'Ed25519' && (typeof algorithm === 'undefined' || ['Ed25519', 'EdDSA'].includes(algorithm))) {
      //return await this.signEdDSA(keyring.key.privateKey, data)
    } else if (type === 'Secp256k1') {
      if (typeof algorithm === 'undefined' || ['ES256K', 'ES256K-R'].includes(algorithm)) {
        return await this.signES256K(keyring.key.privateKey, algorithm, dataBytes)
      } else if (['eth_signTransaction', 'signTransaction', 'signTx'].includes(algorithm)) {
        //return await this.eth_signTransaction(keyring.key.privateKey, data)
      } else if (algorithm === 'eth_signMessage') {
        //return await this.eth_signMessage(keyring.key.privateKey, data)
      } else if (['eth_signTypedData', 'EthereumEip712Signature2021'].includes(algorithm)) {
        //return await this.eth_signTypedData(keyring.key.privateKey, data)
      }
    }
    throw Error(`not_supported: Cannot sign ${algorithm} using key of type ${type}`)
  }
}

const mySigner:Signer = new Signer();

export class Suite {
  getSupportedVerificationType(): string {
    return 'EcdsaSecp256k1RecoveryMethod2020'
  }

  getSupportedVeramoKeyType(): string {
    return 'Secp256k1'
  }

  getSuiteForSigning(
    keyring: SingleKeyring,
    did: string,
    verifiableMethodId: string
  ): any {
    const controller = did
    const signer = {
      //returns a JWS detached
      sign: async (args: { data: Uint8Array }): Promise<string> => {
        const header = {
          alg: 'ES256K-R',
          b64: false,
          crit: ['b64'],
        }
        const headerString = u8a.toString(u8a.fromString(JSON.stringify(header), 'utf-8'), 'base64url')
        const messageBuffer = u8a.concat([u8a.fromString(`${headerString}.`, 'utf-8'), args.data])
        const messageString = u8a.toString(messageBuffer, 'base64')
        const signature = await mySigner.sign(keyring,'Secp256k1','ES256K-R','base64',messageString)
        return `${headerString}..${signature}`
      },
    }

    const suite = new EcdsaSecp256k1RecoverySignature2020({
      // signer,
      key: new EcdsaSecp256k1RecoveryMethod2020({
        publicKeyHex: keyring.getPublicKey(),
        signer: () => signer,
        type: this.getSupportedVerificationType(),
        controller,
        id: verifiableMethodId,
      }),
    })

    suite.ensureSuiteContext = ({ document }: { document: any, addSuiteContext: boolean }) => {
      document['@context'] = [...document['@context'], this.getContext()]
    }

    return suite
  }

  getSuiteForVerification(): any {
    return new EcdsaSecp256k1RecoverySignature2020()
  }

  preSigningCredModification(credential: any): void {
  }

  /*preDidResolutionModification(didUrl: string, didDoc: DIDDocument): void {
//    did:ethr
    const idx = didDoc['@context']?.indexOf('https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld') || -1
    if (Array.isArray(didDoc['@context']) && idx !== -1) {
      didDoc['@context'][idx] = this.getContext()
    }

    if (didUrl.toLowerCase().startsWith('did:ethr')) {
      //EcdsaSecp256k1RecoveryMethod2020 does not support older format blockchainAccountId
      didDoc.verificationMethod?.forEach((x) => {
        if (x.blockchainAccountId) {
          if (x.blockchainAccountId.lastIndexOf('@eip155:') !== -1) {
            const [ address, chain ] = x.blockchainAccountId.split("@eip155:")
            x.blockchainAccountId = `eip155:${chain}:${address}`
          }
        }
      })
    }
  }*/
  getContext(): string {
    return 'https://w3id.org/security/suites/secp256k1recovery-2020/v2'
  }
}