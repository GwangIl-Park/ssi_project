import {VerificationMethodTypes} from '../interfaces'

/**
 * @descryption : veramo
 */
export interface VerificationMethod {
  id: string
  type: string
  controller: string
  publicKeyBase58?: string
  publicKeyBase64?: string
  publicKeyJwk?: JsonWebKey
  publicKeyHex?: string
  publicKeyMultibase?: string
  blockchainAccountId?: string
  ethereumAddress?: string
}

/*export interface VerificationMethod{
  id:string;
  type:VerificationMethodTypes | string;
  controller:string;
  publicKeyJwk?:Object;
  publicKeyBase58?:Object;

  publicKeyMultibase?:Object; //비표준
  blockchainAccountId?:string;
  
   * @deprecated
   * ethereumAddress
   
};*/

export interface LegacyVerificationMethod extends VerificationMethod {
  /**@deprecated */
  publicKeyHex?: string
  /**@deprecated */
  publicKeyBase64?: string
  /**@deprecated */
  publicKeyPem?: string
  [x: string]:any;
}

export enum Representations{
  JSON='application/did+json',
  JSONLD='application/did+ld+json',
  CBOR='application/did+cbor'
}

export interface Service{
  id:string;
  type:string;
  serviceEndpoint:string;
};

export type KeyCapabilitySection =
    | 'authentication'
    | 'assertionMethod'
    | 'keyAgreement'
    | 'capabilityInvocation'
    | 'capabilityDelegation'

export type DIDDocument = {
  '@context'?: 'https://www.w3.org/ns/did/v1' | string | string[]
  id: string
  alsoKnownAs?: string[]
  controller?: string | string[]
  verificationMethod?: VerificationMethod[]
  //service?: ServiceEndpoint[]
  service?: any[]
  //publicKey?: VerificationMethod[]
} & {
  [x in KeyCapabilitySection]?: (string | VerificationMethod)[]
}

/*export interface DIDDocument{
  '@context':string[];
  id:string;
  alsoKnownAs?:string[];
  
  // * @description : 존재한다면 VerificationRelationships 필요
   
  controller?:string | string[];
  verificationMethod?:VerificationMethod[];
  
  // * @deprecated : VerificationMethod로 대체
  
  publicKey?:VerificationMethod[];

  assertionMethod?:VerificationMethod[] | string[];
  
  // * @description : VerificationRelationships : VerificationMethod와 DIDSubject의 관계
  
  authentication?:VerificationMethod[] | string[];
  capabilityDelegation?:VerificationMethod[];
  capabilityInvocation?:VerificationMethod[];
  keyAgreement?:VerificationMethod[] | string[];
  service?:Service[];
};*/

export enum eventNames {
  DIDOwnerChanged = 'DIDOwnerChanged',
  DIDAttributeChanged = 'DIDAttributeChanged',
  DIDDelegateChanged = 'DIDDelegateChanged',
}

export interface ERC1056Event {
  identity: string
  previousChange: number
  validTo?: number
  _eventName: string
  blockNumber: number
}

export interface DIDOwnerChanged extends ERC1056Event {
  owner: string
}

export interface DIDAttributeChanged extends ERC1056Event {
  name: string
  value: string
  validTo: number
}

export interface DIDDelegateChanged extends ERC1056Event {
  delegateType: string
  delegate: string
  validTo: number
}

export const legacyAttrTypes: Record<string, string> = {
  sigAuth: 'SignatureAuthentication2018',
  veriKey: 'VerificationKey2018',
  enc: 'KeyAgreementKey2019',
}

export const legacyAlgoMap: Record<string, string> = {
  /**@deprecated */
  Secp256k1VerificationKey2018: VerificationMethodTypes.EcdsaSecp256k1VerificationKey2019,
  /**@deprecated */
  Ed25519SignatureAuthentication2018: VerificationMethodTypes.Ed25519VerificationKey2018,
  /**@deprecated */
  Secp256k1SignatureAuthentication2018: VerificationMethodTypes.EcdsaSecp256k1VerificationKey2019,
  //keep legacy mapping
  RSAVerificationKey2018: VerificationMethodTypes.RSAVerificationKey2018,
  Ed25519VerificationKey2018: VerificationMethodTypes.Ed25519VerificationKey2018,
  X25519KeyAgreementKey2019: VerificationMethodTypes.X25519KeyAgreementKey2019,
}