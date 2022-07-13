export enum VerificationMethodTypes{
  JsonWebKey2020='JsonWebKey2020',
  EcdsaSecp256k1VerificationKey2019='EcdsaSecp256k1VerificationKey2019',
  Ed25519VerificationKey2018='Ed25519VerificationKey2018',
  Bls12381G1Key2020='Bls12381G1Key2020',
  Bls12381G2Key2020='Bls12381G2Key2020',
  PgpVerificationKey2021='PgpVerificationKey2021',

  RSAVerificationKey2018='RSAVerificationKey2018',
  X25519KeyAgreementKey2019='X25519KeyAgreementKey2019',
   
   EcdsaSecp256k1RecoveryMethod2020='EcdsaSecp256k1RecoveryMethod2020',
   VerifiableCondition2021='VerifiableCondition2021',
};

export interface Issuer{
  id:string
}

export interface CredentialSubject{
  id:string;
  [type:string]:any;
}

export interface CredentialStatus{
  id:string;
  type:string;
  [x:string]:any;
}

export interface CredentialPayload {
  issuer: Issuer;
  credentialSubject?: CredentialSubject;
  type?: string[];
  '@context'?: string[];
  issuanceDate?: string;
  expirationDate?: string;
  credentialStatus?: CredentialStatus
  id?: string

  [x: string]: any
}

export interface CredentialProof{
  [x:string]:string;
}

export interface VerifiableCredential extends CredentialPayload{
  proof:CredentialProof;
}