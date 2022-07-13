import {getBlock, getContract, hextoascii, toChecksumAddress} from '../caver'
import { VerificationMethod, Service, ERC1056Event, DIDDelegateChanged, DIDAttributeChanged, DIDOwnerChanged,
  DIDDocument, eventNames, LegacyVerificationMethod, legacyAttrTypes, legacyAlgoMap } from './interfaces'
import {VerificationMethodTypes} from '../interfaces'
import {bytes32ToString, strip0x} from '../utils'

const NULLADDRESS = '0x0000000000000000000000000000000000000000';

class DIDResolver{
  private contract;
  constructor()
  {
    this.contract = getContract();
  }

  private async setEvents(address:string):Promise<ERC1056Event[]>{
    let allEvents:ERC1056Event[] = [];

    let previousChange = await this.contract.methods.changed(address).call();  //해당 address가 마지막으로 변경된 블록 number
    while(previousChange!=0){
      await this.contract.getPastEvents('allEvents', {  //해당 address의 변경된 블록 number로 이벤트를 가져옴
        filter: {identity:toChecksumAddress(address)},
        fromBlock: previousChange,
        toBlock: previousChange})
        .then(function(result){
          let eventCurrent = (result as any[])[0];
          let eventResult = eventCurrent.returnValues;
          previousChange = eventResult.previousChange;  //이전 이벤트 블록 number로 갱신 (0이 될때까지)

          let commonObject:ERC1056Event = {
            identity: eventResult.identity,
            previousChange: eventResult.identity,
            blockNumber: eventCurrent.blockNumber,
            _eventName: eventCurrent.event,
            validTo: eventResult.validTo,
          };
          
          switch (eventCurrent.event){
            case eventNames.DIDOwnerChanged:
            {
              let eventObject = {
                ...commonObject,
                owner: eventResult.owner
              }
              allEvents.push(eventObject);
              break;
            }
            case eventNames.DIDAttributeChanged:
            {
              let eventObject = {
                ...commonObject,
                name: eventResult.name,
                value: eventResult.value,
                validTo: eventResult.validTo
              }
              allEvents.push(eventObject);
              break;
            }
            case eventNames.DIDDelegateChanged:
            {
              let eventObject = {
                ...commonObject,
                delegateType: eventResult.delegateType,
                delegate: eventResult.delegate,
                validTo: eventResult.validTo
              }
              allEvents.push(eventObject);
              break;
            }
          }
      });
    }

    allEvents = allEvents.reverse();
    return allEvents;
  }

  private makeDIDDocument(did:string, address:string, allEvents:ERC1056Event[], chainId:number, controllerKey:string | undefined, blockHeight:string | number, now:number){
    let controller = address;

    const eventAuthentications:Record<string,string> = {};
    const eventKeyAgreementRefs: Record<string, string> = {}
    const eventPublicKeys: Record<string, VerificationMethod> = {};
    const eventServices: Record<string, Service> = {};

    let deactivated = false;
    let delegateCount = 0;
    let serviceCount = 0;

    let versionId = 0;
    let nextVersionId = Infinity;

    for(const event of allEvents){
      if (blockHeight !== -1 && event.blockNumber > blockHeight) {
        if (nextVersionId > event.blockNumber) {
          nextVersionId = event.blockNumber
        }
        continue
      } else {
        if (versionId < event.blockNumber) {
          versionId = event.blockNumber
        }
      }
      
      if(event._eventName === eventNames.DIDAttributeChanged){
        const eventCurrent = event as DIDAttributeChanged;
        const eventIndex = `${eventCurrent._eventName}-${eventCurrent.name}-${eventCurrent.value}`;
        if(event.validTo && event.validTo >= now){
          //const match = eventCurrent.name.match(/^did\/(pub|svc)\/(\w+)(\/(\w+))?(\/(\w+))?$/);
          const name = bytes32ToString(eventCurrent.name);
          const eventNameArray = name.split('/');
          const section = eventNameArray[1];
          switch(section){
            case 'svc':{                        //ex)/did/svc/DIDCommMessaging
              const type = eventNameArray[2];
              serviceCount++;
              eventServices[eventIndex] = {
              id:`${did}#service-${serviceCount}`,
              type:type,
              serviceEndpoint : hextoascii(eventCurrent.value)
              }
              break;
            }
            case 'key':{                      //ex)did/key/Secp256k1/veriKey/hex
              delegateCount++;
              const type = eventNameArray[2];
              const usg = legacyAttrTypes[eventNameArray[3]] || eventNameArray[3];
              const encoding = eventNameArray[4];

              const publicKey:LegacyVerificationMethod = {
                id:`${did}#delegate-${delegateCount}`,
                type: `${type}${usg}`,
                controller: did
              }
              publicKey.type = legacyAlgoMap[publicKey.type] || type;

              switch(encoding){
                case null:
                case undefined:
                case 'hex':
                {
                  publicKey.publicKeyHex = strip0x(eventCurrent.value);  
                  break;
                }
                case 'base64':
                  publicKey.publicKeyBase64 = Buffer.from(eventCurrent.value.slice(2), 'hex').toString('base64');
                  break
                /*case 'base58':
                  publicKey.publicKeyBase58 = Base58.encode(Buffer.from(eventCurrent.value.slice(2), 'hex'));
                  break*/
                case 'pem':
                  publicKey.publicKeyPem = Buffer.from(eventCurrent.value.slice(2), 'hex').toString();
                  break
                default:
                  publicKey.value = strip0x(eventCurrent.value);
              }

              eventPublicKeys[eventIndex] = publicKey;
              if(eventNameArray[3] === 'sigAuth'){
                eventAuthentications[eventIndex] = publicKey.id;
              }
              else if(eventNameArray[3] === 'enc'){
                eventKeyAgreementRefs[eventIndex] = publicKey.id;
              }
              break;
            }
          }
        }
        else{
          if(eventCurrent.name.match(/^did\/pub\//)){
            delegateCount++;
          }
          else if(eventCurrent.name.match(/^did\/svc\//)){
            serviceCount++;
          }
          delete eventAuthentications[eventIndex];
          delete eventPublicKeys[eventIndex];
          delete eventServices[eventIndex];
        }
      }
      else if(event._eventName === eventNames.DIDDelegateChanged){
        const eventCurrent = event as DIDDelegateChanged;
        const eventIndex = `${eventCurrent._eventName}-${eventCurrent.delegateType}-${eventCurrent.delegate}`;
        if(event.validTo && event.validTo >= now){
          delegateCount++;
          const delegateType = bytes32ToString(eventCurrent.delegateType);
          switch(delegateType){
            case 'sigAuth':{
              eventAuthentications[eventIndex] = `${did}#delegate-${delegateCount}`;
              break;
            }
            case 'veriKey':{
              eventPublicKeys[eventIndex] = {
                id:`${did}#delegate-${delegateCount}`,
                type:VerificationMethodTypes.EcdsaSecp256k1RecoveryMethod2020,
                controller:did,
                blockchainAccountId: `eip155:${chainId}:${eventCurrent.delegate}`,
              }
              break;
            }
          }
        }
        else{
          delegateCount++;
          delete eventAuthentications[eventIndex];
          delete eventPublicKeys[eventIndex];
          delete eventServices[eventIndex];
        }
      }
      else if(event._eventName === eventNames.DIDOwnerChanged){
        const eventCurrent = event as DIDOwnerChanged;
        controller = eventCurrent.owner;
        if(eventCurrent.owner === NULLADDRESS){
          deactivated = true;
          break;
        }
      }
    }

    const authentication : string[] = [`${did}#controller`];
    const keyAgreement : string[] = [];

    const publickeys: VerificationMethod[] = [
      {
        id:`${did}#controller`,
        type:VerificationMethodTypes.EcdsaSecp256k1RecoveryMethod2020,
        controller:did,
        blockchainAccountId:`eip155:${chainId}:${controller}`
      }
    ];

    if (controllerKey && controller == address) {
      publickeys.push({
        id: `${did}#controllerKey`,
        type: VerificationMethodTypes.EcdsaSecp256k1VerificationKey2019,
        controller: did,
        publicKeyHex: strip0x(controllerKey),
      })
      authentication.push(`${did}#controllerKey`);
    }

    const baseDIDDocument: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/secp256k1recovery-2020/v2'],
      id: did,
      verificationMethod: [],
      authentication: [],
      assertionMethod: [],
    }
    
    const didDocument: DIDDocument = {
      ...baseDIDDocument,
      verificationMethod: publickeys.concat(Object.values(eventPublicKeys)),
      authentication: authentication.concat(Object.values(eventAuthentications))
    }

    if(Object.values(eventServices).length > 0){
      didDocument.service = Object.values(eventServices);
    }

    if (Object.values(eventKeyAgreementRefs).length > 0) {
      didDocument.keyAgreement = keyAgreement.concat(Object.values(eventKeyAgreementRefs));
    }

    didDocument.assertionMethod = [...(didDocument.verificationMethod?.map((pk) => pk.id) || [])]

    return deactivated
      ? {
          didDocument: { ...baseDIDDocument, '@context': 'https://www.w3.org/ns/did/v1' },
          deactivated,
          versionId,
          nextVersionId,
        }
      : { didDocument, deactivated, versionId, nextVersionId }
  }

  async resolve(did:string, address:string, controllerKey: string | undefined, chainId:number){
    
    let allEvents:ERC1056Event[] = await this.setEvents(address);

    const now = Math.floor(new Date().getTime() / 1000);
    
    const {didDocument, deactivated, versionId, nextVersionId} = this.makeDIDDocument(did, address, allEvents, chainId, controllerKey, 'latest', now);

    const status = deactivated ? { deactivated: true } : {}
      let versionMeta = {}
      let versionMetaNext = {}
      if (versionId !== 0) {
        const block = await getBlock(versionId)
        versionMeta = {
          versionId: block.height,
          updated: block.isoDate,
        }
      }
      if (nextVersionId !== Number.POSITIVE_INFINITY) {
        const block = await getBlock(nextVersionId)
        versionMetaNext = {
          nextVersionId: block.height,
          nextUpdate: block.isoDate,
        }
      }

      return {
        didDocumentMetadata: { ...status, ...versionMeta, ...versionMetaNext },
        didResolutionMetadata: { contentType: 'application/did+ld+json' },
        didDocument,
      }
  }
};

export default DIDResolver;