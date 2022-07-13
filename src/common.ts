import DIDManager from './did'
import Credential from './credential';
import Presentation from './presentation';
import { Suite } from './signer';
import { extendContextLoader } from '@digitalcredentials/jsonld-signatures'
import { LdDefaultContexts } from "./contexts";
import * as vc from '@digitalcredentials/vc'

export const didManager:DIDManager = new DIDManager();
export const credential:Credential = new Credential();
export const presentation:Presentation = new Presentation();
export const suite:Suite = new Suite();

export const getDocumentLoader = () => {
  return extendContextLoader(async (url:string) => {
    const error = new Error();
    
    if(url.toLowerCase().startsWith('did:')){
    const resolutionResult = await didManager.resolve(url);
    const didDoc = resolutionResult.didDocument;

    return {
      contextUrl:null,
      documentUrl:url,
      document:didDoc
    }
  }

  if(LdDefaultContexts.has(url)){
    const contextDoc = LdDefaultContexts.get(url);
    return {
      contextUrl: null,
      documentUrl: url,
      document: contextDoc,
    }
  } /*else {
    if (attemptToFetchContexts) {
      // attempt to fetch the remote context!!!! MEGA FAIL for JSON-LD.
      debug('WARNING: attempting to fetch the doc directly for ', url)
      try {
        const response = await fetch(url)
        if (response.status === 200) {
          const document = await response.json()
          return {
            contextUrl: null,
            documentUrl: url,
            document,
          }
        }
      } catch (e) {
        debug('WARNING: unable to fetch the doc or interpret it as JSON', e)
      }
    }
  }

  debug(
    `WARNING: Possible unknown context/identifier for ${url} \n falling back to default documentLoader`,
  )*/
  return vc.defaultDocumentLoader(url)
  })
}