import inquirer from 'inquirer';
import {didManager, credential, presentation} from './common'

async function procCreateDID(){
  const answer = await inquirer.prompt([{
    type:'input',
    name:'passwd'
  }]);
  const did = didManager.create(answer.passwd);
  console.log(did)
}

async function procListDID(){
  console.log(didManager.list());
}

async function procDeleteDID(){
  const dids = didManager.list();
  const answer = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'did',
    choices:dids,
    message:'삭제할 DID를 선택하세요'
  }]);
  didManager.delete(answer.did);
}

async function procAddDelegate(){
  const dids = didManager.list();
  const answerSubject = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'subjectDID',
    choices:dids,
    message:'subject DID를 선택하세요'
  }]);
  const answerPasswd = await inquirer.prompt([{
    type:'input',
    name:'passwd'
  }]);
  const answerFrom = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'fromDID',
    choices:dids,
    message:'from DID를 선택하세요'
  }]);
  const answerType = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'type',
    choices:[
      'sigAuth',
      'veriKey'
    ],
    message:'type을 선택하세요'
  }]);
  const answerSecond = await inquirer.prompt([{
    type:'input',
    name:'expireSecond',
    default:86400
  }]);
  didManager.addDelegate(answerSubject.subjectDID, answerPasswd.passwd, answerFrom.fromDID, answerType.type, answerSecond.expireSecond);
}

async function procChangeOwner(){
  const dids = didManager.list();
  const answerSubject = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'subjectDID',
    choices:dids,
    message:'subject DID를 선택하세요'
  }]);
  const answerPasswd = await inquirer.prompt([{
    type:'input',
    name:'passwd'
  }]);
  const answerOwner = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'ownerDID',
    choices:dids,
    message:'owner DID를 선택하세요'
  }]);
  didManager.changeOwner(answerSubject.subjectDID, answerPasswd.passwd, answerOwner.ownerDID);
}

async function procAddKey(){
  const dids = didManager.list();
  const answerDID = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'did',
    choices:dids,
    message:'DID를 선택하세요'
  }]);
  const answerPasswd = await inquirer.prompt([{
    type:'input',
    name:'passwd'
  }]);
  const answerNewPasswd = await inquirer.prompt([{
    type:'input',
    name:'newPasswd'
  }]);
  const answerType = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'type',
    choices:['veriKey',
            'sigAuth',
              'enc'],
    message:'타입을 선택하세요'
  }]);
  const answerSecond = await inquirer.prompt([{
    type:'input',
    name:'expireSecond',
    default:86400
  }]);
  didManager.addKey(answerDID.did, answerPasswd.passwd, answerNewPasswd.newPasswd, answerType.type, answerSecond.expireSecond);
}

async function procAddService(){
  const dids = didManager.list();
  const answerDID = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'did',
    choices:dids,
    message:'DID를 선택하세요'
  }]);
  const answerPasswd = await inquirer.prompt([{
    type:'input',
    name:'passwd'
  }]);
  const answerType = await inquirer.prompt([{
    type:'input',
    name:'type',
    default:'DIDCommMessaging'
  }]);
  if(answerType.type === ''){
    throw new Error('type을 입력해야 합니다.')
  }
  const answerEndpoint = await inquirer.prompt([{
    type:'input',
    name:'endpoint'
  }]);
  if(answerEndpoint.endpoint === ''){
    throw new Error('endpoint를 입력해야 합니다.')
  }
  const answerSecond = await inquirer.prompt([{
    type:'input',
    name:'expireSecond',
    default:86400
  }]);
  didManager.addService(answerDID.did, answerPasswd.passwd, answerType.type, answerEndpoint.endpoint, answerSecond.expireSecond);
}

async function procResolve(){
  const dids = didManager.list();
  const answerDID = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'did',
    choices:dids,
    message:'DID를 선택하세요'
  }]);
  const did = 'did:klay:0x0326dc31f57014f699387510e8fe61ab4c40c37a81daa038dbd718ef1dc91238dd'
  const didDocument = await didManager.resolve(did);
  console.log(JSON.stringify(didDocument,null,2));
}

async function procCreateVC(){
  const dids = didManager.list();
  const answerIssuer = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'issuerDID',
    choices:dids,
    message:'issuer DID를 선택하세요'
  }]);
  const answerPasswd = await inquirer.prompt([{
    type:'input',
    name:'passwd'
  }]);
  const answerSubject = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'subjectDID',
    choices:dids,
    message:'subject DID를 선택하세요'
  }]);
  const answerType = await inquirer.prompt([{
    type:'input',
    name:'type',
    default:'VerifiableCredential,Profile'
  }]);
  const answerClaimType = await inquirer.prompt([{
    type:'input',
    name:'claimType',
    default:'name'
  }]);
  const answerclaimValue = await inquirer.prompt([{
    type:'input',
    name:'claimValue',
    default:'alice'
  }]);
  /*const answerProof = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'proof',
    choices:[
      'jwt','lds'
    ],
    message:'proof format을 선택하세요'
  }]);
  const answerAlgorithm = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'algorithm',
    choices:[
      'ES256K','ES256K-R','klay_signMessage'
    ],
    message:'암호화 algorithm을 선택하세요'
  }]);*/
  await credential.createCredential(answerIssuer.issuerDID, answerPasswd.passwd, answerSubject.subjectDID, answerType.type, answerClaimType.claimType, answerclaimValue.claimValue, '', '');
}

async function procVerifyVC(){
  const vcs = credential.list();
  const answerVC = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'VC',
    choices:vcs,
    message:'검증할 VC를 선택하세요'
  }]);
  await credential.verifyCredential(answerVC.VC);
}

async function procCreateVP(){
  const dids = didManager.list();
  const vcs = credential.list();
  const answerHolder = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'holder',
    choices:dids,
    message:'holder를 선택하세요'
  }]);
  const answerPasswd = await inquirer.prompt([{
    type:'input',
    name:'passwd',
  }]);
  const answerVerifier = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'verifier',
    choices:dids,
    message:'verifier를 선택하세요'
  }]);
  const answerTag = await inquirer.prompt([{
    type:'input',
    name:'tag',
    default:'xyz123'
  }]);
  const answerType = await inquirer.prompt([{
    type:'input',
    name:'type',
    default:'VerifiablePresentation,Profile'
  }]);
  const answerVCs = await inquirer.prompt([{
    type:'checkbox',
    pageSize:64,
    name:'vcs',
    choices:vcs,
    message:'holder를 선택하세요'
  }]);
  await presentation.createPresentation(answerHolder.holder, answerPasswd.passwd, answerVerifier.verifier, answerTag.tag, answerType.type, answerVCs.vcs)
}

async function procVerifyVP(){
  const vcs = credential.list();
  const answerVC = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'VC',
    choices:vcs,
    message:'검증할 VC를 선택하세요'
  }]);
  await credential.verifyCredential(answerVC.VC);
}

async function runProc(){
  const answer = await inquirer.prompt([{
    type:'list',
    pageSize:64,
    name:'menu',
    choices:[
      'CreateDID',
      'ListDID',
      'DeleteDID',
      'AddDelegate',
      'ChangeOwner',
      'Add-Key',
      'Add-Service',
      'Resolve',
      'CreateVC',
      'VerifyVC',
      'CreateVP',
      'VerifyVP'
    ],
    message:'메뉴를 선택하세요'
  }]);
  switch(answer.menu){
    case 'CreateDID':{
      procCreateDID();
      break;
    }
    case 'ListDID':{
      procListDID();
      break;
    }
    case 'DeleteDID':{
      procDeleteDID();
      break;
    }
    case 'AddDelegate':{
      procAddDelegate();
      break;
    }
    case 'ChangeOwner':{
      procChangeOwner();
      break;
    }
    case 'Add-Key':{
      procAddKey();
      break;
    }
    case 'Add-Service':{
      procAddService();
      break;
    }
    case 'Resolve':{
      procResolve();
      break;
    }
    case 'CreateVC':{
      procCreateVC();
      break;
    }
    case 'VerifyVC':{
      procVerifyVC();
      break;
    }
    case 'CreateVP':{
      procCreateVP();
      break;
    }
    case 'VerifyVP':{
      procVerifyVP();
      break;
    }
  }
}

runProc();