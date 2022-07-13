mkdir ./dist/esm
cat >dist/esm/index.js <<!EOF
import cjsModule from '../index.js';
export const IdDecoder = cjsModule.IdDecoder;
export const IdGenerator = cjsModule.IdGenerator;
export const IdEncoder = cjsModule.IdEncoder;
export const generateId = cjsModule.generateId;
export const decodeId = cjsModule.decodeId;
export const minEncodedIdBytes = cjsModule.minEncodedIdBytes;
export const maxEncodedIdBytes = cjsModule.maxEncodedIdBytes;
export const generateSecretKeySeed = cjsModule.generateSecretKeySeed;
export const decodeSecretKeySeed = cjsModule.decodeSecretKeySeed;
!EOF

cat >dist/esm/package.json <<!EOF
{
  "type": "module"
}
!EOF
