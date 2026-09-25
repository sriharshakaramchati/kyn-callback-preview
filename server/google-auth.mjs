import { createHmac } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { SafeError } from './constants.mjs';
const googleKeys = createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'), {timeoutDuration:10000});
export const GOOGLE_CLIENT_ID = '314143985831-er2khu6v2s37ffflim4skrohtms9ha2i.apps.googleusercontent.com';
export function googleAuthenticator({clientId=GOOGLE_CLIENT_ID, ownerSecret, keySet=googleKeys}) {
  return async ({credential, nonce}) => {
    try {
      if (typeof credential !== 'string' || credential.length > 12000 || typeof nonce !== 'string' || !/^[a-f0-9]{64}$/.test(nonce)) throw new Error();
      const {payload} = await jwtVerify(credential, keySet, {algorithms:['RS256'], audience:clientId, issuer:['https://accounts.google.com','accounts.google.com'], requiredClaims:['sub','exp','iat','email','email_verified','nonce'], maxTokenAge:'1 hour',clockTolerance:10});
      if (payload.nonce !== nonce || payload.email_verified !== true || typeof payload.sub !== 'string' || !payload.sub || typeof payload.email !== 'string' || (payload.azp && payload.azp !== clientId)) throw new Error();
      // Distinct domains for the opaque account identifier and the server's half of the unlock secret.
      // This half cannot decrypt a map without the independent random seed kept only on its device.
      const derive = purpose => createHmac('sha256',ownerSecret).update(JSON.stringify([purpose,clientId,payload.sub])).digest('base64url');
      return {id:'google:'+derive('kyn-account:v1'),name:typeof payload.name==='string'?payload.name.slice(0,160):payload.email.split('@')[0],email:payload.email,unlockPart:derive('kyn-unlock:v1')};
    } catch { throw new SafeError(401,'GOOGLE_SIGN_IN_FAILED'); }
  };
}
