import { RSABlindSignProducer, RSABlindSigner } from './index';
import { i2osp, mockableFn, os2ip } from './util';

import { jest } from '@jest/globals';
import sjcl from './sjcl';
// Test vector
// https://www.ietf.org/archive/id/draft-irtf-cfrg-rsa-blind-signatures-03.html#appendix-A
import vectors from './testdata/rsablind_vectors.json';

function hexToB64URL(x: string): string {
    return Buffer.from(x, 'hex').toString('base64url');
}

function hexToUint8(x: string): Uint8Array {
    return new Uint8Array(Buffer.from(x, 'hex'));
}

function hexToBn(x: string): sjcl.bn {
    return os2ip(new Uint8Array(Buffer.from(x, 'hex')));
}

function bnToB64URL(x: sjcl.bn): string {
    return Buffer.from(i2osp(x, Math.ceil(x.bitLength() / 8))).toString('base64url');
}

function paramsFromVector(v: typeof vectors[number]): {
    n: string;
    e: string;
    d: string;
    p: string;
    q: string;
    dp: string;
    dq: string;
    qi: string;
} {
    const n = hexToB64URL(v.n);
    const e = hexToB64URL(v.e);
    const d = hexToB64URL(v.d);
    const p = hexToB64URL(v.p);
    const q = hexToB64URL(v.q);

    // Calculate CRT values
    const bnD = hexToBn(v.d);
    const bnP = hexToBn(v.p);
    const bnQ = hexToBn(v.q);
    const one = new sjcl.bn(1);
    const dp = bnToB64URL(bnD.mod(bnP.sub(one)));
    const dq = bnToB64URL(bnD.mod(bnQ.sub(one)));
    const qi = bnToB64URL(bnQ.inverseMod(bnP));
    return { n, e, d, p, q, dp, dq, qi };
}

async function keysFromVector(v: typeof vectors[number]): Promise<CryptoKeyPair> {
    const params = paramsFromVector(v);
    const { n, e } = params;
    const publicKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', ext: true, n, e },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['verify'],
    );

    const privateKey = await crypto.subtle.importKey(
        'jwk',
        { kty: 'RSA', ext: true, ...params },
        { name: 'RSA-PSS', hash: 'SHA-384' },
        true,
        ['sign'],
    );
    return { privateKey, publicKey };
}

describe('BlindRSA', () => {
    test.each(vectors)('vec$#', async (v: typeof vectors[number]) => {
        jest.spyOn(mockableFn, 'getRandomSalt').mockReturnValueOnce(hexToUint8(v.salt));
        jest.spyOn(RSABlindSignProducer.prototype, 'genRandomBlind').mockImplementationOnce(
            (n: sjcl.bn): sjcl.bn => {
                const r_inv = hexToBn(v.inv);
                const r = r_inv.inverseMod(n);
                return r;
            },
        );
        const keys = await keysFromVector(v);
        const msg = hexToUint8(v.msg);
        const saltLength = v.salt.length / 2;

        const alice = new RSABlindSignProducer(keys.publicKey);
        const { blinded_msg, inv } = await alice.blind(msg, saltLength);
        expect(blinded_msg).toStrictEqual(hexToUint8(v.blinded_msg));
        expect(inv).toStrictEqual(hexToUint8(v.inv));

        const bob = new RSABlindSigner(keys.privateKey);
        const blind_sig = await bob.sign(blinded_msg);
        expect(blind_sig).toStrictEqual(hexToUint8(v.blind_sig));

        const signature = await alice.finalize(msg, inv, blind_sig, saltLength);
        expect(signature).toStrictEqual(hexToUint8(v.sig));
    });
});
