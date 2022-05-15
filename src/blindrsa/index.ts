import { emsa_pss_encode, i2osp, os2ip, rsasp1, rsavp1 } from './util';

import sjcl from './sjcl';

export class RSABlindSignProducer {
    private kBits: number;
    private kLen: number;
    private hash: string;
    constructor(public publicKey: CryptoKey) {
        if (publicKey.type !== 'public' || publicKey.algorithm.name !== 'RSA-PSS') {
            throw new Error('key is not rsa-pss');
        }
        const { modulusLength, hash: hashFn } = publicKey.algorithm as RsaHashedKeyGenParams;
        this.kBits = modulusLength;
        this.kLen = Math.ceil(this.kBits / 8);
        this.hash = (hashFn as Algorithm).name;
    }

    genRandomBlind(n: sjcl.bn): sjcl.bn {
        let blind: sjcl.bn;
        do {
            blind = os2ip(crypto.getRandomValues(new Uint8Array(this.kLen)));
        } while (blind.greaterEquals(n));
        return blind;
    }

    async blind(
        msg: Uint8Array,
        saltLength: number,
    ): Promise<{
        blinded_msg: Uint8Array;
        inv: Uint8Array;
    }> {
        // 1. encoded_msg = EMSA-PSS-ENCODE(msg, kBits - 1)
        //    with MGF and HF as defined in the parameters
        // 2. If EMSA-PSS-ENCODE raises an error, raise the error and stop
        const encoded_msg = await emsa_pss_encode(msg, this.kBits - 1, {
            hash: this.hash,
            sLen: saltLength,
        });

        // 3. m = bytes_to_int(encoded_msg)
        const m = os2ip(encoded_msg);
        const jwkKey = await crypto.subtle.exportKey('jwk', this.publicKey);
        if ((jwkKey.kty && jwkKey.kty != 'RSA') || !jwkKey.n || !jwkKey.e) {
            throw new Error('key is not rsa-pss');
        }
        const n = new sjcl.bn(Buffer.from(jwkKey.n, 'base64url').toString('hex'));
        const e = new sjcl.bn(Buffer.from(jwkKey.e, 'base64url').toString('hex'));

        // 4. r = random_integer_uniform(1, n)
        const r = this.genRandomBlind(n);

        // 5. r_inv = inverse_mod(r, n)
        // 6. If inverse_mod fails, raise an "invalid blind" error
        //    and stop
        const r_inv = r.inverseMod(n);

        // 7. x = RSAVP1(pkS, r)
        const x = rsavp1({ n, e }, r);

        // 8. z = m * x mod n
        const z = m.mulmod(x, n);

        // 9. blinded_msg = int_to_bytes(z, kLen)
        const blinded_msg = i2osp(z, this.kLen);

        // 10. inv = int_to_bytes(r_inv, kLen)
        const inv = i2osp(r_inv, this.kLen);

        // 11. output blinded_msg, inv
        return { blinded_msg, inv };
    }

    async finalize(
        msg: Uint8Array,
        inv: Uint8Array,
        blind_sig: Uint8Array,
        saltLength: number,
    ): Promise<Uint8Array> {
        // 1. If len(blind_sig) != kLen, raise "unexpected input size" and stop
        // 2. If len(inv) != kLen, raise "unexpected input size" and stop
        if (blind_sig.length != this.kLen || inv.length != this.kLen) {
            throw new Error('unexpected input size');
        }
        // 3. z = bytes_to_int(blind_sig)
        const z = os2ip(blind_sig);
        // 4. r_inv = bytes_to_int(inv)
        const r_inv = os2ip(inv);
        // 5. s = z * r_inv mod n
        const jwkKey = await crypto.subtle.exportKey('jwk', this.publicKey);
        if ((jwkKey.kty && jwkKey.kty != 'RSA') || !jwkKey.n || !jwkKey.e) {
            throw new Error('key is not rsa-pss');
        }
        const n = new sjcl.bn(Buffer.from(jwkKey.n, 'base64url').toString('hex'));
        const s = z.mulmod(r_inv, n);
        // 6. sig = int_to_bytes(s, kLen)
        const sig = i2osp(s, this.kLen);
        // 7. result = RSASSA-PSS-VERIFY(pkS, msg, sig)
        // 8. If result = "valid signature", output sig, else
        //    raise "invalid signature" and stop
        if (
            !(await crypto.subtle.verify({ name: 'RSA-PSS', saltLength }, this.publicKey, sig, msg))
        ) {
            throw new Error('invalid signature');
        }

        return sig;
    }
}

export class RSABlindSigner {
    constructor(private privateKey: CryptoKey) {
        if (privateKey.type !== 'private' || privateKey.algorithm.name !== 'RSA-PSS') {
            throw new Error('key is not rsa-pss');
        }
    }

    async sign(blinded_msg: Uint8Array): Promise<Uint8Array> {
        const { modulusLength } = this.privateKey.algorithm as RsaHashedKeyGenParams;
        const kLen = Math.ceil(modulusLength / 8);
        // 1. If len(blinded_msg) != kLen, raise "unexpected input size"
        //    and stop
        if (blinded_msg.length != kLen) {
            throw new Error('unexpected input size');
        }
        // 2. m = bytes_to_int(blinded_msg)
        const m = os2ip(blinded_msg);

        const jwkKey = await crypto.subtle.exportKey('jwk', this.privateKey);
        if ((jwkKey.kty && jwkKey.kty != 'RSA') || !jwkKey.n || !jwkKey.d) {
            throw new Error('key is not rsa-pss');
        }
        const n = new sjcl.bn(Buffer.from(jwkKey.n, 'base64url').toString('hex'));
        const d = new sjcl.bn(Buffer.from(jwkKey.d, 'base64url').toString('hex'));
        // 3. If m >= n, raise "invalid message length" and stop
        if (m.greaterEquals(n)) {
            throw new Error('invalid message length');
        }
        // 4. s = RSASP1(skS, m)
        const s = rsasp1({ n, d }, m);
        // 5. blind_sig = int_to_bytes(s, kLen)
        // 6. output blind_sig
        return i2osp(s, kLen);
    }
}
