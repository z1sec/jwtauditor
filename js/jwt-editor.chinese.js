/*!
 * JWTAuditor - JWT编辑器模块 (中文版)
 * https://github.com/dr34mhacks/jwtauditor
 * Copyright (c) 2025 Sid Joshi (@dr34mhacks)
 * Licensed under Apache-2.0 License
 */

class JWTEditor {
    constructor() {
        this.token = null;
        this.header = null;
        this.payload = null;
        this.signature = null;
        this.decoder = jwtDecoder;
    }

    loadToken(token) {
        if (!token) {
            throw new Error('令牌是必需的');
        }

        try {
            const decoded = this.decoder.decode(token);
            this.token = token;
            this.header = decoded.header;
            this.payload = decoded.payload;
            this.signature = decoded.signature;
            return decoded;
        } catch (error) {
            throw new Error(`加载JWT失败: ${error.message}`);
        }
    }

    updateHeader(header) {
        try {
            if (typeof header === 'string') {
                header = JSON.parse(header);
            }
            this.header = header;
        } catch (error) {
            throw new Error(`无效的头部JSON: ${error.message}`);
        }
    }

    updatePayload(payload) {
        try {
            if (typeof payload === 'string') {
                payload = JSON.parse(payload);
            }
            this.payload = payload;
        } catch (error) {
            throw new Error(`无效的载荷JSON: ${error.message}`);
        }
    }

    generateToken(algorithm, secret = '', privateKey = '') {
        if (!this.header || !this.payload) {
            throw new Error('生成令牌前必须设置头部和载荷');
        }

        this.header.alg = algorithm;

        const encodedHeader = base64UrlEncode(JSON.stringify(this.header));
        const encodedPayload = base64UrlEncode(JSON.stringify(this.payload));
        const headerAndPayload = `${encodedHeader}.${encodedPayload}`;

        let signature = '';

        if (algorithm === 'none') {
            signature = '';
        } else if (algorithm.startsWith('HS')) {
            try {
                let hmac;
                if (algorithm === 'HS256') {
                    hmac = CryptoJS.HmacSHA256(headerAndPayload, secret);
                } else if (algorithm === 'HS384') {
                    hmac = CryptoJS.HmacSHA384(headerAndPayload, secret);
                } else if (algorithm === 'HS512') {
                    hmac = CryptoJS.HmacSHA512(headerAndPayload, secret);
                } else {
                    throw new Error(`不支持的算法: ${algorithm}`);
                }

                const signatureBytes = CryptoJS.enc.Base64.stringify(hmac);
                signature = signatureBytes.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            } catch (error) {
                throw new Error(`生成HMAC签名失败: ${error.message}`);
            }
        } else if (algorithm.startsWith('RS')) {
            if (!privateKey) {
                throw new Error('RSA算法需要私钥');
            }

            if (typeof KJUR === 'undefined' || !KJUR.crypto || !KJUR.crypto.Signature) {
                throw new Error('jsrsasign库未加载或不可用。请刷新页面后再试。');
            }

            if (!privateKey.includes('-----BEGIN') || !privateKey.includes('PRIVATE KEY-----')) {
                throw new Error('私钥必须是PEM格式（-----BEGIN ... PRIVATE KEY-----）');
            }

            try {
                let sigAlg;
                switch (algorithm) {
                    case 'RS256':
                        sigAlg = 'SHA256withRSA';
                        break;
                    case 'RS384':
                        sigAlg = 'SHA384withRSA';
                        break;
                    case 'RS512':
                        sigAlg = 'SHA512withRSA';
                        break;
                    default:
                        throw new Error(`不支持的RSA算法: ${algorithm}`);
                }

                const sig = new KJUR.crypto.Signature({ alg: sigAlg });
                sig.init(privateKey);
                sig.updateString(headerAndPayload);
                const hSig = sig.sign();

                // 将十六进制转换为Base64 URL编码
                const byteChars = [];
                for (let i = 0; i < hSig.length; i += 2) {
                    byteChars.push(parseInt(hSig.substr(i, 2), 16));
                }

                // 处理大数组
                const chunkSize = 8192;
                let signatureString = '';
                for (let i = 0; i < byteChars.length; i += chunkSize) {
                    const chunk = byteChars.slice(i, i + chunkSize);
                    signatureString += String.fromCharCode.apply(null, chunk);
                }

                const signatureBase64 = btoa(signatureString);
                signature = signatureBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            } catch (error) {
                throw new Error(`生成RSA签名失败: ${error.message}`);
            }
        } else {
            throw new Error(`不支持的算法: ${algorithm}`);
        }

        return `${headerAndPayload}.${signature}`;
    }

    generateNoneToken() {
        return this.generateToken('none');
    }

    generateSymmetricToken(algorithm, secret) {
        if (!algorithm.startsWith('HS')) {
            throw new Error('对称签名算法必须是HS256、HS384或HS512');
        }
        return this.generateToken(algorithm, secret);
    }

    generateAsymmetricToken(algorithm, privateKey) {
        if (!algorithm.startsWith('RS')) {
            throw new Error('非对称签名算法必须是RS256、RS384或RS512');
        }
        return this.generateToken(algorithm, '', privateKey);
    }

    getFormattedHeader() {
        return JSON.stringify(this.header, null, 2);
    }

    getFormattedPayload() {
        return JSON.stringify(this.payload, null, 2);
    }

    async verifySignature(secretOrPublicKey) {
        if (!this.token) {
            throw new Error('未加载令牌');
        }

        const tokenParts = this.token.split('.');
        if (tokenParts.length !== 3) {
            throw new Error('令牌格式无效');
        }

        const header = this.header;
        const algorithm = header.alg;

        if (algorithm === 'none') {
            return true;
        }

        const headerAndPayload = `${tokenParts[0]}.${tokenParts[1]}`;
        const expectedSignature = tokenParts[2];

        if (algorithm.startsWith('HS')) {
            try {
                let hmac;
                if (algorithm === 'HS256') {
                    hmac = CryptoJS.HmacSHA256(headerAndPayload, secretOrPublicKey);
                } else if (algorithm === 'HS384') {
                    hmac = CryptoJS.HmacSHA384(headerAndPayload, secretOrPublicKey);
                } else if (algorithm === 'HS512') {
                    hmac = CryptoJS.HmacSHA512(headerAndPayload, secretOrPublicKey);
                } else {
                    throw new Error(`不支持的算法: ${algorithm}`);
                }

                const computedSignatureBytes = CryptoJS.enc.Base64.stringify(hmac);
                const computedSignature = computedSignatureBytes.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

                return computedSignature === expectedSignature;
            } catch (error) {
                console.error('验证HMAC签名时出错:', error);
                return false;
            }
        } else if (algorithm.startsWith('RS')) {
            if (typeof KJUR === 'undefined' || !KJUR.crypto || !KJUR.crypto.Signature || !KEYUTIL) {
                throw new Error('jsrsasign库未加载或不可用。请刷新页面后再试。');
            }

            try {
                let sigAlg;
                switch (algorithm) {
                    case 'RS256':
                        sigAlg = 'SHA256withRSA';
                        break;
                    case 'RS384':
                        sigAlg = 'SHA384withRSA';
                        break;
                    case 'RS512':
                        sigAlg = 'SHA512withRSA';
                        break;
                    default:
                        throw new Error(`不支持的RSA算法: ${algorithm}`);
                }

                const pubKey = KEYUTIL.getKey(secretOrPublicKey);
                const sig = new KJUR.crypto.Signature({ alg: sigAlg });
                sig.init(pubKey);
                sig.updateString(headerAndPayload);

                // 将Base64 URL编码的签名转换回Base64
                const signatureBase64Url = expectedSignature;
                const signatureBase64 = signatureBase64Url.replace(/-/g, '+').replace(/_/g, '/');
                const padding = '='.repeat((4 - signatureBase64.length % 4) % 4);
                const signaturePadded = signatureBase64 + padding;
                const signatureBinary = atob(signaturePadded);

                // 转换为十六进制字符串
                const signatureHex = Array.from(signatureBinary, byte => 
                    byte.charCodeAt(0).toString(16).padStart(2, '0')
                ).join('');

                return sig.verify(signatureHex);
            } catch (error) {
                console.error('验证RSA签名时出错:', error);
                return false;
            }
        } else {
            throw new Error(`不支持的算法: ${algorithm}`);
        }
    }
}

const jwtEditor = new JWTEditor;