/*!
 * JWTAuditor - JWT解码器模块 (中文版)
 * https://github.com/dr34mhacks/jwtauditor
 * Copyright (c) 2025 Sid Joshi (@dr34mhacks)
 * Licensed under Apache-2.0 License
 */

class JWTDecoder {
    constructor() {
        this.token = null;
        this.header = null;
        this.payload = null;
        this.signature = null;
        this.parts = [];
        this._author = 'dr34mhacks';
        this._repo = 'https://github.com/dr34mhacks/jwtauditor';
    }

    validateJWTFormat(token) {
        if (!token) throw new Error('JWT令牌是必需的');
        token = token.trim();
        if (!token) throw new Error('JWT令牌不能为空');
        if (token.startsWith('http') || token.includes('://') || token.includes('www.') || 
            token.includes('.com') || token.includes('.org') || token.includes('.net')) 
            throw new Error('URL不是有效的JWT令牌');
        if (token.includes(' ') && token.split(' ').length > 3) 
            throw new Error('无效输入：这似乎是文本，而不是JWT令牌');
        if (token.length < 30) 
            throw new Error('无效JWT：令牌太短，不足以成为有效的JWT');
        if (!token.includes('.')) 
            throw new Error('无效JWT格式：令牌必须包含点作为分隔符');
        
        const parts = token.split('.');
        if (parts.length !== 3) 
            throw new Error(`无效JWT格式：预期3个部分用点分隔，得到${parts.length}个部分`);
        
        for (let i = 0; i < 2; i++) {
            if (!parts[i] || parts[i].trim() === '') 
                throw new Error(`无效JWT格式：${['头部','载荷'][i]}部分不能为空`);
            this.detectMaliciousPayloads(parts[i]);
            if (!/^[A-Za-z0-9_-]+$/.test(parts[i])) 
                throw new Error(`无效JWT格式：${['头部','载荷'][i]}包含无效的base64url字符`);
        }
        
        if (parts[2]) {
            this.detectMaliciousPayloads(parts[2]);
            if (!/^[A-Za-z0-9_-]+$/.test(parts[2])) 
                throw new Error('无效JWT格式：签名包含无效的base64url字符');
        }
        
        return { token, parts, hasSignature: !!(parts[2] && parts[2].length > 0) };
    }

    detectMaliciousPayloads(part) {
        if (!part || part.length === 0) return;
    }

    decode(token) {
        try {
            const { token: tokenVal, parts, hasSignature } = this.validateJWTFormat(token);
            
            if (!hasSignature) {
                showNotification('警告：JWT没有签名 - 此令牌不安全且可以轻松篡改', 'warning', 5000);
            }
            
            let headerStr, payloadStr;
            
            try {
                headerStr = base64UrlDecode(parts[0]);
            } catch (error) {
                throw new Error(`解码JWT头部失败: ${error.message}`);
            }
            
            try {
                payloadStr = base64UrlDecode(parts[1]);
            } catch (error) {
                throw new Error(`解码JWT载荷失败: ${error.message}`);
            }
            
            let header, payload;
            
            try {
                header = JSON.parse(headerStr);
            } catch (error) {
                throw new Error(`无效JWT头部: 头部不是有效的JSON - ${error.message}`);
            }
            
            try {
                payload = JSON.parse(payloadStr);
            } catch (error) {
                throw new Error(`无效JWT载荷: 载荷不是有效的JSON - ${error.message}`);
            }
            
            if (!header || typeof header !== 'object') 
                throw new Error('无效JWT: 头部必须是有效的JSON对象');
            if (!header.alg) 
                throw new Error('无效JWT: 头部必须包含"alg"（算法）字段');
            
            const supportedAlgorithms = [
                'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 
                'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'none'
            ];
            
            if (!supportedAlgorithms.includes(header.alg)) 
                throw new Error(`无效JWT: 不支持的算法"${header.alg}"。支持的算法: ${supportedAlgorithms.join(', ')}`);
            
            if (header.typ && header.typ !== 'JWT') 
                throw new Error(`无效JWT: 令牌类型"${header.typ}"不受支持。预期"JWT"`);
            
            if (!payload || typeof payload !== 'object') 
                throw new Error('无效JWT: 载荷必须是有效的JSON对象');
            
            const timestampClaims = ['iat', 'exp', 'nbf'];
            for (const claim of timestampClaims) {
                if (payload[claim] !== undefined && (typeof payload[claim] !== 'number' || payload[claim] < 0))
                    throw new Error(`无效JWT: "${claim}"声明必须是正数（Unix时间戳）`);
            }
            
            if (payload.iat && payload.exp && payload.iat > payload.exp) 
                throw new Error('无效JWT: "iat"（签发时间）不能晚于"exp"（过期时间）');
            if (payload.nbf && payload.exp && payload.nbf > payload.exp) 
                throw new Error('无效JWT: "nbf"（生效时间）不能晚于"exp"（过期时间）');
            
            this.token = tokenVal;
            this.parts = parts;
            this.header = header;
            this.payload = payload;
            this.signature = parts[2] || '';
            
            return {
                header: this.header,
                payload: this.payload,
                signature: this.signature,
                raw: {
                    header: parts[0],
                    payload: parts[1],
                    signature: parts[2] || ''
                }
            };
        } catch (error) {
            this.token = null;
            this.header = null;
            this.payload = null;
            this.signature = null;
            this.parts = [];
            throw error;
        }
    }

    isExpired() {
        if (!this.payload || !this.payload.exp) return false;
        return isExpired(this.payload.exp);
    }

    getTimeUntilExpiration() {
        if (!this.payload || !this.payload.exp) return '无过期时间';
        return timeUntilExpiration(this.payload.exp);
    }

    isValidForUse() {
        if (!this.payload) return false;
        const now = getCurrentTimestamp();
        if (this.payload.exp && this.payload.exp < now) return false;
        if (this.payload.nbf && this.payload.nbf > now) return false;
        return true;
    }

    getFormattedPayload() {
        if (!this.payload) return null;
        const formatted = { ...this.payload };
        const timestampFields = ['exp', 'iat', 'nbf'];
        for (const field of timestampFields) {
            if (formatted[field] && typeof formatted[field] === 'number') {
                formatted[`${field}_formatted`] = formatTimestamp(formatted[field]);
            }
        }
        return formatted;
    }

    getAlgorithm() {
        return this.header ? this.header.alg : null;
    }

    usesNoneAlgorithm() {
        return this.getAlgorithm() === 'none';
    }

    usesSymmetricAlgorithm() {
        const algorithm = this.getAlgorithm();
        return algorithm && algorithm.startsWith('HS');
    }

    usesAsymmetricAlgorithm() {
        const algorithm = this.getAlgorithm();
        return algorithm && (algorithm.startsWith('RS') || algorithm.startsWith('ES') || algorithm.startsWith('PS'));
    }

    getSigningInput() {
        if (!this.parts || this.parts.length < 2) return '';
        return `${this.parts[0]}.${this.parts[1]}`;
    }

    async verifySignature(secret) {
        if (!this.token) return false;
        try {
            const algorithm = this.getAlgorithm();
            if (algorithm === 'none') return true;
            if (!algorithm.startsWith('HS')) throw new Error(`算法${algorithm}在回退模式下不支持`);
            const signingInput = this.getSigningInput();
            const expectedSignature = await computeHmac(algorithm, secret, signingInput);
            const expectedSignatureBase64Url = expectedSignature
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=/g, '');
            return expectedSignatureBase64Url === this.signature;
        } catch (error) {
            console.error('验证签名时出错:', error);
            return false;
        }
    }
}

const jwtDecoder = new JWTDecoder;