/*!
 * JWTAuditor - JWT生成器模块 (中文版)
 * https://github.com/dr34mhacks/jwtauditor
 * Copyright (c) 2025 Sid Joshi (@dr34mhacks)
 * Licensed under Apache-2.0 License
 */

class JWTGenerator {
    constructor() {
        this.editor = jwtEditor;
        this.defaultHeader = { alg: 'HS256', typ: 'JWT' };
        this.defaultPayload = {
            sub: '1234567890',
            name: '张三',
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 3600
        };
        this.claimTemplates = {
            sub: { 
                name: '主体', 
                description: 'JWT的主题（用户）', 
                value: '1234567890' 
            },
            iss: { 
                name: '签发者', 
                description: 'JWT的签发者', 
                value: 'https://example.com' 
            },
            aud: { 
                name: '受众', 
                description: 'JWT的受众', 
                value: 'https://api.example.com' 
            },
            exp: { 
                name: '过期时间', 
                description: 'JWT何时过期（自纪元以来的秒数）', 
                value: Math.floor(Date.now() / 1000) + 3600 
            },
            nbf: { 
                name: '生效时间', 
                description: 'JWT何时生效（自纪元以来的秒数）', 
                value: Math.floor(Date.now() / 1000) 
            },
            iat: { 
                name: '签发时间', 
                description: 'JWT签发时间（自纪元以来的秒数）', 
                value: Math.floor(Date.now() / 1000) 
            },
            jti: { 
                name: 'JWT标识符', 
                description: 'JWT的唯一标识符', 
                value: crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2) 
            }
        };
    }

    resetToDefaults() {
        this.editor.header = { ...this.defaultHeader };
        this.editor.payload = { ...this.defaultPayload };
        this.editor.payload.iat = Math.floor(Date.now() / 1000);
        this.editor.payload.exp = Math.floor(Date.now() / 1000) + 3600;
    }

    setHeader(header) {
        this.editor.updateHeader(header);
    }

    setPayload(payload) {
        this.editor.updatePayload(payload);
    }

    addClaim(claim) {
        this.editor.payload || (this.editor.payload = {});
        if (this.claimTemplates[claim]) {
            if (!this.editor.payload[claim]) {
                this.editor.payload[claim] = this.claimTemplates[claim].value;
                return true;
            }
        }
        return false;
    }

    removeClaim(claim) {
        if (this.editor.payload && this.editor.payload[claim]) {
            delete this.editor.payload[claim];
            return true;
        }
        return false;
    }

    updateTimestamps() {
        if (!this.editor.payload) return;
        const now = Math.floor(Date.now() / 1000);
        this.editor.payload.iat !== void 0 && (this.editor.payload.iat = now);
        this.editor.payload.nbf !== void 0 && (this.editor.payload.nbf = now);
        this.editor.payload.exp !== void 0 && (this.editor.payload.exp = now + 3600);
    }

    generateToken(algorithm, secret = '', privateKey = '') {
        this.editor.header || (this.editor.header = { ...this.defaultHeader });
        this.editor.payload || (this.editor.payload = { ...this.defaultPayload });
        this.editor.header.alg = algorithm;
        return this.editor.generateToken(algorithm, secret, privateKey);
    }

    getClaimInfo(claim) {
        return this.claimTemplates[claim] || null;
    }

    getAllClaimTemplates() {
        return this.claimTemplates;
    }

    getFormattedHeader() {
        return this.editor.getFormattedHeader();
    }

    getFormattedPayload() {
        return this.editor.getFormattedPayload();
    }
}

const jwtGenerator = new JWTGenerator;