/*!
 * JWTAuditor - JWT暴力破解器模块 (中文版)
 * https://github.com/dr34mhacks/jwtauditor
 * Copyright (c) 2025 Sid Joshi (@dr34mhacks)
 * Licensed under Apache-2.0 License
 */

class JWTBruteforcer {
    constructor() {
        this.token = null;
        this.header = null;
        this.payload = null;
        this.signature = null;
        this.algorithm = null;
        this.wordlist = [];
        this.customWordlist = null;
        this.isRunning = false;
        this.shouldStop = false;
        this.progress = 0;
        this.nonHmacAlgorithmDetected = false;
        this.detectedAlgorithm = null;
        this.defaultWordlist = null;
        this.signingInput = null;
        this.expectedSignature = null;
        this.batchSize = 100;
        this._author = 'dr34mhacks';
        this._repo = 'https://github.com/dr34mhacks/jwtauditor';
    }

    async loadDefaultWordlist() {
        if (this.defaultWordlist) return this.defaultWordlist;
        
        try {
            const response = await fetch('jwt_auditor_potential_secrets.txt');
            if (!response.ok) throw new Error('HTTP ' + response.status + ': ' + response.statusText);
            const text = await response.text();
            this.defaultWordlist = text.split('\n')
                .map(line => line.trim())
                .filter(line => line.length > 0);
            return this.defaultWordlist;
        } catch (error) {
            // 如果无法加载外部词表，使用内置词表
            this.defaultWordlist = [
                'secret', 'password', '123456', 'admin', 'test', 'key', 'jwt', 'token', 
                'default', 'qwerty', 'your-256-bit-secret', 'supersecret', 'mySecretKey', 
                'jwt_secret', 'secretkey', 'mysecret', 'jwtsecret', 'secret123', 
                'password123', 'testkey', 'demo', 'sample', 'example', 'dev', 
                'development', 'prod', 'production', 'staging', 'local', 'localhost', 
                'app', 'application', 'service', 'api'
            ];
            return this.defaultWordlist;
        }
    }

    init(token) {
        try {
            this.token = token;
            const decoded = jwtDecoder.decode(token);
            this.header = decoded.header;
            this.payload = decoded.payload;
            this.signature = decoded.signature;
            this.algorithm = this.header.alg;
            this.nonHmacAlgorithmDetected = false;
            this.detectedAlgorithm = this.algorithm;
            
            // 检查算法是否支持暴力破解
            if (this.algorithm !== 'none' && !this.algorithm.startsWith('HS')) {
                this.nonHmacAlgorithmDetected = true;
                return false;
            }
            
            // 准备签名验证所需的数据
            const tokenParts = token.split('.');
            this.signingInput = tokenParts[0] + '.' + tokenParts[1];
            this.expectedSignature = tokenParts[2];
            
            return true;
        } catch (error) {
            return false;
        }
    }

    setCustomWordlist(wordlist) {
        this.customWordlist = wordlist.split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);
    }

    setWordlist(wordlist) {
        this.setCustomWordlist(wordlist);
    }

    start(method, progressCallback, resultCallback) {
        if (arguments.length === 2) {
            // 旧的调用方式，假定为字典方法
            return this._startBruteforce('dictionary', method, progressCallback);
        } else {
            return this._startBruteforce(method, progressCallback, resultCallback);
        }
    }

    async _startBruteforce(method, progressCallback, resultCallback) {
        if (this.isRunning) return;
        
        this.isRunning = true;
        this.shouldStop = false;
        this.progress = 0;
        
        try {
            // 根据方法选择词表
            if (method === 'custom' && this.customWordlist) {
                this.wordlist = this.customWordlist;
            } else {
                this.wordlist = await this.loadDefaultWordlist();
            }
            
            const totalSecrets = this.wordlist.length;
            let testedCount = 0;
            
            progressCallback(0);
            
            // 批量处理以避免阻塞UI
            for (let i = 0; i < this.wordlist.length; i += this.batchSize) {
                if (this.shouldStop) break;
                
                // 获取当前批次
                const batch = this.wordlist.slice(i, i + this.batchSize);
                
                // 并行测试批次中的所有密钥
                const results = await this.processBatch(batch);
                
                // 检查是否找到了正确的密钥
                if (results.found) {
                    resultCallback({ success: true, secret: results.secret });
                    this.isRunning = false;
                    return;
                }
                
                testedCount += batch.length;
                this.progress = Math.floor((testedCount / totalSecrets) * 100);
                progressCallback(this.progress);
                
                // 让出控制权以便UI更新
                await new Promise(resolve => setTimeout(resolve, 0));
            }
            
            resultCallback({ success: false, error: '在词表中未找到匹配的密钥。' });
            this.isRunning = false;
        } catch (error) {
            resultCallback({ success: false, error: error.message });
            this.isRunning = false;
        }
    }

    async processBatch(secrets) {
        // 并行测试批次中的所有密钥
        const promises = secrets.map(secret => this.testSecretFast(secret));
        const results = await Promise.all(promises);
        
        // 检查是否有匹配的密钥
        for (let i = 0; i < results.length; i++) {
            if (results[i]) {
                return { found: true, secret: secrets[i] };
            }
        }
        
        return { found: false };
    }

    testSecretFast(secret) {
        try {
            // 根据算法计算签名
            if (this.algorithm === 'HS256') {
                const signature = CryptoJS.HmacSHA256(this.signingInput, secret);
                const base64Signature = CryptoJS.enc.Base64.stringify(signature)
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=/g, '');
                return base64Signature === this.expectedSignature;
            } else if (this.algorithm === 'HS384') {
                const signature = CryptoJS.HmacSHA384(this.signingInput, secret);
                const base64Signature = CryptoJS.enc.Base64.stringify(signature)
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=/g, '');
                return base64Signature === this.expectedSignature;
            } else if (this.algorithm === 'HS512') {
                const signature = CryptoJS.HmacSHA512(this.signingInput, secret);
                const base64Signature = CryptoJS.enc.Base64.stringify(signature)
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=/g, '');
                return base64Signature === this.expectedSignature;
            }
            
            return false;
        } catch (error) {
            return false;
        }
    }

    testSecret(secret) {
        return this.testSecretFast(secret);
    }

    stop() {
        this.shouldStop = true;
        this.isRunning = false;
    }
}

window.jwtBruteforcer = new JWTBruteforcer();