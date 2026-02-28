/*!
 * JWTAuditor Utilities Library (Chinese Version)
 * https://github.com/dr34mhacks/jwtauditor
 * Copyright (c) 2025 Sid Joshi (@dr34mhacks)
 * Licensed under Apache-2.0 License
 */

/**
 * 检查浏览器是否支持WebAssembly
 * @returns {boolean} 如果支持WebAssembly则返回true，否则返回false
 */
const isWasmSupported = () => {
    try {
        if (typeof WebAssembly === "object" && typeof WebAssembly.instantiate === "function") {
            const module = new WebAssembly.Module(Uint8Array.of(0x0, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00));
            return module instanceof WebAssembly.Module;
        } else {
            return false;
        }
    } catch (e) {
        return false;
    }
};

/**
 * Base64 URL编码
 * @param {string} str - 要编码的字符串
 * @returns {string} 编码后的Base64 URL字符串
 */
const base64UrlEncode = (str) => {
    let encoded = btoa(str);
    return encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/**
 * Base64 URL解码
 * @param {string} str - 要解码的Base64 URL字符串
 * @returns {string} 解码后的字符串
 */
const base64UrlDecode = (str) => {
    // 替换URL安全字符为标准Base64字符
    let base64Str = str.replace(/-/g, '+').replace(/_/g, '/');
    
    // 根据长度添加适当的填充
    switch (base64Str.length % 4) {
        case 0: break;
        case 2: base64Str += '=='; break;
        case 3: base64Str += '='; break;
        default: throw new Error('无效的base64url字符串');
    }
    
    try {
        return atob(base64Str);
    } catch (error) {
        throw new Error('无法解码base64url字符串');
    }
};

/**
 * 将字符串转换为UTF-8数组
 * @param {string} str - 要转换的字符串
 * @returns {number[]} UTF-8字节数组
 */
const stringToUtf8Array = (str) => {
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
        let charCode = str.charCodeAt(i);
        
        if (charCode < 128) {
            bytes.push(charCode);
        } else if (charCode < 2048) {
            bytes.push(192 | (charCode >> 6), 128 | (charCode & 63));
        } else if (charCode < 55296 || charCode >= 57344) {
            bytes.push(224 | (charCode >> 12), 128 | ((charCode >> 6) & 63), 128 | (charCode & 63));
        } else {
            // 处理代理对
            i++;
            charCode = 65536 + ((charCode & 1023) << 10) | (str.charCodeAt(i) & 1023);
            bytes.push(
                240 | (charCode >> 18),
                128 | ((charCode >> 12) & 63),
                128 | ((charCode >> 6) & 63),
                128 | (charCode & 63)
            );
        }
    }
    return bytes;
};

/**
 * 格式化JSON为语法高亮的HTML
 * @param {any} json - 要格式化的JSON数据
 * @returns {string} 格式化后的HTML字符串
 */
const formatJSON = (json) => {
    if (!json) return '';
    
    try {
        // 解析JSON（如果输入是字符串）并格式化
        const obj = typeof json === 'string' ? JSON.parse(json) : json;
        const jsonString = JSON.stringify(obj, null, 2);
        
        // 应用基本的语法高亮
        let highlighted = jsonString
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, (match) => {
                let className = 'json-number';
                
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) {
                        className = 'json-key';  // 键
                    } else {
                        className = 'json-string';  // 字符串值
                    }
                } else if (/true|false/.test(match)) {
                    className = 'json-boolean';  // 布尔值
                } else if (/null/.test(match)) {
                    className = 'json-null';  // null值
                }
                
                return `<span class="${className}">${match}</span>`;
            })
            .replace(/([{}[\],])/g, '<span class="json-punctuation">$1</span>');
        
        // 高亮时间戳字段
        const timestampFields = ['iat', 'exp', 'nbf'];
        for (const field of timestampFields) {
            const timestampRegex = new RegExp(`<span class="json-key">"${field}":</span>\\s*<span class="json-number">(\\d+)</span>`, 'g');
            highlighted = highlighted.replace(timestampRegex, (match, timestamp) => {
                const ts = parseInt(timestamp);
                const formattedTime = formatTimestamp(ts);
                const currentTime = getCurrentTimestamp();
                
                let status;
                if (field === 'exp') {
                    status = ts < currentTime ? '🔴 已过期' : '🟢 有效';
                } else if (field === 'nbf') {
                    status = ts > currentTime ? '🔴 尚未生效' : '🟢 有效';
                } else {
                    status = '🟢 有效';
                }
                
                const fieldName = field === 'iat' ? '签发时间' : field === 'exp' ? '过期时间' : '生效时间';
                
                return `<span class="json-key">"${field}":</span> <span class="json-timestamp" data-timestamp="${ts}" title="${fieldName}: ${formattedTime} (${status})">${timestamp}</span>`;
            });
        }
        
        return highlighted;
    } catch (error) {
        console.error('格式化JSON时出错:', error);
        return String(json);
    }
};

/**
 * 复制文本到剪贴板
 * @param {string} text - 要复制的文本
 * @returns {Promise<void>} 异步操作的Promise
 */
const copyToClipboard = (text) => {
    return new Promise((resolve, reject) => {
        // 使用现代剪贴板API（如果可用）
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(resolve).catch(reject);
        } else {
            // 回退到传统方法
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.left = '-999999px';
            textarea.style.top = '-999999px';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            
            try {
                const success = document.execCommand('copy');
                document.body.removeChild(textarea);
                if (success) {
                    resolve();
                } else {
                    reject(new Error('无法复制'));
                }
            } catch (error) {
                document.body.removeChild(textarea);
                reject(error);
            }
        }
    });
};

/**
 * 显示通知消息
 * @param {string} message - 要显示的消息
 * @param {'info'|'success'|'warning'|'error'} type - 通知类型
 * @param {number} duration - 显示持续时间（毫秒）
 */
const showNotification = (message, type = 'info', duration = 3000) => {
    // 移除现有通知
    const existingNotification = document.querySelector('.notification');
    if (existingNotification) {
        existingNotification.remove();
    }
    
    // 创建新通知元素
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;
    
    // 添加到页面
    document.body.appendChild(notification);
    
    // 触发显示动画
    setTimeout(() => {
        notification.classList.add('show');
    }, 10);
    
    // 设置自动隐藏
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 300);
    }, duration);
};

/**
 * 验证JSON字符串的有效性
 * @param {string} str - 要验证的字符串
 * @returns {boolean} 如果是有效的JSON则返回true，否则返回false
 */
const isValidJSON = (str) => {
    try {
        JSON.parse(str);
        return true;
    } catch (error) {
        return false;
    }
};

/**
 * 获取当前时间戳（秒）
 * @returns {number} 当前Unix时间戳
 */
const getCurrentTimestamp = () => {
    return Math.floor(Date.now() / 1000);
};

/**
 * 格式化时间戳为可读日期时间
 * @param {number} timestamp - Unix时间戳（秒）
 * @returns {string} 格式化的日期时间字符串
 */
const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp * 1000);
    const dateString = date.toDateString() + ' ' + date.toTimeString().split(' ')[0];
    const timezone = date.toTimeString().split(' ')[1];
    return dateString + '\n' + timezone;
};

/**
 * 检查时间戳是否已过期
 * @param {number} timestamp - 要检查的时间戳
 * @returns {boolean} 如果已过期则返回true，否则返回false
 */
const isExpired = (timestamp) => {
    const now = getCurrentTimestamp();
    return timestamp < now;
};

/**
 * 计算到期剩余时间
 * @param {number} expTimestamp - 过期时间戳
 * @returns {string} 格式化的剩余时间字符串
 */
const timeUntilExpiration = (expTimestamp) => {
    const now = getCurrentTimestamp();
    const diff = expTimestamp - now;
    
    if (diff <= 0) {
        return '已过期';
    }
    
    const days = Math.floor(diff / 86400);
    const hours = Math.floor((diff % 86400) / 3600);
    const minutes = Math.floor((diff % 3600) / 60);
    const seconds = diff % 60;
    
    if (days > 0) {
        return `${days}天 ${hours}小时 ${minutes}分钟`;
    } else if (hours > 0) {
        return `${hours}小时 ${minutes}分钟 ${seconds}秒`;
    } else if (minutes > 0) {
        return `${minutes}分钟 ${seconds}秒`;
    } else {
        return `${seconds}秒`;
    }
};

/**
 * 计算HMAC哈希
 * @param {string} algorithm - 算法名称（HS256, HS384, HS512）
 * @param {string} secret - 密钥
 * @param {string} data - 要哈希的数据
 * @returns {string} Base64编码的哈希值
 */
const computeHmac = async (algorithm, secret, data) => {
    let hash;
    
    if (algorithm === 'HS256') {
        hash = CryptoJS.HmacSHA256(data, secret);
    } else if (algorithm === 'HS384') {
        hash = CryptoJS.HmacSHA384(data, secret);
    } else if (algorithm === 'HS512') {
        hash = CryptoJS.HmacSHA512(data, secret);
    } else {
        throw new Error(`不支持的算法: ${algorithm}`);
    }
    
    return CryptoJS.enc.Base64.stringify(hash);
};

/**
 * 验证JWT签名
 * @param {string} token - JWT令牌
 * @param {string} secret - 用于验证的密钥
 * @returns {Promise<boolean>} 如果签名有效则返回true，否则返回false
 */
const verifySignature = async (token, secret) => {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            return false;
        }
        
        const header = JSON.parse(base64UrlDecode(parts[0]));
        const alg = header.alg;
        
        // 如果算法是"none"，则不需要验证签名
        if (alg === 'none') {
            return true;
        }
        
        // 只有HMAC算法才能使用这种方法验证
        if (!alg.startsWith('HS')) {
            throw new Error(`算法 ${alg} 不支持回退模式`);
        }
        
        const signingInput = `${parts[0]}.${parts[1]}`;
        const signature = parts[2];
        
        // 计算预期签名
        const expectedSignature = await computeHmac(alg, secret, signingInput);
        
        // 将Base64转换为Base64URL格式进行比较
        const expectedSignatureBase64Url = expectedSignature
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        
        return expectedSignatureBase64Url === signature;
    } catch (error) {
        console.error('验证签名时出错:', error);
        return false;
    }
};

/**
 * 生成RSA密钥对
 * @param {number} keySize - 密钥大小，默认为2048位
 * @returns {Promise<{privateKey: string, publicKey: string}>} 包含PEM格式私钥和公钥的对象
 */
const generateRSAKeyPair = async (keySize = 2048) => {
    try {
        // 检查Web Crypto API是否可用
        if (!window.crypto || !window.crypto.subtle) {
            throw new Error('此浏览器不支持Web Crypto API');
        }
        
        // 生成RSA密钥对
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: keySize,
                publicExponent: new Uint8Array([1, 0, 1]), // 65537
                hash: 'SHA-256'
            },
            true, // 可提取
            ['sign', 'verify'] // 使用场景
        );
        
        // 导出私钥和公钥
        const privateKeyBuffer = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
        const publicKeyBuffer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
        
        // 转换为PEM格式
        const privateKeyPem = derToPem(new Uint8Array(privateKeyBuffer), 'PRIVATE KEY');
        const publicKeyPem = derToPem(new Uint8Array(publicKeyBuffer), 'PUBLIC KEY');
        
        return {
            privateKey: privateKeyPem,
            publicKey: publicKeyPem
        };
    } catch (error) {
        console.error('生成RSA密钥对时出错:', error);
        throw new Error(`生成RSA密钥对失败: ${error.message}`);
    }
};

/**
 * 将DER格式转换为PEM格式
 * @param {Uint8Array} derBuffer - DER格式的字节数组
 * @param {string} type - PEM类型（例如 'PRIVATE KEY', 'PUBLIC KEY'）
 * @returns {string} PEM格式的字符串
 */
const derToPem = (derBuffer, type) => {
    // 转换为Base64
    const binaryString = String.fromCharCode(...derBuffer);
    const base64Pem = btoa(binaryString);
    
    // 每64个字符一行
    const formattedBase64 = base64Pem.replace(/(.{64})/g, '$1\n').trim();
    
    // 添加PEM包装
    return `-----BEGIN ${type}-----\n${formattedBase64}\n-----END ${type}-----`;
};

/**
 * 检查jsrsasign库是否可用
 * @returns {boolean} 如果jsrsasign库可用则返回true，否则返回false
 */
const isJSRSASignAvailable = () => {
    return typeof KJUR !== 'undefined' &&
           KJUR.crypto &&
           KJUR.crypto.Signature &&
           typeof KEYUTIL !== 'undefined';
};