/*!
 * JWTAuditor JWT解码器增强版 (中文版)
 * https://github.com/dr34mhacks/jwtauditor
 * Copyright (c) 2025 Sid Joshi (@dr34mhacks)
 * Licensed under Apache-2.0 License
 */

/**
 * JWT解码器类
 */
class JWTDecoder {
    /**
     * 构造函数
     */
    constructor() {
        this.noneAlgorithmWarningShown = false;
        this.missingSignatureWarningShown = false;
    }

    /**
     * 解码JWT令牌
     * @param {string} token - JWT令牌字符串
     * @returns {Object} 包含头部、载荷和签名的对象
     */
    decode(token) {
        if (!token || typeof token !== 'string') {
            throw new Error('无效的JWT令牌：令牌必须是非空字符串');
        }

        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('无效的JWT令牌：令牌必须包含三个部分（头部.载荷.签名）');
        }

        const [headerPart, payloadPart, signaturePart] = parts;

        try {
            // 解码头部
            const header = JSON.parse(base64UrlDecode(headerPart));
            
            // 解码载荷
            const payload = JSON.parse(base64UrlDecode(payloadPart));
            
            // 检查算法并显示警告
            this.checkAlgorithm(header.alg, headerPart, payloadPart, signaturePart);
            
            return {
                header: header,
                payload: payload,
                signature: signaturePart,
                raw: {
                    header: headerPart,
                    payload: payloadPart,
                    signature: signaturePart
                }
            };
        } catch (error) {
            throw new Error(`JWT解码失败: ${error.message}`);
        }
    }

    /**
     * 检查JWT算法并显示警告
     * @param {string} alg - JWT算法
     * @param {string} headerPart - 头部部分
     * @param {string} payloadPart - 载荷部分
     * @param {string} signaturePart - 签名部分
     */
    checkAlgorithm(alg, headerPart, payloadPart, signaturePart) {
        // 检查"none"算法
        if (alg === 'none' && !this.noneAlgorithmWarningShown) {
            if (typeof showNotification === 'function') {
                showNotification('⚠️ 检测到None算法：此令牌没有签名验证！', 'warning', 7000);
                this.noneAlgorithmWarningShown = true;
            }
        }
        
        // 检查缺失签名但算法不是"none"
        if (!signaturePart && alg !== 'none' && !this.missingSignatureWarningShown) {
            if (typeof showNotification === 'function') {
                showNotification('⚠️ 缺失签名：令牌缺少签名但算法不是"none"', 'warning', 5000);
                this.missingSignatureWarningShown = true;
            }
        }
    }

    /**
     * 检查JWT是否使用对称算法
     * @param {Object} jwtParts - JWT解析后的各部分
     * @returns {boolean} 如果使用对称算法则返回true，否则返回false
     */
    usesSymmetricAlgorithm(jwtParts) {
        if (!jwtParts || !jwtParts.header || !jwtParts.header.alg) {
            return false;
        }
        
        const alg = jwtParts.header.alg.toUpperCase();
        return alg.startsWith('HS'); // HS256, HS384, HS512等对称算法
    }
}

// 创建全局实例
const jwtDecoder = new JWTDecoder();

// 在DOM加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    // 重置警告标志，允许在页面刷新后再次显示警告
    if (jwtDecoder) {
        jwtDecoder.noneAlgorithmWarningShown = false;
        jwtDecoder.missingSignatureWarningShown = false;
    }
});