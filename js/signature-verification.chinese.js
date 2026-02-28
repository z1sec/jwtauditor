/*!
 * JWTAuditor - 签名验证模块 (中文版)
 * https://github.com/dr34mhacks/jwtauditor
 * Copyright (c) 2025 Sid Joshi (@dr34mhacks)
 * Licensed under Apache-2.0 License
 */

function initSignatureVerification() {
    const verifyButton = document.getElementById('verify-signature-btn');
    const secretInput = document.getElementById('verify-secret');
    const resultDisplay = document.getElementById('verification-result');
    const jwtOutput = document.getElementById('edited-jwt-output');
    
    if (!verifyButton || !secretInput || !resultDisplay) {
        console.error('签名验证元素未找到');
        return;
    }
    
    verifyButton.addEventListener('click', async () => {
        const token = jwtOutput.textContent;
        const secret = secretInput.value;
        
        if (!token) {
            showNotification('没有要验证的JWT', 'warning');
            return;
        }
        
        if (!secret) {
            showNotification('请输入密钥', 'warning');
            return;
        }
        
        try {
            // 确保JWT编辑器中有令牌
            if (jwtEditor.token !== token) {
                jwtEditor.loadToken(token);
            }
            
            const isValid = await jwtEditor.verifySignature(secret);
            
            resultDisplay.className = isValid ? 'verification-result success' : 'verification-result error';
            resultDisplay.innerHTML = isValid ? 
                '<i class="fas fa-check-circle"></i> 签名有效！该令牌使用此密钥签名。' :
                '<i class="fas fa-times-circle"></i> 签名无效。该令牌未使用此密钥签名。';
            
            showNotification(isValid ? '签名验证成功！' : '签名验证失败', isValid ? 'success' : 'error');
        } catch (error) {
            resultDisplay.className = 'verification-result error';
            resultDisplay.innerHTML = `<i class="fas fa-exclamation-circle"></i> 错误: ${error.message}`;
            showNotification(`错误: ${error.message}`, 'error');
        }
    });
}

document.addEventListener('DOMContentLoaded', initSignatureVerification);