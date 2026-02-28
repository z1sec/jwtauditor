/*!
 * JWTAuditor 主应用程序控制器 (中文版)
 * https://github.com/dr34mhacks/jwtauditor
 * Copyright (c) 2025 Sid Joshi (@dr34mhacks)
 * Licensed under Apache-2.0 License
 */

document.addEventListener('DOMContentLoaded', () => {
    if (!isWasmSupported()) {
        showNotification('此浏览器不支持WebAssembly。某些功能可能无法正常工作。', 'warning', 5000);
    }
    
    initTabs();
    initDecoderTab();
    initAttackPlatform();
    initBruteforceTab();
    initEditorTab();
    initGeneratorTab();
});

function initTabs() {
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const tabId = button.getAttribute('data-tab');
            
            // 移除所有激活状态
            tabButtons.forEach(btn => btn.classList.remove('active'));
            tabPanes.forEach(pane => pane.classList.remove('active'));
            
            // 激活当前标签
            button.classList.add('active');
            document.getElementById(tabId).classList.add('active');
        });
    });
}

function initAttackPlatform() {
    // JWT攻击平台通过其自身的DOMContentLoaded事件初始化
    // 此函数为向后兼容保留
}

function initDecoderTab() {
    const jwtInput = document.getElementById('jwt-input');
    const decodeButton = document.getElementById('decode-btn');
    const generateRandomJwtButton = document.getElementById('generate-random-jwt-btn');
    const headerOutput = document.getElementById('header-output');
    const payloadOutput = document.getElementById('payload-output');
    const signatureOutput = document.getElementById('signature-output');
    const securityAnalysis = document.getElementById('security-analysis');
    
    // 生成随机JWT
    generateRandomJwtButton.addEventListener('click', () => {
        try {
            jwtGenerator.resetToDefaults();
            const secret = 'random-secret-' + Math.random().toString(36).substring(2, 15);
            const token = jwtGenerator.generateToken('HS256', secret);
            jwtInput.value = token;
            decodeButton.click();
            showNotification('随机JWT生成并分析成功', 'success');
        } catch (error) {
            showNotification(`生成随机JWT时出错: ${error.message}`, 'error');
        }
    });
    
    // 解码JWT
    decodeButton.addEventListener('click', () => {
        const token = jwtInput.value.trim();
        
        if (!token) {
            showNotification('请输入JWT令牌', 'warning');
            return;
        }
        
        try {
            const decoded = jwtDecoder.decode(token);
            
            // 输出解码结果
            headerOutput.innerHTML = formatJSON(decoded.header);
            payloadOutput.innerHTML = formatJSON(decoded.payload);
            signatureOutput.textContent = decoded.signature;
            
            // 高亮时间戳
            setTimeout(() => {
                document.querySelectorAll('.json-timestamp').forEach(ts => {
                    ts.classList.add('highlight');
                });
                
                setTimeout(() => {
                    document.querySelectorAll('.json-timestamp').forEach(ts => {
                        ts.classList.remove('highlight');
                    });
                }, 600);
            }, 100);
            
            // 分析安全漏洞
            jwtAnalyzer.analyze(token);
            securityAnalysis.innerHTML = jwtAnalyzer.getVulnerabilitiesHTML();
            
            // 移除现有操作按钮
            const existingActions = document.querySelector('.analysis-actions');
            if (existingActions) {
                existingActions.remove();
            }
            
            // 添加操作按钮
            setTimeout(() => {
                // 为漏洞链接添加点击事件
                const vulnLinks = document.querySelectorAll('.vulnerability a[href="#bruteforce"], .vulnerability-card a[href="#bruteforce"], .test-btn');
                vulnLinks.forEach(link => {
                    link.addEventListener('click', (e) => {
                        e.preventDefault();
                        document.querySelector('.tab-btn[data-tab="bruteforce"]').click();
                        document.getElementById('bruteforce-jwt-input').value = token;
                        showNotification('令牌已复制到暴力破解标签页', 'info');
                    });
                });
                
                // 如果使用对称算法，添加测试按钮
                if (jwtDecoder.usesSymmetricAlgorithm(decoded)) {
                    const actionsDiv = document.createElement('div');
                    actionsDiv.className = 'analysis-actions';
                    actionsDiv.innerHTML = `
                        <button id="try-bruteforce-btn" class="primary-btn">
                            <i class="fas fa-key"></i> 测试弱密钥
                        </button>
                        <p class="action-hint">此令牌使用对称算法(HS*)，可以测试弱密钥</p>
                    `;
                    securityAnalysis.parentNode.insertBefore(actionsDiv, securityAnalysis.nextSibling);
                    
                    document.getElementById('try-bruteforce-btn').addEventListener('click', () => {
                        document.querySelector('.tab-btn[data-tab="bruteforce"]').click();
                        document.getElementById('bruteforce-jwt-input').value = token;
                        showNotification('令牌已复制到暴力破解标签页', 'info');
                    });
                }
            }, 100);
            
            showNotification('JWT解码和分析成功', 'success');
        } catch (error) {
            showNotification(`错误: ${error.message}`, 'error');
            headerOutput.innerHTML = '';
            payloadOutput.innerHTML = '';
            signatureOutput.textContent = '';
            securityAnalysis.innerHTML = '';
            
            // 移除现有操作按钮
            const existingActions = document.querySelector('.analysis-actions');
            if (existingActions) {
                existingActions.remove();
            }
        }
    });
}

function initBruteforceTab() {
    const jwtInput = document.getElementById('bruteforce-jwt-input');
    const methodRadios = document.querySelectorAll('input[name="bruteforce-method"]');
    const customContainer = document.getElementById('custom-wordlist-container');
    const customWordlist = document.getElementById('custom-wordlist');
    const wordlistFile = document.getElementById('wordlist-file');
    const fileNameDisplay = document.getElementById('file-name');
    const startButton = document.getElementById('start-bruteforce-btn');
    const stopButton = document.getElementById('stop-bruteforce-btn');
    const progressBar = document.getElementById('bruteforce-progress');
    const progressText = document.getElementById('progress-text');
    const statusDisplay = document.getElementById('bruteforce-status');
    const resultDisplay = document.getElementById('bruteforce-result');
    const optionsSection = document.getElementById('bruteforce-options');
    const warningDisplay = document.getElementById('bruteforce-warning');
    
    // 监听JWT输入变化，检查算法
    jwtInput.addEventListener('input', () => {
        const token = jwtInput.value.trim();
        if (token) {
            try {
                const decoded = jwtDecoder.decode(token);
                const algorithm = decoded.header.alg;
                
                // 清除之前的警告
                if (warningDisplay) {
                    warningDisplay.innerHTML = '';
                    warningDisplay.style.display = 'none';
                }
                
                // 检查算法是否支持暴力破解
                if (algorithm !== 'none' && !algorithm.startsWith('HS')) {
                    if (warningDisplay) {
                        warningDisplay.innerHTML = `
                            <div class="warning-box">
                                <i class="fas fa-exclamation-triangle warning-icon"></i>
                                <div class="warning-content">
                                    <strong>检测到非HMAC算法: ${algorithm}</strong>
                                    <p>此令牌使用${algorithm}，不能使用此方法进行暴力破解。</p>
                                    <p>只有HMAC算法(HS256, HS384, HS512)可以暴力破解，因为它们使用共享密钥。</p>
                                    <p>${algorithm}使用非对称加密与公钥/私钥对，无法暴力破解。</p>
                                    <p><a href="docs/tool-guides/secret-bruteforcer.html#limitations" target="_blank">了解更多关于算法限制的信息</a></p>
                                </div>
                            </div>
                        `;
                        warningDisplay.style.display = 'block';
                        startButton.disabled = true;
                    }
                } else {
                    startButton.disabled = false;
                }
            } catch (error) {
                if (warningDisplay) {
                    warningDisplay.innerHTML = '';
                    warningDisplay.style.display = 'none';
                }
            }
        } else {
            if (warningDisplay) {
                warningDisplay.innerHTML = '';
                warningDisplay.style.display = 'none';
            }
        }
    });
    
    // 切换暴力破解方法
    methodRadios.forEach(radio => {
        radio.addEventListener('change', () => {
            if (radio.value === 'custom') {
                customContainer.style.display = 'block';
                document.getElementById('dictionary-description').style.display = 'none';
                document.getElementById('custom-description').style.display = 'block';
            } else {
                customContainer.style.display = 'none';
                document.getElementById('dictionary-description').style.display = 'block';
                document.getElementById('custom-description').style.display = 'none';
            }
        });
    });
    
    // 处理文件上传
    wordlistFile.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            fileNameDisplay.textContent = file.name;
            const reader = new FileReader();
            reader.onload = (e) => {
                customWordlist.value = e.target.result;
            };
            reader.readAsText(file);
        } else {
            fileNameDisplay.textContent = '';
        }
    });
    
    // 开始暴力破解
    startButton.addEventListener('click', async () => {
        const token = jwtInput.value.trim();
        if (!token) {
            showNotification('请输入JWT令牌', 'warning');
            return;
        }
        
        try {
            const decoded = jwtDecoder.decode(token);
            const algorithm = decoded.header.alg;
            
            // 检查算法是否支持暴力破解
            if (algorithm !== 'none' && !algorithm.startsWith('HS')) {
                if (warningDisplay) {
                    warningDisplay.innerHTML = `
                        <div class="warning-box">
                            <i class="fas fa-exclamation-triangle warning-icon"></i>
                            <div class="warning-content">
                                <strong>检测到非HMAC算法: ${algorithm}</strong>
                                <p>此令牌使用${algorithm}，不能使用此方法进行暴力破解。</p>
                                <p>只有HMAC算法(HS256, HS384, HS512)可以暴力破解，因为它们使用共享密钥。</p>
                                <p>${algorithm}使用非对称加密与公钥/私钥对，无法暴力破解。</p>
                                <p><a href="docs/tool-guides/secret-bruteforcer.html#limitations" target="_blank">了解更多关于算法限制的信息</a></p>
                            </div>
                        </div>
                    `;
                    warningDisplay.style.display = 'block';
                }
                showNotification(`无法暴力破解: 算法${algorithm}不支持暴力破解`, 'warning');
                return;
            }
        } catch (error) {
            // 解码失败，继续处理
        }
        
        // 获取暴力破解方法
        const method = document.querySelector('input[name="bruteforce-method"]:checked').value;
        
        // 初始化暴力破解器
        if (!jwtBruteforcer.init(token)) {
            if (jwtBruteforcer.nonHmacAlgorithmDetected) {
                const detectedAlgorithm = jwtBruteforcer.detectedAlgorithm;
                statusDisplay.textContent = `无法暴力破解: 算法${detectedAlgorithm}不支持`;
                resultDisplay.innerHTML = `
                    <div class="warning-box">
                        <i class="fas fa-exclamation-triangle warning-icon"></i>
                        <div class="warning-content">
                            <strong>检测到非HMAC算法: ${detectedAlgorithm}</strong>
                            <p>此令牌使用${detectedAlgorithm}，不能使用此方法进行暴力破解。</p>
                            <p>只有HMAC算法(HS256, HS384, HS512)可以暴力破解，因为它们使用共享密钥。</p>
                            <p>${detectedAlgorithm}使用非对称加密与公钥/私钥对，无法暴力破解。</p>
                            <p><a href="docs/tool-guides/secret-bruteforcer.html#limitations" target="_blank">了解更多关于算法限制的信息</a></p>
                        </div>
                    </div>
                `;
                resultDisplay.style.display = 'block';
                showNotification(`无法暴力破解: 算法${detectedAlgorithm}不支持暴力破解`, 'warning');
            } else {
                showNotification('初始化暴力破解器失败。请检查令牌是否有效。', 'error');
            }
            return;
        }
        
        // 设置自定义词表
        if (method === 'custom') {
            if (!customWordlist.value.trim()) {
                showNotification('请输入自定义词表', 'warning');
                return;
            }
            jwtBruteforcer.setCustomWordlist(customWordlist.value);
        }
        
        // 开始暴力破解
        startButton.disabled = true;
        stopButton.disabled = false;
        progressBar.style.width = '0%';
        progressText.textContent = '0%';
        statusDisplay.textContent = '暴力破解进行中...';
        resultDisplay.style.display = 'none';
        resultDisplay.textContent = '';
        
        jwtBruteforcer.start(method, (progress) => {
            progressBar.style.width = `${progress}%`;
            progressText.textContent = `${progress}%`;
        }, (result) => {
            if (result.success) {
                statusDisplay.textContent = '密钥已找到！';
                resultDisplay.textContent = `密钥: ${result.secret}`;
                resultDisplay.style.display = 'block';
                showNotification('密钥已找到！', 'success');
            } else {
                statusDisplay.textContent = result.error || '在词表中未找到匹配的密钥。';
                showNotification('暴力破解完成，未找到匹配项', 'error');
            }
            startButton.disabled = false;
            stopButton.disabled = true;
        });
    });
    
    // 停止暴力破解
    stopButton.addEventListener('click', () => {
        jwtBruteforcer.stop();
        statusDisplay.textContent = '暴力破解被用户停止。';
        startButton.disabled = false;
        stopButton.disabled = true;
        showNotification('暴力破解已停止', 'info');
    });
}

function initEditorTab() {
    const jwtInput = document.getElementById('editor-jwt-input');
    const loadButton = document.getElementById('load-jwt-btn');
    const headerEditor = document.getElementById('header-editor');
    const payloadEditor = document.getElementById('payload-editor');
    const algorithmSelect = document.getElementById('signature-algorithm');
    const secretKeyContainer = document.getElementById('secret-key-container');
    const rsaKeyContainer = document.getElementById('rsa-key-container');
    const secretKeyInput = document.getElementById('secret-key');
    const privateKeyInput = document.getElementById('private-key');
    const generateButton = document.getElementById('generate-edited-jwt-btn');
    const copyButton = document.getElementById('copy-edited-jwt-btn');
    const outputDisplay = document.getElementById('edited-jwt-output');
    
    // 监听算法选择变化
    algorithmSelect.addEventListener('change', () => {
        const algorithm = algorithmSelect.value;
        if (algorithm === 'none') {
            secretKeyContainer.style.display = 'none';
            rsaKeyContainer.style.display = 'none';
        } else if (algorithm.startsWith('HS')) {
            secretKeyContainer.style.display = 'block';
            rsaKeyContainer.style.display = 'none';
        } else if (algorithm.startsWith('RS')) {
            secretKeyContainer.style.display = 'none';
            rsaKeyContainer.style.display = 'block';
        }
    });
    
    // 加载JWT
    loadButton.addEventListener('click', () => {
        const token = jwtInput.value.trim();
        if (!token) {
            showNotification('请输入JWT令牌', 'warning');
            return;
        }
        
        try {
            const loaded = jwtEditor.loadToken(token);
            headerEditor.value = jwtEditor.getFormattedHeader();
            payloadEditor.value = jwtEditor.getFormattedPayload();
            algorithmSelect.value = loaded.header.alg || 'HS256';
            algorithmSelect.dispatchEvent(new Event('change'));
            showNotification('JWT加载成功', 'success');
        } catch (error) {
            showNotification(`错误: ${error.message}`, 'error');
        }
    });
    
    // 生成JWT
    generateButton.addEventListener('click', () => {
        try {
            jwtEditor.updateHeader(headerEditor.value);
            jwtEditor.updatePayload(payloadEditor.value);
            
            const algorithm = algorithmSelect.value;
            let token;
            
            if (algorithm === 'none') {
                token = jwtEditor.generateNoneToken();
            } else if (algorithm.startsWith('HS')) {
                if (!secretKeyInput.value) {
                    showNotification('请输入密钥', 'warning');
                    return;
                }
                token = jwtEditor.generateSymmetricToken(algorithm, secretKeyInput.value);
            } else if (algorithm.startsWith('RS')) {
                if (!privateKeyInput.value) {
                    showNotification('请输入私钥', 'warning');
                    return;
                }
                token = jwtEditor.generateAsymmetricToken(algorithm, privateKeyInput.value);
            }
            
            outputDisplay.textContent = token;
            showNotification('JWT生成成功', 'success');
        } catch (error) {
            showNotification(`错误: ${error.message}`, 'error');
        }
    });
    
    // 复制JWT
    copyButton.addEventListener('click', async () => {
        const token = outputDisplay.textContent;
        if (!token) {
            showNotification('没有JWT可复制', 'warning');
            return;
        }
        
        try {
            await copyToClipboard(token);
            showNotification('JWT已复制到剪贴板', 'success');
        } catch (error) {
            showNotification('复制到剪贴板失败', 'error');
        }
    });
}

function initGeneratorTab() {
    const headerEditor = document.getElementById('generator-header');
    const payloadEditor = document.getElementById('generator-payload');
    const claimButtons = document.querySelectorAll('.claim-btn');
    const algorithmSelect = document.getElementById('generator-algorithm');
    const secretKeyContainer = document.getElementById('generator-secret-key-container');
    const rsaKeyContainer = document.getElementById('generator-rsa-key-container');
    const secretKeyInput = document.getElementById('generator-secret-key');
    const privateKeyInput = document.getElementById('generator-private-key');
    const publicKeyDisplay = document.getElementById('generator-public-key');
    const publicKeySection = document.getElementById('public-key-display');
    const generateRsaKeysButton = document.getElementById('generate-rsa-keys-btn');
    const generateButton = document.getElementById('generate-new-jwt-btn');
    const copyButton = document.getElementById('copy-new-jwt-btn');
    const outputDisplay = document.getElementById('generated-jwt-output');
    
    // 重置为默认值
    jwtGenerator.resetToDefaults();
    headerEditor.value = jwtGenerator.getFormattedHeader();
    payloadEditor.value = jwtGenerator.getFormattedPayload();
    
    // 监听算法选择变化
    algorithmSelect.addEventListener('change', () => {
        const algorithm = algorithmSelect.value;
        if (algorithm === 'none') {
            secretKeyContainer.style.display = 'none';
            rsaKeyContainer.style.display = 'none';
        } else if (algorithm.startsWith('HS')) {
            secretKeyContainer.style.display = 'block';
            rsaKeyContainer.style.display = 'none';
        } else if (algorithm.startsWith('RS')) {
            secretKeyContainer.style.display = 'none';
            rsaKeyContainer.style.display = 'block';
        }
    });
    
    // 生成RSA密钥对
    generateRsaKeysButton.addEventListener('click', async () => {
        try {
            showNotification('正在生成RSA密钥对...', 'info', 2000);
            const keyPair = await generateRSAKeyPair(2048);
            privateKeyInput.value = keyPair.privateKey;
            publicKeyDisplay.value = keyPair.publicKey;
            publicKeySection.style.display = 'block';
            showNotification('RSA密钥对生成成功！', 'success');
        } catch (error) {
            showNotification(`错误: ${error.message}`, 'error');
        }
    });
    
    // 添加声明按钮
    claimButtons.forEach(button => {
        button.addEventListener('click', () => {
            const claim = button.getAttribute('data-claim');
            try {
                jwtGenerator.setPayload(payloadEditor.value);
                if (jwtGenerator.addClaim(claim)) {
                    payloadEditor.value = jwtGenerator.getFormattedPayload();
                    showNotification(`已添加${claim}声明`, 'success');
                } else {
                    showNotification(`声明${claim}已存在`, 'info');
                }
            } catch (error) {
                showNotification(`错误: ${error.message}`, 'error');
            }
        });
    });
    
    // 生成JWT
    generateButton.addEventListener('click', () => {
        try {
            jwtGenerator.setHeader(headerEditor.value);
            jwtGenerator.setPayload(payloadEditor.value);
            jwtGenerator.updateTimestamps();
            
            const algorithm = algorithmSelect.value;
            let token;
            
            if (algorithm === 'none') {
                token = jwtGenerator.generateToken('none');
            } else if (algorithm.startsWith('HS')) {
                if (!secretKeyInput.value) {
                    showNotification('请输入密钥', 'warning');
                    return;
                }
                token = jwtGenerator.generateToken(algorithm, secretKeyInput.value);
            } else if (algorithm.startsWith('RS')) {
                if (!privateKeyInput.value) {
                    showNotification('请输入私钥', 'warning');
                    return;
                }
                token = jwtGenerator.generateToken(algorithm, '', privateKeyInput.value);
            }
            
            outputDisplay.textContent = token;
            payloadEditor.value = jwtGenerator.getFormattedPayload();
            showNotification('JWT生成成功', 'success');
        } catch (error) {
            showNotification(`错误: ${error.message}`, 'error');
        }
    });
    
    // 复制JWT
    copyButton.addEventListener('click', async () => {
        const token = outputDisplay.textContent;
        if (!token) {
            showNotification('没有JWT可复制', 'warning');
            return;
        }
        
        try {
            await copyToClipboard(token);
            showNotification('JWT已复制到剪贴板', 'success');
        } catch (error) {
            showNotification('复制到剪贴板失败', 'error');
        }
    });
}