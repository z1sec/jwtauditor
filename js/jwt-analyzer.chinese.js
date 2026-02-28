/*!
 * JWTAuditor - JWT分析器模块 (中文版)
 * https://github.com/dr34mhacks/jwtauditor
 * Copyright (c) 2025 Sid Joshi (@dr34mhacks)
 * Licensed under Apache-2.0 License
 */

class JWTAnalyzer {
    constructor() {
        this.vulnerabilities = [];
        this.decoder = jwtDecoder;
        this.securitySummary = {
            totalIssues: 0,
            highSeverity: 0,
            mediumSeverity: 0,
            lowSeverity: 0,
            infoItems: 0
        };
    }

    analyze(token) {
        this.vulnerabilities = [];
        this.securitySummary = {
            totalIssues: 0,
            highSeverity: 0,
            mediumSeverity: 0,
            lowSeverity: 0,
            infoItems: 0
        };

        try {
            const decoded = this.decoder.decode(token);
            this.checkAlgorithmVulnerabilities();
            this.checkExpirationIssues();
            this.checkSensitiveData();
            this.checkMissingClaims();
            this.checkWeakSignature();
            this.checkSignaturePresence();
            this.checkBruteforceVulnerability();
            this.checkKidHeaderIssues();
            this.checkJwtIdIssues();
            this.checkAudienceIssues();
            this.checkReplayPotential();
            return this.vulnerabilities;
        } catch (error) {
            this.addVulnerability('JWT格式无效', 'high', 'JWT无法解码: ' + error.message, '确保JWT格式正确，由三个由点分隔的部分组成。');
            return this.vulnerabilities;
        }
    }

    checkAlgorithmVulnerabilities() {
        const algorithm = this.decoder.getAlgorithm();
        if (this.decoder.usesNoneAlgorithm()) {
            this.addVulnerability('无算法', 'high', 'JWT使用"none"算法，这意味着它没有签名。', '拒绝使用"none"算法的令牌，因为它们很容易伪造。 <a href="docs/jwt-vulnerabilities-guide.html#algorithm-none" target="_blank">了解有关无算法攻击的更多信息</a>');
        }

        if (algorithm === 'HS256') {
            this.addVulnerability('潜在的弱算法', 'medium', 'JWT使用HS256，如果使用了弱密钥，可能存在漏洞。', '考虑使用更强的算法，如HS384、HS512或非对称算法（RS256、ES256）。 <a href="docs/jwt-vulnerabilities-guide.html#weak-secrets" target="_blank">了解有关弱密钥的更多信息</a>');
        }

        if (this.decoder.usesSymmetricAlgorithm()) {
            this.addVulnerability('潜在的算法混淆', 'medium', 'JWT使用对称算法（HS*），如果服务器接受多种算法，可能容易受到算法混淆攻击。', '确保您的应用程序在验证之前显式验证算法，并拒绝意外的算法。 <a href="docs/jwt-vulnerabilities-guide.html#algorithm-confusion" target="_blank">了解有关算法混淆的更多信息</a>');
        }

        const insecureAlgorithms = ['HS1', 'RS1', 'ES1', 'PS1'];
        if (insecureAlgorithms.some(alg => algorithm && algorithm.startsWith(alg))) {
            this.addVulnerability('不安全的算法', 'high', 'JWT使用' + algorithm + '，这被认为是密码学上不安全的。', '使用现代、安全的算法，如HS256、RS256、ES256或PS256。');
        }
    }

    checkExpirationIssues() {
        const payload = this.decoder.payload;
        if (this.decoder.isExpired()) {
            this.addVulnerability('令牌过期', 'medium', '令牌已于过期时间过期。', '在您的应用程序中拒绝过期的令牌。');
        }

        if (!payload.exp) {
            this.addVulnerability('无过期时间', 'high', '令牌没有过期时间（exp声明），使其永久有效。', '始终在JWT中包含过期时间以限制其生命周期并减少令牌被盗的影响。 <a href="docs/jwt-vulnerabilities-guide.html#missing-claims" target="_blank">了解有关缺失声明的更多信息</a>');
        }

        if (payload.exp && payload.iat) {
            const lifetime = payload.exp - payload.iat;
            if (lifetime > 86400) {
                this.addVulnerability('长令牌生命周期', 'medium', '令牌的生命周期很长。', '考虑使用较短寿命的令牌（以小时代替天数）以减少令牌被盗的影响。');
            }
        }

        if (payload.nbf && payload.nbf > Math.floor(Date.now() / 1000)) {
            this.addVulnerability('令牌尚未有效', 'medium', '此令牌尚未到达生效时间。', '验证您的服务器和客户端时钟是否同步。');
        }
    }

    checkSensitiveData() {
        const payload = this.decoder.payload;
        const sensitivePatterns = [
            { name: '密码', regex: /pass(word)?/i },
            { name: '密钥', regex: /secret/i },
            { name: '凭证', regex: /credential/i },
            { name: '令牌', regex: /token/i },
            { name: '密钥', regex: /key/i },
            { name: '社会安全号码', regex: /ssn|social.*security/i },
            { name: '信用卡', regex: /credit.*card|card.*number|cc|credit_card/i },
            { name: 'API密钥', regex: /api.*key/i },
            { name: '认证', regex: /auth/i },
            { name: '私有', regex: /private/i },
            { name: '访问令牌', regex: /access.*token/i },
            { name: '刷新令牌', regex: /refresh.*token/i },
            { name: '会话', regex: /session/i }
        ];

        const foundSensitive = [];
        for (const pattern of sensitivePatterns) {
            for (const key in payload) {
                if (pattern.regex.test(key)) {
                    foundSensitive.push(key);
                }
            }
        }

        const piiFields = [
            'email', 'address', 'phone', 'dob', 'birthdate', 'birth_date', 'ssn', 'social_security',
            'passport', 'driver_license', 'license_number', 'national_id', 'tax_id', 'ip_address',
            'location', 'gps', 'coordinates', 'first_name', 'last_name', 'full_name', 'username', 'user_id'
        ];
        const foundPii = [];
        for (const field of piiFields) {
            for (const key in payload) {
                if (key.toLowerCase().includes(field.toLowerCase())) {
                    foundPii.push(key);
                }
            }
        }

        const ccPattern = /^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-5][0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})$/;
        const foundCc = [];
        for (const key in payload) {
            if (key.toLowerCase().includes('card') || key.toLowerCase().includes('cc') || key.toLowerCase().includes('credit')) {
                const value = String(payload[key]);
                const digits = value.replace(/[\s-]/g, '');
                if (ccPattern.test(digits) && digits.length >= 13 && digits.length <= 19) {
                    foundCc.push(key);
                }
            }
        }

        const privilegedRoles = ['admin', 'administrator', 'root', 'superuser', 'system'];
        const foundPrivileged = [];
        if (payload.role) {
            const role = String(payload.role).toLowerCase();
            if (privilegedRoles.includes(role)) {
                foundPrivileged.push(payload.role);
            }
        } else if (payload.roles && Array.isArray(payload.roles)) {
            for (const role of payload.roles) {
                const roleLower = String(role).toLowerCase();
                if (privilegedRoles.includes(roleLower)) {
                    foundPrivileged.push(role);
                }
            }
        }

        const payloadSize = JSON.stringify(payload).length;
        if (payloadSize > 1000) {
            this.addVulnerability('大型载荷', 'low', 'JWT载荷很大，相对较大。', '考虑最小化存储在JWT中的数据以提高性能并减少带宽使用。');
        }

        if (foundSensitive.length > 0) {
            this.addVulnerability('载荷中的敏感数据', 'high', 'JWT包含潜在的敏感数据: ' + foundSensitive.join(', '), '从JWT载荷中删除敏感信息，因为它是仅编码，而非加密的。将敏感数据存储在服务器端。 <a href="docs/jwt-vulnerabilities-guide.html#sensitive-data" target="_blank">了解有关JWT中敏感数据的更多信息</a>');
        }

        if (foundPii.length > 0) {
            this.addVulnerability('载荷中的个人身份信息', 'high', 'JWT包含个人身份信息（PII）: ' + foundPii.join(', '), '删除或最小化JWT载荷中的PII以符合GDPR和CCPA等隐私法规。将PII存储在服务器端。 <a href="docs/jwt-vulnerabilities-guide.html#sensitive-data" target="_blank">了解有关JWT中PII的更多信息</a>');
        }

        if (foundCc.length > 0) {
            this.addVulnerability('载荷中的信用卡数据', 'critical', 'JWT包含似乎是信用卡号码的字段: ' + foundCc.join(', '), '切勿在JWT中存储信用卡信息。这违反PCI DSS要求并构成严重的安全风险。 <a href="docs/jwt-vulnerabilities-guide.html#sensitive-data" target="_blank">了解有关敏感数据风险的更多信息</a>');
        }

        if (foundPrivileged.length > 0) {
            this.addVulnerability('敏感角色信息', 'medium', 'JWT包含敏感角色信息: ' + foundPrivileged.join(', '), '考虑在令牌中使用角色ID或更通用的角色描述，并在服务器端执行详细权限检查。');
        }

        if (Object.keys(payload).length > 15) {
            this.addVulnerability('过多声明', 'medium', 'JWT包含很多声明，这异常高。', '最小化JWT中的声明数量以减少令牌大小并限制不必要的数据暴露。');
        }
    }

    checkMissingClaims() {
        const payload = this.decoder.payload;
        const missing = [];
        if (!payload.iss) missing.push('iss (签发者)');
        if (!payload.sub) missing.push('sub (主题)');
        if (!payload.iat) missing.push('iat (签发时间)');
        if (!payload.jti) missing.push('jti (JWT ID)');
        if (!payload.aud) missing.push('aud (受众)');

        if (missing.length > 0) {
            this.addVulnerability('缺少推荐声明', 'medium', 'JWT缺少推荐声明: ' + missing.join(', '), '包含这些声明以提高安全性并防止令牌滥用、重放攻击和受众混淆。 <a href="docs/jwt-vulnerabilities-guide.html#missing-claims" target="_blank">了解有关重要JWT声明的更多信息</a>');
        }

        const emptyClaims = [];
        for (const [key, value] of Object.entries(payload)) {
            if (value === '' || value === null || (Array.isArray(value) && value.length === 0)) {
                emptyClaims.push(key);
            }
        }

        if (emptyClaims.length > 0) {
            this.addVulnerability('空声明', 'low', 'JWT包含空声明: ' + emptyClaims.join(', '), '删除空声明或提供有意义的值以避免潜在的验证问题。');
        }
    }

    checkWeakSignature() {
        const algorithm = this.decoder.getAlgorithm();
        const signature = this.decoder.signature;

        if (signature && signature.length < 10 && algorithm !== 'none') {
            this.addVulnerability('可疑的短签名', 'high', '令牌签名可疑地短，这可能表明签名较弱或已损坏。', '验证您的签名过程是否使用强密钥。 <a href="docs/jwt-vulnerabilities-guide.html#weak-secrets" target="_blank">了解有关弱签名的更多信息</a>');
        }

        if (algorithm && algorithm.startsWith('HS')) {
            const expectedLengths = { HS256: 40, HS384: 60, HS512: 80 };
            const expected = expectedLengths[algorithm] || 40;
            if (signature && signature.length < expected) {
                this.addVulnerability('潜在的弱签名', 'medium', '签名长度比较短', '确保为所选算法使用足够强的秘密密钥。 <a href="docs/jwt-vulnerabilities-guide.html#weak-secrets" target="_blank">了解有关签名强度的更多信息</a>');
            }
        }
    }

    checkSignaturePresence() {
        const signature = this.decoder.signature;
        const algorithm = this.decoder.getAlgorithm();

        if (algorithm !== 'none' && (!signature || signature.length === 0)) {
            this.addVulnerability('缺少签名', 'high', 'JWT声称使用算法但没有签名。', '确保令牌正确签名。拒绝缺少签名的令牌。');
        }
    }

    checkBruteforceVulnerability() {
        if (this.decoder.usesSymmetricAlgorithm()) {
            this.addVulnerability('潜在的暴力破解漏洞', 'medium', '此JWT使用对称算法（HS*），如果使用了弱密钥，可能容易受到密钥暴力破解攻击。', '使用强、高熵秘密密钥（至少32个随机字节），并考虑使用密钥暴力破解器工具测试您的令牌是否使用常见密钥。 <a href="docs/jwt-vulnerabilities-guide.html#weak-secrets" target="_blank">了解有关弱密钥攻击的更多信息</a>');
            this.addVulnerability('建议暴力破解测试', 'info', '您应该使用密钥暴力破解器工具测试此令牌是否使用弱密钥。', '点击"⚡ 密钥暴力破解"标签页或使用下方的"测试弱密钥"按钮，使用常见密钥和词表测试此令牌。');
        }
    }

    checkKidHeaderIssues() {
        const header = this.decoder.header;
        if (header && header.kid) {
            const sqlPatterns = ["'", '"', ';', '--', '/*', '*/', '=', ' OR ', ' AND ', 'UNION', 'SELECT', 'DROP', 'INSERT', 'DELETE', 'UPDATE'];
            let hasSqlInjection = false;
            let foundSqlPatterns = [];

            for (const pattern of sqlPatterns) {
                const upperPattern = pattern.trim().toUpperCase();
                const kidUpper = header.kid.toUpperCase();
                if (upperPattern === "'" || upperPattern === '"' || upperPattern === ';' || upperPattern === '--') {
                    if (header.kid.includes(pattern)) {
                        hasSqlInjection = true;
                        foundSqlPatterns.push(pattern);
                    }
                } else if (upperPattern === ' OR ' || upperPattern === ' AND ') {
                    if (kidUpper.includes(upperPattern) || kidUpper.includes(upperPattern.trim() + ' ') || kidUpper.includes(' ' + upperPattern.trim())) {
                        hasSqlInjection = true;
                        foundSqlPatterns.push(pattern.trim());
                    }
                } else {
                    if (kidUpper.includes(' ' + upperPattern + ' ') || kidUpper.startsWith(upperPattern + ' ') || kidUpper.endsWith(' ' + upperPattern) || kidUpper === upperPattern) {
                        hasSqlInjection = true;
                        foundSqlPatterns.push(pattern);
                    }
                }
            }

            if (hasSqlInjection) {
                this.addVulnerability('kid头部中的SQL注入', 'high', 'kid头部参数包含SQL注入模式: ' + foundSqlPatterns.join(', '), '在将kid参数用于数据库查询之前验证和清理。拒绝带有可疑kid值的令牌。 <a href="docs/jwt-vulnerabilities-guide.html#kid-injection" target="_blank">了解有关kid注入攻击的更多信息</a>');
            }

            const traversalPatterns = ['../', '..\\', '%2e%2e%2f', '%2e%2e/', '..%2f', '%252e%252e%252f'];
            let hasTraversal = false;
            let foundTraversal = [];

            for (const pattern of traversalPatterns) {
                if (header.kid.toLowerCase().includes(pattern.toLowerCase())) {
                    hasTraversal = true;
                    foundTraversal.push(pattern);
                }
            }

            if (hasTraversal) {
                this.addVulnerability('kid头部中的路径遍历', 'high', 'kid头部参数包含目录遍历序列: ' + foundTraversal.join(', '), '验证kid参数，切勿在文件系统操作中直接使用它。拒绝带有路径遍历尝试的令牌。 <a href="docs/jwt-vulnerabilities-guide.html#kid-injection" target="_blank">了解有关kid路径遍历攻击的更多信息</a>');
            }

            const cmdPatterns = ['|', '&', ';', '`', '$', '(', ')', ' rm ', ' cat ', 'bash', ' sh ', '/bin/', ' wget ', ' curl ', ' > ', ' >> '];
            let hasCmdInjection = false;
            let foundCmd = [];

            for (const pattern of cmdPatterns) {
                if (header.kid.toLowerCase().includes(pattern.toLowerCase())) {
                    hasCmdInjection = true;
                    foundCmd.push(pattern);
                }
            }

            if (hasCmdInjection) {
                this.addVulnerability('kid头部中的命令注入', 'high', 'kid头部参数包含命令注入模式: ' + foundCmd.join(', '), '在将kid参数用于任何命令或系统操作之前验证和清理。拒绝带有可疑kid值的令牌。 <a href="docs/jwt-vulnerabilities-guide.html#kid-injection" target="_blank">了解有关kid命令注入的更多信息</a>');
            }

            if (header.kid.length > 100) {
                this.addVulnerability('过长的kid头部', 'medium', 'kid头部参数异常长', '限制kid参数的长度以防止潜在的缓冲区溢出攻击和性能问题。 <a href="docs/jwt-vulnerabilities-guide.html#kid-injection" target="_blank">了解有关kid头部安全的更多信息</a>');
            }
        }
    }

    checkJwtIdIssues() {
        const payload = this.decoder.payload;
        if (!payload.jti) {
            this.addVulnerability('缺少JWT ID', 'medium', '令牌没有JWT ID（jti声明），这使得实现令牌撤销更加困难。', '包含唯一的jti声明以启用令牌撤销并防止重放攻击。 <a href="docs/jwt-vulnerabilities-guide.html#replay-attacks" target="_blank">了解有关重放攻击预防的更多信息</a>');
        } else {
            const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
            const highEntropyPattern = payload.jti.length >= 16 && /[a-zA-Z0-9_-]{16,}/.test(payload.jti);

            if (payload.jti.length < 8) {
                this.addVulnerability('非常弱的JWT ID', 'high', 'JWT ID太短并且缺乏足够的熵。', '使用UUID或其他高熵值（至少16个字符）作为jti声明，以确保唯一性并防止令牌伪造。');
            } else if (!uuidPattern.test(payload.jti) && !highEntropyPattern) {
                this.addVulnerability('潜在的弱JWT ID', 'medium', 'JWT ID可能没有足够的随机性或唯一性。', '为jti声明使用UUID或其他高熵值以确保唯一性。');
            }

            if (/^[0-9]+$/.test(payload.jti)) {
                this.addVulnerability('顺序JWT ID', 'high', 'JWT ID似乎是顺序数字，这是可预测的。', '使用不可预测的随机值作为JWT ID以防止令牌枚举攻击。');
            }
        }
    }

    checkAudienceIssues() {
        const payload = this.decoder.payload;
        if (!payload.aud) {
            this.addVulnerability('缺少受众', 'medium', '令牌没有受众（aud声明），这对于限制令牌可用位置很重要。', '包含特定的受众声明以防止令牌被无意的服务接受。 <a href="docs/jwt-vulnerabilities-guide.html#missing-claims" target="_blank">了解有关受众验证的更多信息</a>');
            return;
        }

        const genericAudiences = ['all', 'any', 'public', 'everyone', '*', 'api', 'service', 'users', 'app'];
        const wildcardPatterns = ['*', '.*', '.+'];

        if (typeof payload.aud === 'string') {
            if (genericAudiences.includes(payload.aud.toLowerCase())) {
                this.addVulnerability('过于通用的受众', 'high', '受众声明太通用，这降低了受众验证的安全效益。', '使用特定的受众值来标识令牌的预期接收者。');
            }

            if (wildcardPatterns.some(pattern => payload.aud.includes(pattern))) {
                this.addVulnerability('受众中的通配符', 'high', '受众声明包含通配符字符，这可能允许无意的服务接受令牌。', '避免在受众声明中使用通配符。使用特定的、完全限定的标识符。');
            }

            if (payload.aud.length < 3 && !wildcardPatterns.includes(payload.aud)) {
                this.addVulnerability('非常短的受众', 'medium', '受众声明非常短，可能没有提供足够的特异性。', '使用更长、更具体的受众标识符以正确限制令牌使用。');
            }
        } else if (Array.isArray(payload.aud)) {
            if (payload.aud.length > 5) {
                this.addVulnerability('多个受众', 'medium', '令牌有很多受众，这可能表示过度宽松的访问。', '限制受众数量仅为真正需要接受此令牌的服务。');
            }

            const genericValues = payload.aud.filter(item => typeof item === 'string' && genericAudiences.includes(item.toLowerCase())).map(item => item);
            if (genericValues.length > 0) {
                this.addVulnerability('通用受众值', 'high', '受众声明包含通用值: ' + genericValues.join(', '), '使用特定的受众值来标识令牌的预期接收者。');
            }

            const wildcardValues = payload.aud.filter(item => typeof item === 'string' && wildcardPatterns.some(pattern => item.includes(pattern))).map(item => item);
            if (wildcardValues.length > 0) {
                this.addVulnerability('受众值中的通配符', 'high', '受众声明包含通配符模式: ' + wildcardValues.join(', '), '避免在受众声明中使用通配符。使用特定的、完全限定的标识符。');
            }
        } else {
            this.addVulnerability('无效的受众格式', 'medium', '受众声明具有无效格式', '受众声明应该是字符串或字符串数组。');
        }
    }

    checkReplayPotential() {
        const payload = this.decoder.payload;
        if (!payload.jti && payload.exp) {
            const now = Math.floor(Date.now() / 1000);
            const remainingTime = payload.exp - now;
            if (remainingTime > 3600) { // More than 1 hour
                this.addVulnerability('重放攻击漏洞', 'medium', '此令牌缺少JWT ID并且有过长的过期时间，使其容易受到重放攻击。', '添加唯一的jti声明并实施服务器端令牌跟踪以防止重放攻击。 <a href="docs/jwt-vulnerabilities-guide.html#replay-attacks" target="_blank">了解有关重放攻击预防的更多信息</a>');
            }
        }
    }

    addVulnerability(title, severity, description, recommendation) {
        this.vulnerabilities.push({
            title: title,
            severity: severity,
            description: description,
            recommendation: recommendation
        });
        this.securitySummary.totalIssues++;

        switch (severity) {
            case 'critical':
                this.securitySummary.highSeverity++;
                break;
            case 'high':
                this.securitySummary.highSeverity++;
                break;
            case 'medium':
                this.securitySummary.mediumSeverity++;
                break;
            case 'low':
                this.securitySummary.lowSeverity++;
                break;
            case 'info':
                this.securitySummary.infoItems++;
                break;
        }
    }

    getVulnerabilitiesHTML() {
        if (this.vulnerabilities.length === 0) {
            return `<div class="vulnerability none"><h3><i class="fas fa-check-circle"></i> 未检测到漏洞</h3><p>在此JWT中未发现明显安全问题。</p><p>注意：这并不能保证令牌是安全的。始终遵循JWT处理的最佳实践。</p></div>`;
        }

        // Sort vulnerabilities by severity
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4, none: 5 };
        this.vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

        const criticalCount = this.vulnerabilities.filter(vuln => vuln.severity === 'critical').length;
        const summaryHTML = `<div class="analysis-summary">
            <h3><i class="fas fa-chart-pie"></i> 安全分析摘要</h3>
            <div class="summary-stats">
                ${criticalCount > 0 ? `<div class="stat-item critical"><span class="stat-count">${criticalCount}</span><span class="stat-label">严重</span></div>` : ''}
                <div class="stat-item high"><span class="stat-count">${this.securitySummary.highSeverity}</span><span class="stat-label">高危</span></div>
                <div class="stat-item medium"><span class="stat-count">${this.securitySummary.mediumSeverity}</span><span class="stat-label">中危</span></div>
                <div class="stat-item low"><span class="stat-count">${this.securitySummary.lowSeverity}</span><span class="stat-label">低危</span></div>
                <div class="stat-item info"><span class="stat-count">${this.securitySummary.infoItems}</span><span class="stat-label">信息</span></div>
            </div>
            ${this.getSecurityRecommendationHTML()}
        </div>`;

        const vulnerabilitiesHTML = this.vulnerabilities.map(vuln => {
            let icon = '';
            switch (vuln.severity) {
                case 'critical':
                    icon = '<i class="fas fa-skull-crossbones"></i>';
                    break;
                case 'high':
                    icon = '<i class="fas fa-exclamation-triangle"></i>';
                    break;
                case 'medium':
                    icon = '<i class="fas fa-exclamation-circle"></i>';
                    break;
                case 'low':
                    icon = '<i class="fas fa-info-circle"></i>';
                    break;
                case 'info':
                    icon = '<i class="fas fa-lightbulb"></i>';
                    break;
                default:
                    icon = '<i class="fas fa-check-circle"></i>';
            }
            return `<div class="vulnerability ${vuln.severity}">
                <h3>${icon} ${vuln.title}</h3>
                <p><strong>严重程度:</strong> ${vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1)}</p>
                <p><strong>描述:</strong> ${vuln.description}</p>
                <p><strong>建议:</strong> ${vuln.recommendation}</p>
            </div>`;
        }).join('');

        return summaryHTML + vulnerabilitiesHTML;
    }

    getSecurityRecommendationHTML() {
        if (this.securitySummary.highSeverity > 0) {
            return `<div class="security-recommendation critical"><i class="fas fa-shield-alt"></i><div><strong>检测到严重安全问题！</strong><p>此令牌有严重安全漏洞，应立即解决。</p></div></div>`;
        } else if (this.securitySummary.mediumSeverity > 0) {
            return `<div class="security-recommendation warning"><i class="fas fa-shield-alt"></i><div><strong>需要安全改进</strong><p>此令牌有安全问题，应解决以改善其安全态势。</p></div></div>`;
        } else if (this.securitySummary.lowSeverity > 0 || this.securitySummary.infoItems > 0) {
            return `<div class="security-recommendation info"><i class="fas fa-shield-alt"></i><div><strong>检测到小问题</strong><p>此令牌有小问题或可从遵循最佳实践中受益。</p></div></div>`;
        } else {
            return `<div class="security-recommendation good"><i class="fas fa-shield-alt"></i><div><strong>未检测到问题</strong><p>此令牌似乎遵循安全最佳实践。</p></div></div>`;
        }
    }
}

const jwtAnalyzer = new JWTAnalyzer;