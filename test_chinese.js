/**
 * JWTAuditor 中文版测试脚本
 * 验证汉化功能是否正常工作
 */

// 测试通知功能
function testNotifications() {
    console.log("正在测试中文通知功能...");
    
    // 测试各种类型的通知
    showNotification('这是中文通知测试', 'info', 2000);
    showNotification('操作成功！', 'success', 2000);
    showNotification('请注意此警告', 'warning', 2000);
    showNotification('发生错误', 'error', 2000);
    
    console.log("通知功能测试完成");
}

// 测试JWT解码功能
function testJWTDecoding() {
    console.log("正在测试JWT解码功能...");
    
    // 使用一个示例JWT进行测试
    const sampleJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    
    try {
        const decoded = jwtDecoder.decode(sampleJWT);
        console.log("JWT解码成功:", decoded);
        console.log("头部:", decoded.header);
        console.log("载荷:", decoded.payload);
    } catch (error) {
        console.error("JWT解码失败:", error.message);
    }
    
    console.log("JWT解码功能测试完成");
}

// 测试JSON格式化功能
function testJSONFormatting() {
    console.log("正在测试JSON格式化功能...");
    
    const sampleJSON = {
        "name": "张三",
        "age": 30,
        "city": "北京",
        "timestamp": Math.floor(Date.now() / 1000)
    };
    
    const formatted = formatJSON(sampleJSON);
    console.log("JSON格式化结果:", formatted);
    
    console.log("JSON格式化功能测试完成");
}

// 运行所有测试
function runAllTests() {
    console.log("开始运行JWTAuditor中文版测试...");
    
    // 确保DOM加载完成后再运行测试
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            testNotifications();
            testJWTDecoding();
            testJSONFormatting();
        });
    } else {
        testNotifications();
        testJWTDecoding();
        testJSONFormatting();
    }
    
    console.log("所有测试已启动");
}

// 页面加载完成后运行测试
document.addEventListener('DOMContentLoaded', runAllTests);

// 也导出测试函数供手动调用
window.testNotifications = testNotifications;
window.testJWTDecoding = testJWTDecoding;
window.testJSONFormatting = testJSONFormatting;
window.runAllTests = runAllTests;