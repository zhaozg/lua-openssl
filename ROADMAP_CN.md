# lua-openssl 开发路线图

**文档版本:** 1.0  
**创建日期:** 2025-11-10  
**状态:** 积极规划中  

## 概述

本路线图为 lua-openssl 开发提供结构化计划，按优先级、难度和影响范围组织。该计划基于全面的代码审查分析，旨在保持向后兼容性和现有接口习惯的前提下实现代码现代化。

**相关文档:**
- [DEPRECATION_STATUS.md](./DEPRECATION_STATUS.md) - 废弃警告状态
- [ROADMAP.md](./ROADMAP.md) - 完整英文路线图

---

## 快速参考

### 优先级
- 🔴 **紧急** - 需要立即处理的安全/稳定性问题
- 🟠 **高** - 影响众多用户的重要功能/修复
- 🟡 **中** - 具有中等影响的改进
- 🟢 **低** - 未来考虑的功能

### 难度
- ⭐ **简单** (1-3天)
- ⭐⭐ **中等** (3-7天)
- ⭐⭐⭐ **困难** (1-3周)
- ⭐⭐⭐⭐ **非常困难** (1-3个月)

### 影响范围
- 🎯 **高影响** - 影响核心功能或众多用户
- 🎯🎯 **中等影响** - 改进特定功能
- 🎯🎯🎯 **低影响** - 小众功能或微小改进

---

## 第一阶段：立即行动 (0-1个月)

### 1.1 错误处理审计
**优先级:** 🔴 紧急 | **难度:** ⭐⭐ 中等 (5-7天) | **影响:** 🎯 高

**任务:**
- [ ] 审计所有 `src/*.c` 中的错误路径，确保正确释放资源
- [ ] 使用静态分析工具 (Valgrind, AddressSanitizer)
- [ ] 修复已识别的内存泄漏
- [ ] 添加错误注入测试
- [ ] 为贡献者编写错误处理模式文档

**关键文件:** `src/digest.c`, `src/pkey.c` 等所有有资源分配的模块

**成功标准:** Valgrind 检测零内存泄漏，所有错误路径正确清理

---

### 1.2 文档增强
**优先级:** 🟠 高 | **难度:** ⭐ 简单 (2-3天) | **影响:** 🎯 高

**任务:**
- [x] 创建 ROADMAP.md 文档
- [x] 创建 ROADMAP_CN.md 中文文档
- [ ] 创建 COMPATIBILITY.md 版本兼容性矩阵
- [ ] 添加 MIGRATION.md 版本升级指南
- [ ] 更新 API 文档，标注版本要求
- [ ] 标记废弃函数并提供替代方案

**成功标准:** 完整的版本兼容性矩阵，主要 OpenSSL 版本的迁移指南

---

### 1.3 CI/CD 增强
**优先级:** 🟠 高 | **难度:** ⭐ 简单 (2-3天) | **影响:** 🎯 高

**任务:**
- [ ] 添加静态分析 (cppcheck, clang-tidy)
- [ ] 添加内存泄漏检测 (Valgrind)
- [ ] 添加代码覆盖率报告 (gcov/lcov)
- [ ] 添加废弃警告检查
- [ ] 扩展 OpenSSL 版本构建矩阵

**成功标准:** CI 自动检测内存泄漏，在 OpenSSL 1.0.2, 1.1.1, 3.0.x, 3.6.x 上构建成功

---

## 第二阶段：短期目标 (1-3个月)

### 2.1 现代签名算法 - Ed25519/Ed448
**优先级:** 🟠 高 | **难度:** ⭐⭐ 中等 (5-7天) | **影响:** 🎯 高

**原因:** Ed25519 是现代数字签名标准，比 RSA 更快，密钥更小，是 SSH、TLS 1.3 等协议的要求

**任务:**
- [ ] 实现 Ed25519 密钥生成
- [ ] 实现 Ed25519 签名/验证
- [ ] 实现 Ed448 支持
- [ ] 添加 PEM/DER 导入/导出
- [ ] 创建测试套件 `test/eddsa.lua`
- [ ] 在 README 中添加使用示例

**API 设计:**
```lua
-- 密钥生成
local ed25519_key = openssl.pkey.new('ed25519')

-- 签名
local signature = ed25519_key:sign("Hello, world!")

-- 验证
local verified = ed25519_key:verify("Hello, world!", signature)
assert(verified == true)
```

**成功标准:** Ed25519 和 Ed448 完全功能，与 OpenSSL 命令行工具兼容

---

### 2.2 现代密钥交换 - X25519/X448
**优先级:** 🟠 高 | **难度:** ⭐⭐ 中等 (3-5天) | **影响:** 🎯 高

**原因:** X25519 是 TLS 1.3 的默认密钥交换算法，比传统 ECDH 更高效

**API 设计:**
```lua
-- 密钥交换示例
local alice = openssl.pkey.new('x25519')
local bob = openssl.pkey.new('x25519')

-- 派生共享密钥
local alice_secret = alice:derive(bob:get_public())
local bob_secret = bob:derive(alice:get_public())

assert(alice_secret == bob_secret)
```

**成功标准:** X25519 和 X448 密钥交换工作正常，与现有 ECDH API 兼容

---

### 2.3 ChaCha20-Poly1305 验证和文档
**优先级:** 🟡 中 | **难度:** ⭐ 简单 (2-3天) | **影响:** 🎯🎯 中等

**原因:** ChaCha20-Poly1305 广泛用于 TLS、QUIC，在移动设备上性能优于 AES-GCM

**任务:**
- [ ] 验证当前代码中的 ChaCha20-Poly1305 支持
- [ ] 创建全面的测试套件
- [ ] 添加类似 AES-GCM 示例的使用示例
- [ ] 文档化性能特征

**成功标准:** ChaCha20-Poly1305 完全测试，README 中有示例代码

---

### 2.4 高级密码哈希 API
**优先级:** 🟠 高 | **难度:** ⭐⭐ 中等 (3-5天) | **影响:** 🎯 高

**原因:** 密码哈希是非常常见的用例，当前 KDF API 较低级且复杂，用户需要简单、安全的默认值

**API 设计:**
```lua
local openssl = require('openssl')

-- 使用良好默认值的简单密码哈希
local hashed = openssl.password.hash('mypassword')

-- 自定义参数
local hashed2 = openssl.password.hash('mypassword', {
  algorithm = 'pbkdf2',  -- 或 'scrypt'
  hash = 'sha256',
  iterations = 100000,
  salt_length = 16
})

-- 验证
local valid = openssl.password.verify('mypassword', hashed)
assert(valid == true)
```

**成功标准:** 简单、安全的密码哈希 API，自动盐生成，清晰的安全警告文档

---

### 2.5 OpenSSL 3.0 OSSL_PARAM API 绑定
**优先级:** 🟠 高 | **难度:** ⭐⭐⭐ 困难 (7-10天) | **影响:** 🎯 高

**原因:** OSSL_PARAM 是 OpenSSL 3.0+ 访问密钥参数的现代方式，是未来 Provider API 使用的基础

**任务:**
- [ ] 研究 OSSL_PARAM API
- [ ] 设计 OSSL_PARAM 的 Lua 绑定
- [ ] 实现参数创建/访问
- [ ] 迁移 RSA 密钥访问使用 OSSL_PARAM
- [ ] 添加 OpenSSL 1.x vs 3.x 的条件编译
- [ ] 创建全面测试

**成功标准:** Lua 可访问 OSSL_PARAM，RSA/EC 密钥参数在 OpenSSL 3.0+ 上工作，保持与 OpenSSL 1.1.x 的向后兼容性

---

## 第三阶段：中期目标 (3-6个月)

### 3.1 可获取对象 API (OpenSSL 3.0)
**优先级:** 🟡 中 | **难度:** ⭐⭐ 中等 (5-7天) | **影响:** 🎯🎯 中等

**原因:** OpenSSL 3.0 引入"可获取"算法，允许指定提供者和属性，启用 FIPS 模式和自定义提供者

**API 设计:**
```lua
-- 从默认提供者获取
local sha256 = openssl.digest.fetch('SHA256')

-- 从特定提供者获取
local fips_sha256 = openssl.digest.fetch('SHA256', {
  provider = 'fips',
  properties = 'fips=yes'
})
```

**成功标准:** 可获取 API 在 OpenSSL 3.0+ 上工作，提供者选择功能正常

---

### 3.2 Provider API 支持 (OpenSSL 3.0)
**优先级:** 🟡 中 | **难度:** ⭐⭐⭐ 困难 (10-15天) | **影响:** 🎯🎯 中等

**原因:** Provider API 是 OpenSSL 3.0 中 ENGINE API 的替代品，支持硬件加速和自定义提供者

**API 设计:**
```lua
-- 加载提供者
local provider = openssl.provider.load('fips')

-- 查询提供者信息
print(provider:name())     -- "fips"
print(provider:status())   -- "active"

-- 列出提供者的算法
local algorithms = provider:query('digest')
```

**成功标准:** 提供者加载/卸载工作，算法查询功能正常，ENGINE 到 Provider 的迁移指南完成

---

### 3.3 KDF 模块增强
**优先级:** 🟡 中 | **难度:** ⭐⭐ 中等 (5-7天) | **影响:** 🎯🎯 中等

**当前状态:**
- ✅ PBKDF2 已实现
- ✅ HKDF 已实现
- ❓ scrypt 需要验证
- ❓ TLS 1.3 KDF 需要验证

**统一 API 设计:**
```lua
-- PBKDF2
local key = openssl.kdf.derive({
  type = 'pbkdf2',
  password = 'secret',
  salt = salt,
  iterations = 100000,
  hash = 'sha256',
  length = 32
})

-- scrypt
local key = openssl.kdf.derive({
  type = 'scrypt',
  password = 'secret',
  salt = salt,
  N = 32768,
  r = 8,
  p = 1,
  length = 32
})
```

**成功标准:** 所有 KDF 算法验证和测试，统一 API 实现，文档完整

---

### 3.4 Base64URL 编码支持
**优先级:** 🟡 中 | **难度:** ⭐ 简单 (1-2天) | **影响:** 🎯🎯 中等

**原因:** Base64URL 是 JWT、JWE 和现代 Web API 所需，与标准 Base64 不同（无填充，不同字符）

**API 设计:**
```lua
-- Base64URL (URL安全，无填充)
local b64url = openssl.base64url('Hello, world!')
-- 返回: SGVsbG8sIHdvcmxkIQ

-- 解码
local decoded = openssl.base64url_decode(b64url)
```

**成功标准:** Base64URL 编码/解码正确工作，与 JWT 库兼容

---

### 3.5 剩余废弃警告解决
**优先级:** 🟡 中 | **难度:** ⭐⭐⭐ 困难 (15-20天) | **影响:** 🎯🎯 中等

**当前状态:**
- ✅ DH、DSA、SRP、HMAC、Digest、ENGINE 模块已更新
- ⚠️ PKEY 模块：还有 127 个警告
- ⚠️ RSA 模块：还有 44 个警告

**策略:**
1. 识别关键路径函数
2. 尽可能迁移到 EVP API
3. 使用条件编译确保版本兼容性
4. 保留废弃 API 并加功能标志用于传统支持
5. 为用户记录迁移路径

**成功标准:** 显著减少废弃警告，无功能回归，保持向后兼容性

---

## 第四阶段：长期目标 (6-12个月)

### 4.1 QUIC 协议支持
**优先级:** 🟡 中 | **难度:** ⭐⭐⭐⭐ 非常困难 (15-20天) | **影响:** 🎯🎯 中等

**前提条件:** OpenSSL 3.2.0 或更高版本

**原因:** QUIC 是 HTTP/3 的传输协议，在 Web 服务中采用率不断增长

**API 设计（初步）:**
```lua
-- 创建 QUIC 连接
local ctx = openssl.ssl.ctx_new('QUIC')
local quic = openssl.quic.new(ctx)

-- 连接到服务器
quic:connect('example.com:443')

-- 创建流
local stream = quic:stream_new()
stream:write('GET / HTTP/3.0\r\n\r\n')
local response = stream:read()
```

**成功标准:** 基本 QUIC 客户端功能工作，与 OpenSSL 3.2+ QUIC API 兼容

---

### 4.2 JWE/JOSE 支持
**优先级:** 🟢 低 | **难度:** ⭐⭐⭐⭐ 非常困难 (20+天) | **影响:** 🎯🎯🎯 低

**考虑因素:** 可能最好作为单独的模块/包，需要 JSON 库集成

**决策点:** 评估是否应该：
1. 作为 lua-openssl 的一部分（更紧密的集成）
2. 单独模块（lua-openssl-jose）
3. 留给第三方实现

---

### 4.3 后量子密码学
**优先级:** 🟢 低 | **难度:** ⭐⭐⭐⭐ 非常困难 (25+天) | **影响:** 🎯🎯🎯 低

**状态:** 高度实验性，取决于 OpenSSL PQC 采用

**原因:** 为后量子威胁做准备，NIST 已标准化 ML-KEM 和 ML-DSA

**时间表:**
- 取决于 OpenSSL 生态系统成熟度
- 生产就绪可能在 2026-2027 年
- 监控 NIST PQC 标准化进展

---

### 4.4 性能优化
**优先级:** 🟡 中 | **难度:** ⭐⭐⭐ 困难 (10-15天) | **影响:** 🎯🎯 中等

**优化领域:**

1. **批量操作:**
```lua
-- 批量操作（单次 C 调用）
local hashes = md:digest_batch(data)
```

2. **零拷贝操作:**
```lua
-- 使用 lightuserdata 处理大缓冲区
local buffer = openssl.buffer.new(1024 * 1024)
cipher:encrypt_into(buffer, data)
```

3. **流式操作:**
```lua
-- 高效流式处理，无中间缓冲区
local ctx = cipher:encrypt_new()
for chunk in file:chunks() do
  ctx:update(chunk)
end
```

**成功标准:** 常见操作性能提升 20%+，建立基准套件

---

## 第五阶段：持续改进

### 5.1 测试覆盖率增强
**优先级:** 🟠 高（持续）| **难度:** ⭐⭐ 中等 | **影响:** 🎯 高

**当前状态:** 177 个测试通过，基础覆盖良好，需要更多边界情况

**任务:**
- [ ] 将测试覆盖率提高到 80%+
- [ ] 添加边界情况测试
- [ ] 添加错误路径测试
- [ ] 添加性能基准测试
- [ ] 添加多版本兼容性测试
- [ ] 集成覆盖率报告

**成功标准:** 80%+ 代码覆盖率，所有关键路径测试，自动回归检测

---

### 5.2 安全审计流程
**优先级:** 🔴 紧急（持续）| **难度:** ⭐⭐⭐ 困难 | **影响:** 🎯 高

**原因:** 加密代码需要最高安全标准，定期审计防止漏洞

**任务:**
- [ ] 建立安全审计计划（季度）
- [ ] 监控 OpenSSL CVE
- [ ] 设置自动依赖扫描
- [ ] 创建安全响应流程
- [ ] 记录安全最佳实践
- [ ] 建立负责任的披露流程

**审计领域:**
- 内存安全：缓冲区溢出、use-after-free、内存泄漏
- 加密安全：弱算法使用、不安全默认值、侧信道漏洞
- API 安全：输入验证、错误处理、资源耗尽

**成功标准:** 定期进行安全审计，无严重漏洞，CVE 响应时间 < 48 小时

---

### 5.3 文档维护
**优先级:** 🟠 高（持续）| **难度:** ⭐ 简单 | **影响:** 🎯 高

**当前状态:** 93.1% 函数已文档化（LDoc），97.9% LDoc 注释有效

**任务:**
- [ ] 保持文档与代码同步
- [ ] 添加更多使用示例
- [ ] 创建常见任务教程
- [ ] 改进 API 参考完整性
- [ ] 添加故障排除指南
- [ ] 维护 CHANGELOG.md

**成功标准:** 所有新函数已文档化，所有主要功能有示例

---

## 实现指南

### 一般原则

1. **向后兼容优先**
   - 维护现有 API 行为
   - 新功能作为可选添加
   - 带警告的渐进式废弃
   - 提供迁移路径

2. **默认安全**
   - 使用安全的默认值
   - 警告不安全选项
   - 记录安全影响
   - 遵循最佳实践

3. **版本兼容性**
   - 支持 OpenSSL 1.0.2+
   - 使用条件编译
   - 跨版本测试
   - 记录版本要求

4. **代码质量**
   - 遵循现有代码风格（clang-format）
   - 添加全面测试
   - 记录所有更改
   - 通过静态分析

5. **用户体验**
   - 常见任务的简单 API
   - 清晰的错误消息
   - 有用的示例
   - 完整的文档

---

## 指标和成功跟踪

### 关键绩效指标（KPI）

1. **代码质量:**
   - 测试覆盖率 > 80%
   - 零内存泄漏（Valgrind）
   - 零安全漏洞
   - 静态分析警告 < 10

2. **兼容性:**
   - 支持 OpenSSL 1.0.2 - 3.6.x
   - 支持 Lua 5.1 - 5.4 + LuaJIT
   - 支持 LibreSSL 3.3.6+
   - 所有版本上所有测试通过

3. **文档:**
   - API 文档 > 95%
   - 所有主要功能有示例
   - 迁移指南可用
   - 安全最佳实践已记录

4. **社区:**
   - 问题响应时间 < 48 小时
   - PR 审查时间 < 7 天
   - 活跃贡献者增长
   - 积极的社区反馈

### 里程碑

**2025 年第一季度（第一阶段完成）:**
- [ ] 错误处理审计完成
- [ ] 文档改进
- [ ] CI/CD 增强
- [ ] 安全流程建立

**2025 年第二季度（第二阶段完成）:**
- [ ] Ed25519/Ed448 实现
- [ ] X25519/X448 实现
- [ ] 密码哈希 API 完成
- [ ] OSSL_PARAM API 可用

**2025 年第三-四季度（第三阶段完成）:**
- [ ] Provider API 支持
- [ ] KDF 模块增强
- [ ] 可获取对象 API
- [ ] 废弃警告解决

**2026+ 年（第四阶段+）:**
- [ ] QUIC 支持（如需要）
- [ ] JWE/JOSE 评估
- [ ] PQC 准备
- [ ] 性能优化

---

## 为新贡献者准备的优先任务

**简单任务（适合首次贡献）:**
- 文档改进
- 测试用例添加
- 有复现步骤的 bug 修复
- 示例代码改进

**中等任务:**
- ChaCha20-Poly1305 验证
- Base64URL 实现
- 密码哈希 API
- 额外测试覆盖

**困难任务:**
- Ed25519/Ed448 实现
- OSSL_PARAM API 绑定
- Provider API 支持
- 性能优化

---

## 总结

本路线图为 lua-openssl 在未来 12 个月以上的开发提供了结构化计划。优先级平衡了：

- **安全性:** 关键错误处理和安全审计
- **现代化:** OpenSSL 3.0 功能和现代算法
- **可用性:** 常见任务的简化 API
- **质量:** 改进的测试和文档
- **面向未来:** QUIC、PQC 和新兴标准

路线图是一个活文档，将根据以下因素更新：
- 社区反馈和贡献
- OpenSSL 生态系统变化
- 用户需求和用例
- 安全要求
- 资源可用性

**让我们一起构建 lua-openssl 的未来！🚀**

---

## 参考资料

- [DEPRECATION_STATUS.md](./DEPRECATION_STATUS.md) - 当前状态
- [README.md](./README.md) - 项目概述
- [ROADMAP.md](./ROADMAP.md) - 完整英文路线图
- [OpenSSL 文档](https://www.openssl.org/docs/)
- [GitHub Issues](https://github.com/zhaozg/lua-openssl/issues)

**有问题？想法？反馈？**
提交问题：https://github.com/zhaozg/lua-openssl/issues/new
