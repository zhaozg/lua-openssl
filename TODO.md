# lua-openssl Development TODO

基于当前库的深度分析，以下是发现的不足之处和开发计划。

## 高优先级 (High Priority)

### 文档质量改进 (Documentation Quality Improvement)
- [ ] **文档过时和质量低下** - README明确指出"Documentation quality is low and stale"
  - [ ] 更新和完善[在线文档](http://zhaozg.github.io/lua-openssl/index.html)
  - [ ] 改进LDoc注释，特别是以下模块文档函数数量较少：
    - cipher.c (24个函数)
    - digest.c (24个函数) 
    - kdf.c (25个函数)
    - crl.c (27个函数)
  - [ ] 添加更多实用示例和教程
  - [ ] 建立统一的API文档标准

### 代码质量和安全性 (Code Quality & Security)
- [ ] **内存管理优化** - 发现617处malloc/free使用，需要审查内存泄漏风险
  - [ ] 实施统一的内存管理策略
  - [ ] 添加更多内存泄漏检测和测试
  - [ ] 改进错误处理路径中的资源清理

- [ ] **不安全C函数使用** - 在th-lock.c中发现strcpy和sprintf使用
  - [ ] 替换为安全版本 (strncpy, snprintf)
  - [ ] 进行全面的代码安全审查
  - [ ] 建立安全编码规范

### 版本兼容性管理 (Version Compatibility)
- [ ] **复杂的版本兼容代码** - 发现120+个版本依赖代码块
  - [ ] 简化版本兼容性处理机制
  - [ ] 建立更清晰的版本支持策略
  - [ ] 考虑逐步淘汰过老版本支持(OpenSSL < 1.1.0)

## 中优先级 (Medium Priority)

### API现代化 (API Modernization)
- [ ] **OpenSSL 3.0+特性支持不完整**
  - [ ] 完善OSSL_PARAM和Provider API支持
  - [ ] 迁移到推荐的EVP高级API
  - [ ] 添加对新算法的支持 (Ed25519/Ed448, X25519/X448)
  - [ ] 实现后量子密码学算法支持准备

- [ ] **API一致性改进**
  - [ ] 统一错误处理模式 (当前48个错误处理点)
  - [ ] 标准化参数验证 (991个CHECK_OBJECT调用)
  - [ ] 改进Lua对象生命周期管理

### 测试覆盖率增强 (Test Coverage Enhancement)
- [ ] **测试用例扩展** - 当前57个测试文件
  - [ ] 增加边界条件测试
  - [ ] 添加性能基准测试
  - [ ] 实施持续集成中的覆盖率报告
  - [ ] 增加跨平台兼容性测试

### 构建系统现代化 (Build System Modernization)  
- [ ] **构建工具优化**
  - [ ] 简化Makefile和CMake配置
  - [ ] 改进依赖检测和错误报告
  - [ ] 支持更多包管理器 (vcpkg, conan)
  - [ ] 优化CI/CD管道性能

## 低优先级 (Low Priority)

### 性能优化 (Performance Optimization)
- [ ] **大文件优化** - ssl.c (2788行), pkey.c (2186行)等大文件重构
  - [ ] 模块化大型源文件
  - [ ] 优化热点函数性能
  - [ ] 减少不必要的内存拷贝
  - [ ] 实施缓存机制

### 功能增强 (Feature Enhancement)
- [ ] **新功能添加**
  - [ ] 时间戳支持增强 (基于ots.c改进)
  - [ ] 更好的流式处理支持
  - [ ] 异步操作支持
  - [ ] 更多哈希算法支持

### 开发体验改进 (Developer Experience)
- [ ] **调试和诊断工具**
  - [ ] 添加详细的错误消息
  - [ ] 实施日志框架
  - [ ] 提供调试构建选项
  - [ ] 创建交互式示例

## 长期目标 (Long-term Goals)

### 架构重构 (Architecture Refactoring)
- [ ] **代码架构优化**
  - [ ] 重新设计模块间依赖关系
  - [ ] 实施插件架构以支持可选功能
  - [ ] 改进错误传播机制
  - [ ] 建立更好的抽象层

### 社区建设 (Community Building)
- [ ] **贡献者体验**
  - [ ] 创建贡献指南和编码标准
  - [ ] 建立issue和PR模板
  - [ ] 设置自动化代码质量检查
  - [ ] 组织定期代码审查

## 实施计划 (Implementation Plan)

### Phase 1 (3个月)
1. 文档质量改进 - 更新关键模块文档
2. 安全问题修复 - 替换不安全C函数
3. 测试覆盖率基线建立

### Phase 2 (6个月)  
1. OpenSSL 3.0+ API完整支持
2. 内存管理优化
3. CI/CD增强

### Phase 3 (12个月)
1. 性能优化和大文件重构
2. 新功能开发
3. 社区建设

## 技术债务评估 (Technical Debt Assessment)

### 高技术债务区域
- 版本兼容性代码复杂度
- 大型源文件 (ssl.c, pkey.c)
- 过时的文档

### 中等技术债务区域  
- 错误处理不一致
- 测试覆盖率不均匀
- 构建系统复杂性

### 低技术债务区域
- 核心加密功能稳定
- 良好的CI/CD基础设施
- 活跃的维护

---

*注：此TODO基于对26k+行代码、57个测试文件、120+版本兼容代码块的深度分析*
*最后更新：2024年*