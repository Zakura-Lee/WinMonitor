# WinMonitor 架构文档

本文档详细说明 WinMonitor 项目各模块的设计和功能。

## 目录

- [整体架构](#整体架构)
- [后端模块](#后端模块)
  - [配置模块](#配置模块)
  - [数据库模块](#数据库模块)
  - [数据模型](#数据模型)
  - [监控核心](#监控核心)
  - [监控模块](#监控模块)
  - [API 路由](#api-路由)
  - [工具函数](#工具函数)
- [前端模块](#前端模块)
  - [页面结构](#页面结构)
  - [JavaScript 模块](#javascript-模块)
- [数据流](#数据流)

---

## 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                        浏览器前端                            │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐          │
│  │  登录   │ │  菜单   │ │ 仪表盘  │ │  日志   │  ...     │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘          │
│       │            │            │            │                │
│       └────────────┴─────┬──────┴────────────┘                │
│                          │                                    │
│                    fetch API / SSE                             │
└──────────────────────────┼────────────────────────────────────┘
                           │
┌──────────────────────────┼────────────────────────────────────┐
│                     Flask 后端                                │
│  ┌─────────────────────────────────────────────────────┐     │
│  │                  API Routes Layer                    │     │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │     │
│  │  │  Auth  │ │Monitor │ │ Logs   │ │ Admin  │  ...  │     │
│  │  └────┬───┘ └────┬───┘ └────┬───┘ └────┬───┘       │     │
│  └───────┼──────────┼──────────┼──────────┼─────────────┘     │
│          │          │          │          │                     │
│  ┌───────┴──────────┴──────────┴──────────┴─────────────┐     │
│  │                  Models Layer                        │     │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐       │     │
│  │  │  User  │ │  Log   │ │Request │ │ Alert  │       │     │
│  │  └────────┘ └────────┘ └────────┘ └────────┘       │     │
│  └─────────────────────────────────────────────────────┘     │
│                           │                                    │
│  ┌────────────────────────┴────────────────────────────┐     │
│  │              Monitor Service                         │     │
│  │  ┌──────────┬──────────┬──────────┬──────────┐      │     │
│  │  │ Process  │  File   │ Network  │Registry │ ...  │     │
│  │  │ Monitor  │ Monitor │ Monitor  │ Monitor  │      │     │
│  │  └──────────┴──────────┴──────────┴──────────┘      │     │
│  └─────────────────────────────────────────────────────┘     │
└─────────────────────────────┬────────────────────────────────┘
                              │
                     ┌────────┴────────┐
                     │     MySQL       │
                     │   Database      │
                     └─────────────────┘
```

---

## 后端模块

### 配置模块

**文件**: `src/config.py`

提供全局配置，包括：
- 数据库连接配置
- 监控规则配置（可疑路径、命令、父进程）
- 告警级别定义
- 日志配置

**关键配置项**:
```python
# 数据库配置
DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME

# 监控规则
SUS_PATH = ["\\temp\\", "\\desktop\\", "\\downloads\\"]
SUS_CMD = ["-enc", "-w hidden", "bitsadmin"]
SUS_PARENT = ["notepad.exe"]

# 高危端口
HIGH_RISK_PORTS = [4444, 1337, 3389]
```

---

### 数据库模块

#### 连接管理

**文件**: `src/db/connection.py`

```python
def get_connection():
    """获取数据库连接"""
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset='utf8mb4'
    )
```

#### 初始化

**文件**: `src/db/setup.py`

自动创建数据库表：
- `users` - 用户表
- `logs` - 日志表
- `user_requests` - 用户请求表
- `critical_alerts` - 严重告警表

**关键功能**:
- 创建管理员默认账号 (admin/admin123)
- 设置数据库字符集为 utf8mb4

---

### 数据模型

#### 用户模型

**文件**: `src/models/user_model.py`

```python
def create_user(username, password, is_admin=False, status='pending'):
    """创建用户 - 管理员直接approved，普通用户需要审批"""

def verify_user(username, password):
    """验证用户登录"""

def get_user_by_id(user_id):
    """根据ID获取用户"""

def update_user_password(user_id, password_hash, salt):
    """更新用户密码"""
```

#### 日志模型

**文件**: `src/models/log_model.py`

```python
def insert_log(username, category, title, message, severity='info', source='system'):
    """插入日志记录"""

def get_logs_for_user(username, is_admin=False, limit=200):
    """获取用户可见的日志"""

def get_logs_summary(username, is_admin=False):
    """获取日志统计"""

def get_category_cn(category):
    """获取日志类型中文名称"""
```

**日志类型映射**:
```python
CATEGORY_CN_MAP = {
    'file': '文件监控',
    'process': '进程监控',
    'network': '网络监控',
    'registry': '注册表监控',
    'audit': '审计日志',
    'asset': '资产清点',
    'user': '用户变更',
    'system': '系统'
}
```

#### 用户请求模型

**文件**: `src/models/user_request_model.py`

```python
def create_request(username, request_type, details='', **kwargs):
    """创建用户请求"""

def get_pending_requests():
    """获取待处理的请求"""

def process_request(request_id, status, admin_username):
    """处理请求"""
```

---

### 监控核心

**文件**: `src/core/monitor.py`

监控服务的核心管理类：

```python
class MonitorService:
    def __init__(self):
        self.running = False
        self.paused = False
        self.alert_queue = Queue()
        self.subscribers = []
        self.processes = []
        self.process_changes = []
        self.current_user = None
        
    def start(self, username):
        """启动监控"""
        
    def stop(self):
        """停止监控"""
        
    def pause(self):
        """暂停监控"""
        
    def subscribe(self):
        """订阅告警通知"""
        
    def unsubscribe(self):
        """取消订阅"""
        
    def _broadcast_alert(self, alert):
        """广播告警给所有订阅者"""
```

**关键机制**:
- **告警队列**: 监控模块产生的告警先放入队列
- **消费线程**: 后台线程从队列消费告警，记录日志并广播
- **SSE订阅**: 前端通过 Server-Sent Events 订阅实时告警
- **用户标记**: 告警记录关联到启动监控的用户

---

### 监控模块

#### 进程监控

**文件**: `src/modules/process_mon.py`

监控内容：
- 可疑路径检测 (`\\temp\\`, `\\desktop\\`, `\\downloads\\`)
- 可疑命令行参数 (`-enc`, `-w hidden`, `bitsadmin`)
- 可疑父进程 (`notepad.exe`)
- 资源异常 (CPU > 70%, 内存 > 300MB)

**信任进程白名单**:
- Windows Update 相关进程
- TrustedInstaller.exe
- Defender 服务进程

#### 文件监控

**文件**: `src/modules/file_mon.py`

使用 `watchdog` 库监听：
- 文件创建、修改、删除、移动
- 系统文件完整性检查
- 危险文件操作告警

**完整性验证**:
- 监控 System32 目录下的 DLL 文件修改
- 只信任特定父进程的修改（Windows Update、Defender）

#### 网络监控

**文件**: `src/modules/network_mon.py`

监控内容：
- TCP 连接状态变化
- 高危端口连接 (4444, 1337, 3389)
- SYN 洪泛检测

**识别正规服务**:
- GitHub, 腾讯云, Windows Update 等
- 内网数据库访问

#### 注册表监控

**文件**: `src/modules/registry_mon.py`

监控注册表路径：
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`

检测新增、修改、删除操作

#### 审计监控

**文件**: `src/modules/audit_mon.py`

读取 Windows 安全日志：
- 登录失败事件
- 进程创建事件
- 服务安装事件
- 审计日志清除事件

#### 资产清点

**文件**: `src/modules/asset_mon.py`

收集系统信息：
- 主机名称、操作系统版本
- 内存信息
- 磁盘信息
- 网络适配器信息

---

### API 路由

#### 认证路由

**文件**: `src/routes/auth.py`

| 方法 | 路由 | 说明 |
|-----|-----|-----|
| POST | /api/login | 用户登录 |
| POST | /api/register | 用户注册 |
| POST | /api/logout | 用户登出 |
| PUT | /api/password | 修改密码 |
| POST | /api/forgot-password | 忘记密码申请 |

**认证流程**:
1. 验证用户名密码
2. 生成 JWT Token
3. 返回用户信息和 Token

#### 监控路由

**文件**: `src/routes/monitor.py`

| 方法 | 路由 | 说明 |
|-----|-----|-----|
| POST | /api/monitor/start | 启动监控 |
| POST | /api/monitor/stop | 停止监控 |
| POST | /api/monitor/pause | 暂停监控 |
| GET | /api/monitor/status | 获取监控状态 |
| GET | /api/monitor/processes | 获取进程信息 |
| GET | /api/monitor/critical-alerts | 获取严重告警 |
| GET | /api/monitor/stream-alerts | SSE 实时告警流 |

**SSE 实时告警**:
```python
@monitor_bp.route("/monitor/stream-alerts", methods=["GET"])
def stream_alerts():
    """SSE端点，实时推送严重告警"""
    # 支持 URL 参数传递 token
    # 定期发送心跳
    # 推送严重告警给订阅者
```

#### 日志路由

**文件**: `src/routes/logs.py`

| 方法 | 路由 | 说明 |
|-----|-----|-----|
| GET | /api/logs | 获取日志列表 |
| GET | /api/logs/summary | 获取日志统计 |

**权限控制**:
- 普通用户：只能查看自己的监控日志 (`username = current_user`)
- 管理员：可以查看所有日志

#### 管理路由

**文件**: `src/routes/admin.py`

| 方法 | 路由 | 说明 |
|-----|-----|-----|
| GET | /api/admin/users | 获取用户列表 |
| PUT | /api/admin/users/{id}/approve | 审批用户 |
| GET | /api/admin/requests | 获取请求列表 |
| PUT | /api/admin/requests/{id} | 处理请求 |
| GET | /api/admin/stats | 获取统计数据 |

---

### 工具函数

**文件**: `src/utils/security.py`

```python
def hash_password(password):
    """使用盐值哈希密码"""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex(), key.hex()

def verify_password(password, salt_hex, password_hash_hex):
    """验证密码"""
    salt = bytes.fromhex(salt_hex)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key.hex() == password_hash_hex

def generate_token(username, is_admin=False):
    """生成 JWT Token"""
    payload = {
        'username': username,
        'is_admin': is_admin,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')
```

---

## 前端模块

### 页面结构

| 页面 | 文件 | 说明 |
|-----|-----|-----|
| 登录 | login.html | 用户登录、忘记密码入口 |
| 注册 | register.html | 新用户注册 |
| 菜单 | menu.html | 功能导航入口 |
| 仪表盘 | dashboard.html | 监控状态、告警展示 |
| 日志 | logs.html | 日志查看 |
| 管理 | admin.html | 用户管理、审批 |
| 个人中心 | profile.html | 密码修改 |

### JavaScript 模块

#### 认证脚本

**文件**: `web/js/auth.js`

功能：
- 表单验证
- 登录/注册请求
- Token 管理
- 忘记密码申请

#### 仪表盘脚本

**文件**: `web/js/dashboard.js`

核心功能：
```javascript
// 监控状态
async function loadMonitorStatus()
async function startMonitoring()
async function pauseMonitoring()
async function stopMonitoring()

// 进程信息
async function loadMonitorProcesses()
function renderProcessChanges(changes)
function renderCurrentProcesses(processes)

// 告警功能
var alertEventSource = null
function startCriticalAlertStream()  // SSE 连接
function stopCriticalAlertStream()   // 断开连接
function addAlertToPanel(alert)      // 添加告警
function playAlertSound()            // 告警音效
function showRealtimeAlert(alert)     // 桌面通知
```

**实时告警流程**:
1. 页面加载时调用 `startCriticalAlertStream()`
2. 通过 EventSource 订阅 SSE 端点
3. 收到告警时调用 `addAlertToPanel()` 和 `playAlertSound()`
4. 浏览器授权后显示桌面通知

#### 日志脚本

**文件**: `web/js/logs.js`

功能：
- 获取日志列表
- 按类型/用户分类展示
- 日志级别筛选
- 管理员/普通用户不同视图

**分类逻辑**:
```javascript
// 普通用户：按日志类型分类
categories = ['file', 'process', 'network', 'registry', 'audit']

// 管理员：用户日志 + 用户变更
monitorLogs = 按 username 分组
userLogs = 按 category 分组（登录、注册、密码修改等）
```

---

## 数据流

### 监控数据流

```
┌─────────────────┐
│   监控模块      │
│  (process_mon   │
│   file_mon...)  │
└────────┬────────┘
         │
         │ 产生告警
         ▼
┌─────────────────┐
│   告警队列      │
│  alert_queue    │
└────────┬────────┘
         │
         │ 消费告警
         ▼
┌─────────────────┐
│   消费线程      │
│ _consume_alerts │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌───────┐ ┌───────────┐
│insert │ │broadcast │
│ _log  │ │ _alert   │
└───┬───┘ └─────┬─────┘
    │           │
    ▼           ▼
┌───────┐ ┌───────────┐
│ MySQL │ │ SSE推送   │
│ logs  │ │ 前端接收  │
└───────┘ └───────────┘
```

### 用户请求数据流

```
用户点击"忘记密码"
       │
       ▼
┌─────────────────┐
│  auth.py        │
│ forgot_password │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ user_requests   │
│     表          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  admin.py       │
│ 处理请求        │
│ 批准/拒绝       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  users 表       │
│ 密码更新        │
└─────────────────┘
```

---

## 数据库表结构

### users 表

| 字段 | 类型 | 说明 |
|-----|-----|-----|
| id | INT | 主键 |
| username | VARCHAR(32) | 用户名 |
| password_hash | VARCHAR(128) | 密码哈希 |
| salt | VARCHAR(64) | 盐值 |
| is_admin | BOOLEAN | 是否管理员 |
| status | VARCHAR(16) | pending/approved/rejected |
| created_at | TIMESTAMP | 创建时间 |

### logs 表

| 字段 | 类型 | 说明 |
|-----|-----|-----|
| id | INT | 主键 |
| username | VARCHAR(32) | 用户名 |
| category | VARCHAR(16) | 日志类别 |
| title | VARCHAR(128) | 标题 |
| message | TEXT | 消息内容 |
| severity | VARCHAR(16) | info/warning/critical |
| source | VARCHAR(32) | 来源 |
| created_at | TIMESTAMP | 创建时间 |

### user_requests 表

| 字段 | 类型 | 说明 |
|-----|-----|-----|
| id | INT | 主键 |
| username | VARCHAR(32) | 用户名 |
| request_type | VARCHAR(32) | 请求类型 |
| details | TEXT | 详情 |
| requested_password_hash | VARCHAR(128) | 新密码哈希 |
| requested_salt | VARCHAR(64) | 新密码盐值 |
| status | VARCHAR(16) | pending/approved/rejected |
| processed_by | VARCHAR(32) | 处理人 |
| created_at | TIMESTAMP | 创建时间 |
| processed_at | TIMESTAMP | 处理时间 |
