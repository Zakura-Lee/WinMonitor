# WinMonitor

Windows HIDS 风格本地安全监控工具

## 概述

WinMonitor 是一个面向 Windows 的本地安全监控工具，采用前后端分离架构：
- **后端**：基于 Flask 框架，提供 RESTful API
- **前端**：纯 HTML/CSS/JavaScript，无需构建工具
- **数据库**：MySQL 存储用户、日志、告警数据

## 运行环境

- Windows 平台
- Python 3.8 及以上版本
- MySQL 5.7 及以上版本
- 依赖包通过 `requirements.txt` 安装

## 项目结构

```
WinMonitor/
├── src/                    # 后端核心代码
│   ├── app.py              # Flask 应用入口
│   ├── config.py           # 配置文件
│   ├── core/               # 监控服务核心
│   │   └── monitor.py      # 监控服务管理
│   ├── db/                 # 数据库相关
│   │   ├── setup.py        # 数据库初始化
│   │   └── connection.py   # 数据库连接
│   ├── models/             # 数据模型
│   │   ├── user_model.py   # 用户模型
│   │   ├── log_model.py    # 日志模型
│   │   └── user_request_model.py  # 用户请求模型
│   ├── modules/            # 监控模块
│   │   ├── process_mon.py  # 进程监控
│   │   ├── file_mon.py     # 文件监控
│   │   ├── network_mon.py  # 网络监控
│   │   ├── registry_mon.py # 注册表监控
│   │   ├── audit_mon.py    # 审计监控
│   │   └── asset_mon.py    # 资产清点
│   ├── routes/             # API 路由
│   │   ├── auth.py         # 认证路由
│   │   ├── monitor.py      # 监控路由
│   │   ├── logs.py         # 日志路由
│   │   ├── admin.py        # 管理路由
│   │   ├── user_requests.py # 用户请求路由
│   │   ├── auth_utils.py   # 认证工具
│   │   └── system.py       # 系统路由
│   └── utils/              # 工具函数
│       └── security.py      # 安全工具
├── web/                    # 前端页面
│   ├── login.html          # 登录页面
│   ├── register.html        # 注册页面
│   ├── menu.html           # 菜单页面
│   ├── dashboard.html      # 监控仪表盘
│   ├── logs.html          # 日志查看
│   ├── admin.html         # 管理面板
│   ├── profile.html       # 个人中心
│   ├── css/
│   │   └── style.css       # 样式文件
│   └── js/
│       ├── auth.js         # 认证脚本
│       ├── menu.js         # 菜单脚本
│       ├── dashboard.js    # 仪表盘脚本
│       ├── logs.js         # 日志脚本
│       ├── admin.js        # 管理脚本
│       └── profile.js      # 个人中心脚本
├── requirements.txt        # Python 依赖
└── README.md               # 本文件
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置数据库

修改 `src/config.py` 中的 MySQL 配置：

```python
DB_HOST = "localhost"
DB_PORT = 3306
DB_USER = "root"
DB_PASSWORD = "your_password"
DB_NAME = "winmonitor"
```

### 3. 创建数据库

```sql
CREATE DATABASE winmonitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 4. 启动服务

```bash
cd src
python app.py
```

### 5. 访问应用

打开浏览器访问：http://localhost:5000

默认管理员账号：`admin` / `admin123`

## 功能模块

### 用户认证

- 用户注册与登录
- 密码修改
- 忘记密码申请
- 管理员审批

### 监控功能

- **进程监控**：检测可疑启动路径、命令行参数、父进程、资源异常
- **文件监控**：监听文件创建、修改、删除，检测系统文件完整性
- **网络监控**：检测外部高危端口连接、可疑网络行为
- **注册表监控**：监控启动项和服务注册表变更
- **审计监控**：分析系统审计日志中的安全事件
- **资产清点**：收集主机信息、内存、磁盘、网络适配器

### 日志管理

- 监控日志分类展示（进程、文件、网络、注册表、审计）
- 用户变更日志记录
- 日志级别筛选（信息、警告、严重）
- 管理员可查看所有日志，普通用户仅查看自己的监控日志

### 告警功能

- 严重告警实时推送（SSE）
- 告警音效提示
- 浏览器桌面通知

### 管理功能

- 用户管理（注册审批）
- 密码重置审批
- 审计日志查看

## API 路由

### 认证相关

| 方法 | 路由 | 说明 |
|-----|-----|-----|
| POST | /api/login | 用户登录 |
| POST | /api/register | 用户注册 |
| POST | /api/logout | 用户登出 |
| PUT | /api/password | 修改密码 |
| POST | /api/forgot-password | 忘记密码申请 |

### 监控相关

| 方法 | 路由 | 说明 |
|-----|-----|-----|
| POST | /api/monitor/start | 启动监控 |
| POST | /api/monitor/stop | 停止监控 |
| POST | /api/monitor/pause | 暂停监控 |
| GET | /api/monitor/status | 获取监控状态 |
| GET | /api/monitor/processes | 获取进程信息 |
| GET | /api/monitor/critical-alerts | 获取严重告警 |
| GET | /api/monitor/stream-alerts | SSE 实时告警流 |

### 日志相关

| 方法 | 路由 | 说明 |
|-----|-----|-----|
| GET | /api/logs | 获取日志列表 |
| GET | /api/logs/summary | 获取日志统计 |

### 管理相关

| 方法 | 路由 | 说明 |
|-----|-----|-----|
| GET | /api/admin/users | 获取用户列表 |
| PUT | /api/admin/users/{id}/approve | 审批用户 |
| GET | /api/admin/requests | 获取请求列表 |
| PUT | /api/admin/requests/{id} | 处理请求 |
| GET | /api/admin/stats | 获取统计数据 |

### 用户请求相关

| 方法 | 路由 | 说明 |
|-----|-----|-----|
| GET | /api/user-requests | 获取用户请求状态 |

## 权限说明

| 功能 | 普通用户 | 管理员 |
|-----|---------|--------|
| 启动/停止监控 | ✓ | ✓ |
| 查看自己的监控日志 | ✓ | ✓ |
| 查看所有监控日志 | ✗ | ✓ |
| 查看用户变更日志 | ✗ | ✓ |
| 审批用户注册 | ✗ | ✓ |
| 审批密码重置 | ✗ | ✓ |
| 管理用户 | ✗ | ✓ |

## 技术栈

- **后端**：Flask, Flask-Cors, PyMySQL, pywin32, watchdog
- **前端**：原生 HTML, CSS, JavaScript
- **数据库**：MySQL

## 注意事项

1. 运行时需要管理员权限，否则可能无法读取全部审计日志
2. 监控模块使用 Windows 原生 API，需要在 Windows 平台运行
3. 首次运行会自动初始化数据库表结构
4. 日志数据存储在 MySQL 数据库中
