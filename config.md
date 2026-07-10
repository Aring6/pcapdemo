# Skills 统一配置

> ⚠️ 本文件为所有 Skill 的**唯一**数据库配置来源。所有脚本必须从此文件解析连接参数，禁止硬编码。
> 使用时必须通过 `--env` 参数指定环境（`trunk`、`auto` 或 `new_trunk`），脚本通过 `db_config.sh` 自动加载对应配置。

---

## 解析规则（Skill 必读）

- **数据库配置**：每条配置是一行可直接执行的 `mysql` 命令，Skill 从中提取 `-u`(user)、`-h`(host)、`-P`(port)、`-p`(password)、最后一个参数(database) 等信息
- **API 配置**：每条配置是一个完整的 base URL，Skill 直接用它拼接请求
- **环境切换**：所有脚本必须通过 `--env trunk`、`--env auto` 或 `--env new_trunk` 指定环境，不允许默认

---

## 1. 数据库连接

### 环境：主干（trunk）

MySQL 地址：`21.0.46.54:3306`

```bash
# [trunk] Shark DB
mysql -uroot -h21.0.46.54 -P3306 -p'yunr1d1stest#cloud' redis_oss

# [trunk] SuperCC DB（默认库，按 grocerySysId 切换库名）
mysql -uroot -h21.0.46.54 -P3306 -p'yunr1d1stest#cloud' supercc_20001_4test

# [trunk] NGCC DB
mysql -uroot -h21.0.46.54 -P3306 -p'yunr1d1stest#cloud' ngcc_61002_test

# [trunk] 备份调度中心 DB
mysql -uroot -h21.0.46.54 -P3306 -p'yunr1d1stest#cloud' dispatch_center

# [trunk] 资源库
mysql -uroot -h21.0.46.54 -P3306 -p'yunr1d1stest#cloud' cc_resource
```

| grocerySysId | 库名 | 类型 |
|---|---|---|
| 15005 | `redis_newcc` | cc |
| 15006 | `redis_multiaz_sh` | cc |
| 15007 | `redis_multiaz_gz` | cc |
| 20001 | `supercc_20001_4test` | supercc |
| 61002 | `ngcc_61002_test` | ngcc |

### 环境：自动化（auto）

MySQL 地址：`21.0.46.59:3306`

```bash
# [auto] Shark DB
mysql -uroot -h21.0.46.59 -P3306 -p'yunr1d1stest#cloud' ci_redis_oss

# [auto] SuperCC DB（默认库，按 grocerySysId 切换库名）
mysql -uroot -h21.0.46.59 -P3306 -p'yunr1d1stest#cloud' at_supercc_20001_4test

# [auto] NGCC DB
mysql -uroot -h21.0.46.59 -P3306 -p'yunr1d1stest#cloud' ngcc_61001_test

# [auto] 备份调度中心 DB
mysql -uroot -h21.0.46.59 -P3306 -p'yunr1d1stest#cloud' auto_dispatch_center

# [auto] 资源库
mysql -uroot -h21.0.46.59 -P3306 -p'yunr1d1stest#cloud' cc_resource
```

| grocerySysId | 库名 | 类型 |
|---|---|---|
| 15011 | `redis_auto_cc_1` | cc |
| 15012 | `redis_auto_cc_2` | cc |
| 15013 | `redis_auto_cc_3` | cc |
| 15017 | `redis_auto_cc_4` | cc |
| 15018 | `redis_auto_cc_5` | cc |
| 20012 | `at_supercc_20001_4test` | supercc |
| 61001 | `ngcc_61001_test` | ngcc |

### 环境：新主干（new_trunk）

MySQL 地址：`21.0.178.111:3306`

```bash
# [new_trunk] Shark DB
mysql -uroot -h21.0.178.111 -P3306 -p'yunr1d1stest#cloud' redis_oss

# [new_trunk] SuperCC DB（默认库，按 grocerySysId 切换库名）
mysql -uroot -h21.0.178.111 -P3306 -p'yunr1d1stest#cloud' supercc_25001

# [new_trunk] NGCC DB
# 无（new_trunk 无此需求）

# [new_trunk] 备份调度中心 DB
mysql -uroot -h21.0.178.111 -P3306 -p'yunr1d1stest#cloud' dispatch_center

# [new_trunk] 资源库
mysql -uroot -h21.0.178.111 -P3306 -p'yunr1d1stest#cloud' cc_resource
```

| grocerySysId | 库名 | 类型 |
|---|---|---|
| 15021 | `cc_15021` | cc |
| 15022 | `cc_15022` | cc |
| 15023 | `cc_15023` | cc |
| 25001 | `supercc_25001` | supercc |

---

## 2. API 服务地址

### 环境：主干（trunk）

```
# [trunk] Shark API（工作流管理系统）
http://21.90.116.28:9091/interface_v3

# [trunk] SuperCC API（集群控制系统）
http://21.90.118.206:10001/api/v3
```

### 环境：自动化（auto）

```
# [auto] Shark API（工作流管理系统）
http://11.141.106.217:9091/interface_v3

# [auto] SuperCC API（集群控制系统）
http://11.141.106.249:10001/api/v3
```

### 环境：新主干（new_trunk）

```
# [new_trunk] Shark API（工作流管理系统）
http://21.90.118.211:9091/interface_v3

# [new_trunk] SuperCC API（集群控制系统）
http://21.90.119.67:10001/api/v3
```

### CcAgent API（机器 Agent，所有环境通用）

```
http://{host}:5000/api/agent/v1
```

> CcAgent 部署在每台 Redis/Proxy 机器上，`{host}` 为目标机器 IP。

---

## 3. Redis 实例默认配置

| 配置项 | 值 | 说明 |
|--------|-----|------|
| **默认密码** | `redis@123` | 创建实例时的默认密码 |
| **默认计费模式** | `BillingMode=1`（包年包月） | |
| **默认可用区** | `ap-guangzhou-2` | |
| **默认购买时长** | `Period=1`（1个月） | |

---

## 4. 配置变更记录

| 日期 | 变更内容 | 操作人 |
|------|---------|--------|
| 2026-06-17 | 新增 new_trunk 环境 API 地址（Shark: 21.90.118.211，SuperCC: 21.90.119.67） | AI |
| 2026-06-17 | 补齐 new_trunk 环境数据库配置（redis_oss、cc_15021/15022/15023、supercc_25001、dispatch_center、cc_resource；无 NGCC） | AI |
| 2026-04-09 | API 地址拆分为 trunk/auto 双环境配置 | AI |
| 2026-04-09 | 统一多环境配置（trunk/auto），所有脚本从 config.md 读取 | AI |
| 2026-03-16 | 简化为一行命令式配置，去掉冗余表格 | AI |
| 2026-03-16 | 初始创建 | AI |
