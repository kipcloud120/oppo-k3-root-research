# shell 权限历史结论回归（响应审核意见 v006 · P1）

> 生成：`tools/sepolicy_regression.py`｜引擎：`tools/cil_policy.py`（语义自检 `tools/cil_selftest.py` 28/28 通过）

## 0 三个口径

| 口径 | 集合语义 | 版本名 | 含义 |
| --- | --- | --- | --- |
| A | legacy（v2.23） | 一律合并 | 复刻旧脚本，对上已发布数字 |
| B | 正确 CIL 语义 | 一律合并 | 只回答"not/xor/and 修好会怎样" |
| **C** | 正确 CIL 语义 | **alias（只并"无成员定义"的版本化名）** | **新基线** |

| 项 | A | B | C |
| --- | --- | --- | --- |
| 类型 | 2650 | 2650 | 2650 |
| 属性 | 2699 | 2699 | 3358 |
| 全集 U | 4078 | 4078 | 4737 |
| 同名 type/attr | 1271 | 1271 | 1271 |
| 求值失败 | 0 | 0 | 0 |

## 1 具名查询三口径对照

| 查询 | 历史出处 | A | B | **C（基线）** |
| --- | --- | --- | --- | --- |
| shell find anti_root_dialog_service | §24.13 判为 0 条 | `∅` | `find` | `find` |
| shell binder call 宿主域 color_system_service_app | §24.13 判为只有 oplus_kevents | `call,transfer` | `call,transfer` | `call,transfer` |
| shell find hephaestus_service | §19 | `∅` | `find` | `find` |
| shell find hans_service | §19 | `∅` | `find` | `find` |
| shell find horae_service | §19 | `∅` | `find` | `find` |
| shell find oiface_service | §19 | `∅` | `find` | `find` |
| shell binder call hephaestus | §19 | `call,transfer` | `call,transfer` | `call,transfer` |
| shell binder call hans | §19 | `call,transfer` | `call,transfer` | `call,transfer` |
| shell binder call horae | §19 | `call,transfer` | `call,transfer` | `call,transfer` |
| shell binder call oiface | §19 | `call,transfer` | `call,transfer` | `call,transfer` |
| shell binder call system_app（appdata 宿主） | §19 | `call,transfer` | `call,transfer` | `call,transfer` |
| shell find hal_orms_hwservice | §19 | `∅` | `add,find` | `∅` |
| shell find hal_oiface_hwservice | §19 | `∅` | `add,find` | `∅` |
| oplus_wifi_service binder call servicemanager | §27 判为 0 条 | `∅` | `∅` | `∅` |
| oplus_wifi_service find alarm_service | §27 判为 0 条 | `∅` | `∅` | `∅` |
| oplus_wifi_service binder call system_server | §27 | `call,transfer` | `call,transfer` | `call,transfer` |
| shell binder call oplus_wifi_service | §23 前提 | `∅` | `∅` | `∅` |
| oplus_wifi_service open adsprpc-smd | §32 判为 ∅ | `∅` | `∅` | `∅` |
| oplus_wifi_service open adsprpc-smd-secure | §32 判为 ∅ | `∅` | `∅` | `∅` |
| oplus_wifi_service open diag（正对照） | §32 正对照 | `append,getattr,ioctl,lock,map,open,read,watch,watch_reads,write` | `append,getattr,ioctl,lock,map,open,read,watch,watch_reads,write` | `append,getattr,ioctl,lock,map,open,read,watch,watch_reads,write` |
| oplus_wifi_service 对 shell_exec 可执行 | §24.13 判为 0 | `∅` | `execute,execute_no_trans,getattr,ioctl,lock,map,open,read,watch,watch_reads` | `∅` |

## 2 口径翻转（A ≠ C）—— 本轮的实质结论

| 查询 | 旧（A） | 新（C） | 性质 |
| --- | --- | --- | --- |
| shell find anti_root_dialog_service | `∅` | `find` | 旧为新子集 ⇒ 旧结果是缺陷造成的**漏算** |
| shell find hephaestus_service | `∅` | `find` | 旧为新子集 ⇒ 旧结果是缺陷造成的**漏算** |
| shell find hans_service | `∅` | `find` | 旧为新子集 ⇒ 旧结果是缺陷造成的**漏算** |
| shell find horae_service | `∅` | `find` | 旧为新子集 ⇒ 旧结果是缺陷造成的**漏算** |
| shell find oiface_service | `∅` | `find` | 旧为新子集 ⇒ 旧结果是缺陷造成的**漏算** |

## 3 闭包总量

| 域 | 属性 A/B/C | 适用 allow A/B/C |
| --- | --- | --- |
| `shell` | 131 / 514 / **752** | 1012 / 1298 / **1271** |
| `oplus_wifi_service` | 89 / 513 / **775** | 307 / 394 / **347** |
| `system_app` | 149 / 579 / **842** | 1254 / 1542 / **1513** |
| `bluetooth` | 132 / 567 / **831** | 713 / 1001 / **978** |
| `sensors` | 89 / 513 / **776** | 301 / 388 / **341** |
| `mediaserver` | 106 / 533 / **795** | 665 / 752 / **706** |
| `untrusted_app` | 130 / 565 / **847** | 708 / 999 / **968** |
| `priv_app` | 131 / 564 / **839** | 716 / 1004 / **975** |
| `hephaestus` | 96 / 525 / **796** | 691 / 778 / **718** |
| `hans` | 96 / 523 / **794** | 337 / 424 / **364** |
| `horae` | 96 / 524 / **795** | 359 / 446 / **386** |
| `oiface` | 99 / 527 / **794** | 451 / 538 / **478** |
| `init` | 95 / 444 / **618** | 2254 / 2305 / **2279** |
| `system_server` | 153 / 543 / **693** | 1907 / 1968 / **1948** |
| `su` | 94 / 521 / **791** | 290 / 377 / **317** |
| `adbd` | 98 / 524 / **786** | 462 / 549 / **503** |
| `wificond` | 95 / 524 / **793** | 371 / 458 / **398** |
| `hostapd` | 89 / 513 / **776** | 282 / 369 / **322** |
| `vendor_shell` | 89 / 514 / **777** | 281 / 368 / **321** |

