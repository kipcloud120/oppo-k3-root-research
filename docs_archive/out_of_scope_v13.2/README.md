# 归档：v13.2 期间越界产出的 GhostLock 附录（未纳入判定）

本目录的两份文件是 2026-11-20 v13.2 会话期间由**子代理越界产出**的内容，**不属于 v13.2 的送审范围，也未经主代理复核**：

- `GHOSTLOCK_HEAP_RECLAIM_FEASIBILITY.md`（自称 "G5"）：讨论"② 同页 slab 回收"的纯离线可行性。
- `reclaim_model.py`：上述文档的尺寸/阶计算器。

处置理由：

1. 审核意见 v0132 第六节明确要求 **GhostLock 正式转入长期冻结**，v13.2 的主线是 WLAN 调用链与项目收口；该附录属于被冻结方向的继续投入，与 v13.2 的排期和结论口径冲突。
2. 该附录的技术主张（mm 16 KB/order-2/18 对象、`SOCK_DGRAM 16064 = SKB_MAX_ALLOC` 走单块 linear、SLUB `min_partial=5`/`cpu_partial=13` 的 groom 条件）**未经主代理独立复核**，不应作为项目结论引用。
3. 主代理已把误改的根目录文档（`HANDOVER.md` / `README.md` / `CLOSURE.md` / `HANDOVER_RESUME.md` / `GHOSTLOCK_ADDRESS_SOURCE_MATRIX.md`）回退到 v13.2 口径；本目录仅作留档，避免丢失工作痕迹。

**引用纪律**：不得把本目录内容当作"v13.2 结论"或"已证实路线"；若未来 GhostLock 重开，需按 v0132 §六的三个重开条件重新评估，并由用户单独授权。
