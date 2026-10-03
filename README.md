# task26100456

离线 TLS 证书路径审计库，基于 Python + cryptography。

## 接口

```python
from certaudit import audit

result = audit(leaf_der, peer_ders, anchor_ders, now_utc)
if result.ok:
    chain = result.path  # 叶证书到信任锚（含锚）的合格路径
else:
    print(result.reason)
```

- 输入均为 DER 编码证书；`anchors` 为显式信任锚集合；`now` 为 UTC 时刻（naive 按 UTC 处理）。
- 签名范围：sha256WithRSAEncryption；扩展范围：BasicConstraints、KeyUsage、DNS SAN、DNS NameConstraints。
- 结论不受 peers 顺序、重复项和无关证书影响；同一 DER 不在路径中重复；候选路径失败会继续搜索其他分支。
- 只有 DER 完全相同的 anchors 成员能结束路径；锚不检查有效期与扩展，也不必自签名。
- 中间 CA 的 pathLen 只统计其下方非自颁发中间 CA（不计叶证书）；自颁发中间证书免受祖先 DNS 约束，但其自身约束仍作用于下级；叶证书永不豁免。

## 依赖与测试

```bash
pip install -r requirements.txt
python -m pytest tests/
```

测试中的证书全部由 `tests/factory.py` 真实签发（RSA-2048 + SHA-256）。
