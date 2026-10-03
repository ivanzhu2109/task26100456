# task26100456

离线 TLS 证书路径审计库，基于 `cryptography` 实现。

## 依赖

```bash
pip install -r requirements.txt
```

## 使用

```python
from datetime import datetime, timezone
from tls_audit import audit

result = audit(leaf_der, peer_ders, anchor_ders, datetime.now(timezone.utc))
if result.ok:
    path = result.path  # DER 列表：叶证书在前，信任锚在后
else:
    print(result.reason)
```

- 签名范围：`sha256WithRSAEncryption`；扩展范围：BasicConstraints、KeyUsage、DNS SAN、DNS NameConstraints。
- 只有 DER 完全相同的 `anchors` 成员能结束路径；锚不检查有效期与扩展。
- 结论不受 `peers` 顺序、重复项与无关证书影响；同一 DER 不会在路径中重复，含环候选会终止并拒绝。

## 测试

```bash
python3 -m pytest tests/ -q
```
