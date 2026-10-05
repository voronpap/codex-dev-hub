from pathlib import Path

from devhub.ledger import Ledger, LedgerIdentityCoreV1


def identity(
    scope_id: str = "p",
    *,
    instance_id: str = "0123456789abcdef0123456789abcdef",
    scope_kind: str = "project",
    account_binding_hash: str | None = None,
) -> LedgerIdentityCoreV1:
    return LedgerIdentityCoreV1.model_validate(
        {
            "family": "devfabric_resource_ledger",
            "format_version": 1,
            "instance_id": instance_id,
            "authority_scope_kind": scope_kind,
            "authority_scope_id": scope_id,
            "account_binding_hash": account_binding_hash,
        }
    )


def initialized_ledger(path: Path, expected: LedgerIdentityCoreV1 | None = None) -> Ledger:
    expected = expected or identity()
    path.parent.mkdir(parents=True, exist_ok=True)
    return Ledger.initialize(path, expected)
