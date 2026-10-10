"""Read-only qualification of the context-bound DevFabric ledger authority."""

import argparse
import json
from pathlib import Path

from devhub.benchmark import canonical, write_new
from devhub.ledger import Ledger
from devhub.qualification import LedgerIdentityReceiptV1, load_context, receipt_header


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--ledger-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Exclusive output required")
    context = load_context(args.context)
    expected = context.payload.ledger_expected
    inspection = Ledger.inspect_read_only(
        args.ledger_root / "ledger.db", expected.identity, state_root=args.ledger_root
    )
    if (
        inspection.domain_schema_version != expected.domain_schema_version
        or inspection.ledger_identity_sha256 != expected.identity_sha256
        or inspection.reserved_count
        or inspection.dispatched_count
        or inspection.unknown_usage_count
    ):
        parser.error("Ledger is not a clean context-bound qualification authority")
    receipt = LedgerIdentityReceiptV1(
        **receipt_header(context, "ledger_identity"),
        ledger_identity_sha256=inspection.ledger_identity_sha256,
        domain_schema_version=inspection.domain_schema_version,
        sqlite_application_id=inspection.application_id,
        identity_record_count=inspection.identity_record_count,
        integrity_check="ok",
        path_is_locator_only=True,
        reserved_count=inspection.reserved_count,
        dispatched_count=inspection.dispatched_count,
        unknown_usage_count=inspection.unknown_usage_count,
        qualification_passed=True,
    )
    write_new(args.output, canonical(receipt.model_dump(mode="json")))
    print(
        json.dumps(
            {
                "qualification_passed": True,
                "ledger_identity_sha256": inspection.ledger_identity_sha256,
            }
        )
    )


if __name__ == "__main__":
    main()
