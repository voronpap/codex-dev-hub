"""Build or execute one reviewed non-benchmark Stage 3G rehearsal pair."""

import argparse
from pathlib import Path

from devhub.benchmark import canonical, write_sealed
from devhub.experiment import ExperimentProtocol, RuntimeBindings
from devhub.experiment_rehearsal import build_rehearsal_plan, load_rehearsal_plan
from devhub.experiment_run import execute_rehearsal_pair
from devhub.qualification import verify_manifest_tree


def regular_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Rehearsal task source must be an explicit regular file")
    return path.read_bytes()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("plan", "execute"))
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--qualification-manifest", type=Path, required=True)
    parser.add_argument("--qualification-manifest-id", required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--task-id")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--task", type=Path)
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--auth", type=Path)
    parser.add_argument("--accounting-root", type=Path)
    parser.add_argument("--operator-reviewed", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    protocol = ExperimentProtocol.model_validate_json(args.protocol.read_bytes())
    qualification = verify_manifest_tree(
        args.qualification_manifest, args.qualification_manifest_id
    )
    if args.action == "plan":
        if not all((args.run_id, args.task_id, args.input, args.task)):
            parser.error("plan requires --run-id, --task-id, --input and --task")
        rehearsal = build_rehearsal_plan(
            repo,
            protocol,
            qualification,
            run_id=args.run_id,
            task_id=args.task_id,
            input_bytes=regular_bytes(args.input),
            task_bytes=regular_bytes(args.task),
        )
        write_sealed(args.plan, canonical(rehearsal.model_dump(mode="json")))
        print(rehearsal.rehearsal_plan_id)
        return
    if not args.operator_reviewed:
        parser.error("execute requires --operator-reviewed")
    if not all((args.run_root, args.auth, args.accounting_root)):
        parser.error("execute requires --run-root, --auth and --accounting-root")
    rehearsal = load_rehearsal_plan(args.plan)
    result = execute_rehearsal_pair(
        repo,
        protocol,
        rehearsal,
        RuntimeBindings(qualification_manifest_id=args.qualification_manifest_id),
        args.run_root,
        args.auth,
        args.qualification_manifest,
        args.accounting_root,
        operator_reviewed=True,
    )
    print(canonical(result.model_dump(mode="json")).decode())


if __name__ == "__main__":
    main()
