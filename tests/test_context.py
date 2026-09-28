import pytest
from pydantic import ValidationError
from test_brain import repo

from devhub.brain import ProjectBrain
from devhub.brain_models import SearchQuery, sha256
from devhub.context import ContextBuilder, estimate, package_digest, render_payload
from devhub.context_models import ContextLimits, ContextPackage, ContextPolicy, ContextTask


@pytest.fixture
def context(tmp_path):
    files = {
        "code.py": "def reserve_slot():\n    return 'quota'\n",
        "adr.md": "Architecture quota authority.\n",
        "guide.md": "Quota introduction.\n" + "Detailed quota explanation.\n" * 30,
        "copy.md": "Architecture quota authority.\n",
    }
    root = repo(tmp_path / "repo", files)
    brain = ProjectBrain(tmp_path / "state", {"p": root})
    scope = brain.scope("p")
    snapshot = brain.index(scope, approved_paths=tuple(files), expected_snapshot=None)
    batches = tuple(
        brain.search(scope, snapshot_id=snapshot.snapshot_id, query=SearchQuery(text=path))
        for path in files
    )
    builder = ContextBuilder(brain)
    args = dict(
        task=ContextTask(
            task_id="task", instructions="Explain quota.", acceptance_criteria=("Cite sources.",)
        ),
        snapshot_id=snapshot.snapshot_id,
        batches=batches,
        policy=ContextPolicy(authoritative_paths=("adr.md",)),
        limits=ContextLimits(context_window_tokens=32768, max_output_tokens=1024),
        now_ms=1000,
    )
    return builder, scope, args, root


def valid(builder, scope, args, package, **changes):
    values = {key: args[key] for key in ("task", "policy", "limits", "now_ms")}
    return builder.validate_package(scope, package, **(values | changes))


def test_deterministic_frozen_package_and_duplicate_queries(context):
    builder, scope, args, _ = context
    first = builder.build(scope, **args).package
    assert first is not None
    batches = tuple(reversed(args["batches"])) + args["batches"]
    second = builder.build(scope, **(args | {"batches": batches})).package
    assert first == second
    restored = ContextPackage.model_validate_json(first.model_dump_json())
    assert restored == first and valid(builder, scope, args, restored)
    assert first.package_hash == package_digest(first)
    with pytest.raises(ValidationError):
        first.input_estimate = 0
    assert len(first.items) == 3
    duplicate = next(item for item in first.items if len(item.sources) == 2)
    assert {s.path for s in duplicate.sources} == {"adr.md", "copy.md"}
    assert render_payload(first.task, first.items).count("Architecture quota authority.") == 1


def test_priority_and_scores_are_not_compared(context):
    builder, scope, args, _ = context
    args["task"] = args["task"].model_copy(update={"identifiers": ("reserve_slot",)})
    package = builder.build(scope, **args).package
    assert [item.selection_reason for item in package.items] == [
        "exact_path_or_symbol",
        "authoritative_path",
        "fts_rank",
    ]
    changed = tuple(
        batch.model_copy(
            update={
                "hits": tuple(
                    hit.model_copy(update={"score": 1e12 * (-1 if index % 2 else 1)})
                    for hit in batch.hits
                )
            }
        )
        for index, batch in enumerate(args["batches"])
    )
    assert builder.build(scope, **(args | {"batches": changed})).package == package


def test_budget_counts_exact_payload_and_preserves_essentials(context):
    builder, scope, args, _ = context
    args["task"] = args["task"].model_copy(update={"instructions": "Поясни квоту."})
    package = builder.build(scope, **args).package
    assert package.effective_token_cap == 8000
    assert package.input_estimate == len(render_payload(package.task, package.items).encode())
    assert package.input_estimate <= 8000
    assert package.task.instructions == "Поясни квоту."
    args["limits"] = ContextLimits(context_window_tokens=1000, max_output_tokens=700)
    failed = builder.build(scope, **args)
    assert failed.status == "context_insufficient" and failed.package is None
    assert failed.missing_context == ("essential_instructions_exceed_budget",)


def test_compaction_preserves_provenance_and_required_source_is_never_cut(context):
    builder, scope, args, _ = context
    args["batches"] = (args["batches"][2],)
    full = builder.build(scope, **args).package
    args["policy"] = ContextPolicy(context_token_cap=full.input_estimate - 200)
    compact = builder.build(scope, **args).package
    assert compact is not None and compact.items[0].compacted
    source = compact.items[0].sources[0]
    assert source.end_line < source.original_end_line
    assert source.original_chunk_sha256 == full.items[0].selected_sha256
    assert compact.items[0].text.endswith("\n")
    assert compact.excluded_sources[0].reason == "compacted"
    assert valid(builder, scope, args, compact)
    args["task"] = args["task"].model_copy(update={"required_paths": ("guide.md",)})
    failed = builder.build(scope, **args)
    assert failed.missing_context == ("required_source_exceeds_budget",)


@pytest.mark.parametrize("when", ["before_build", "before_seal", "after_build"])
def test_stale_sources_fail_closed(context, monkeypatch, when):
    builder, scope, args, root = context

    def change():
        (root / "adr.md").write_text("Changed quota.\n", encoding="utf-8")

    if when == "before_build":
        change()
    elif when == "before_seal":
        original = builder.brain.validate_excerpts

        def changed(*values):
            change()
            return original(*values)

        monkeypatch.setattr(builder.brain, "validate_excerpts", changed)
    result = builder.build(scope, **args)
    if when == "after_build":
        assert result.package is not None
        change()
        assert not valid(builder, scope, args, result.package)
    else:
        assert result.status == "context_insufficient" and result.package is None


def test_scope_expiry_and_expected_contract_binding(context):
    builder, scope, args, _ = context
    package = builder.build(scope, **args).package
    assert not valid(builder, scope, args, package, now_ms=package.expires_at_ms)
    assert not valid(builder, scope, args, package, now_ms=999)
    assert not valid(builder, scope.model_copy(update={"project_id": "other"}), args, package)
    for key, update in (
        ("task", {"instructions": "Different task"}),
        ("policy", {"context_token_cap": 9000}),
        ("limits", {"model_identity": "other"}),
    ):
        assert not valid(
            builder, scope, args, package, **{key: args[key].model_copy(update=update)}
        )
    batch = args["batches"][0]
    alien = batch.hits[0].model_copy(
        update={"scope": scope.model_copy(update={"project_id": "other"})}
    )
    result = builder.build(
        scope, **(args | {"batches": (batch.model_copy(update={"hits": (alien,)}),)})
    )
    assert result.status == "context_insufficient"


def test_rehashed_forged_text_is_not_source_evidence(context):
    builder, scope, args, _ = context
    package = builder.build(scope, **args).package
    item = package.items[0].model_copy(
        update={"text": "Invented.\n", "selected_sha256": sha256(b"Invented.\n")}
    )
    forged = package.model_copy(update={"items": (item, *package.items[1:])})
    forged = forged.model_copy(update={"input_estimate": estimate(forged.task, forged.items)})
    digest = package_digest(forged)
    forged = forged.model_copy(update={"package_hash": digest, "package_id": digest})
    assert not valid(builder, scope, args, forged)


def test_missing_context_is_explicit(context):
    builder, scope, args, _ = context
    for changes in (
        {"batches": ()},
        {"task": args["task"].model_copy(update={"required_paths": ("missing.md",)})},
    ):
        result = builder.build(scope, **(args | changes))
        assert result.package is None
        assert result.missing_context == ("required_context_missing",)


def test_default_cap_actually_excludes_content_deterministically(context):
    builder, scope, args, _ = context
    args["task"] = args["task"].model_copy(update={"instructions": "x" * 6300})
    package = builder.build(scope, **args).package
    assert package is not None
    assert package.excluded_sources
    assert package.input_estimate <= package.effective_token_cap == 8000
    assert len(package.task.instructions) == 6300
    changed = args | {"batches": tuple(reversed(args["batches"]))}
    assert builder.build(scope, **changed).package == package


def test_within_query_rank_and_configurable_cap(context):
    builder, scope, args, _ = context
    guide = args["batches"][2].hits[0]
    code = args["batches"][0].hits[0]
    batch = args["batches"][0].model_copy(update={"hits": (guide, code)})
    args["batches"] = (batch,)
    args["policy"] = ContextPolicy(context_token_cap=12000)
    args["task"] = args["task"].model_copy(update={"token_cap": 10000})
    package = builder.build(scope, **args).package
    assert package.effective_token_cap == 10000
    assert [item.sources[0].path for item in package.items] == ["guide.md", "code.py"]
    args["task"] = args["task"].model_copy(update={"focus_paths": ("code.py",)})
    package = builder.build(scope, **args).package
    assert [item.sources[0].path for item in package.items] == ["code.py", "guide.md"]
