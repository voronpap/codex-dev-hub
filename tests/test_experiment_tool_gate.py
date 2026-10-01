from devhub.experiment_tool_gate import CLI_VERSION, policy_hash, tool_surface


def test_shell_block_is_independent_of_backend_and_patch_stays_unknown():
    for backend in ("true", "false"):
        result = tool_surface({"shell_tool": "false", "unified_exec": backend}, CLI_VERSION)
        assert result["forbidden_tools_absent"] == {
            "exec_command": True,
            "write_stdin": True,
            "apply_patch": None,
        }
        assert result["forbidden_execution_tools_absent"] is False
        assert result["tool_surface_observation"] == "source_derived"
        assert result["qualification_policy_sha256"] == policy_hash()


def test_unknown_or_enabled_shell_and_wrong_cli_never_prove_absence():
    for features, version in (
        ({}, CLI_VERSION),
        ({"shell_tool": "true"}, CLI_VERSION),
        ({"shell_tool": "false"}, "other"),
    ):
        result = tool_surface(features, version)
        assert result["effective_shell_tool_disabled"] is False
        assert result["forbidden_tools_absent"]["exec_command"] is None
        assert result["forbidden_execution_tools_absent"] is False
