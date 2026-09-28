"""Local entry points. Stdout is reserved for MCP messages while serving."""

import argparse
import json
import sys
from pathlib import Path

from devhub.config import ConfigError, HubConfig, load_config
from devhub.models import ModelResult, StatusRequest, StatusResponse, TaskRequest


def schemas() -> dict[str, object]:
    models = (HubConfig, StatusRequest, StatusResponse, TaskRequest, ModelResult)
    return {model.__name__: model.model_json_schema() for model in models}


def main() -> int:
    parser = argparse.ArgumentParser(prog="devhub")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start the offline MCP stdio server")
    serve.add_argument("--transport", choices=["stdio"], default="stdio")
    serve.add_argument("--config", required=True, type=Path)
    validate = commands.add_parser("validate-config")
    validate.add_argument("--config", required=True, type=Path)
    commands.add_parser("schema", help="Print Stage 1 JSON Schemas")
    args = parser.parse_args()
    if args.command == "schema":
        print(json.dumps(schemas(), indent=2, sort_keys=True))
        return 0
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"devhub: {exc}", file=sys.stderr)
        return 2
    if args.command == "validate-config":
        print("Configuration valid: offline Stage 1.")
        return 0
    from devhub.server import create_server

    create_server(config).run(transport="stdio")
    return 0
