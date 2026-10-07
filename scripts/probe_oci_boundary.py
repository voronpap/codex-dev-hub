"""Offline Linux OCI boundary test, FROM scratch: no network pull or model invocation."""

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

from devhub.benchmark import digest
from devhub.experiment import PlannedSession
from devhub.experiment_launch import DOCKER, ContainerRuntimeSpec, container_command
from devhub.qualification import load_context, receipt_header

C_SOURCE = r"""
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
int has(const char *path, const char *wanted) {
  FILE *f=fopen(path,"r"); if (!f) return 0;
  char b[8192]; size_t n=fread(b,1,sizeof(b)-1,f); b[n]=0; fclose(f);
  return strstr(b,wanted)!=NULL;
}
int main(int argc, char **argv) {
  if (argc != 4) return 2;
  int hidden = access(argv[1], F_OK) != 0;
  int other = access(argv[2], F_OK) != 0;
  int oracle = access(argv[3], F_OK) != 0;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr = { .sin_family=AF_INET, .sin_port=htons(443) };
  inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);
  int denied = connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0;
  close(fd);
  int allowed = 1;
  DIR *d = opendir("/bridge"); struct dirent *entry;
  if (!d) return 3;
  while ((entry = readdir(d))) {
    if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..") &&
        strcmp(entry->d_name,"proxy.sock")) allowed = 0;
  }
  closedir(d);
  int home = access("/home/runner/.codex", F_OK) != 0;
  int control = access("/control/session.json", R_OK) == 0;
  int readonly = access("/control/session.json", W_OK) != 0;
  int task_hidden = access("/packet/input.txt", F_OK) != 0 &&
                    access("/packet/task.txt", F_OK) != 0 &&
                    access("/packet/instructions.txt", F_OK) != 0;
  int packet_writable = access("/packet", W_OK) == 0;
  int uid = geteuid() == 1000;
  int caps = has("/proc/self/status", "CapEff:\t0000000000000000") &&
             has("/proc/self/status", "CapBnd:\t0000000000000000");
  int nnp = has("/proc/self/status", "NoNewPrivs:\t1");
  int limits = has("/sys/fs/cgroup/memory.max", "2147483648") &&
               has("/sys/fs/cgroup/pids.max", "128") &&
               has("/sys/fs/cgroup/cpu.max", "200000 100000");
  int docker = access("/var/run/docker.sock", F_OK) != 0;
  int hosthome = access("/root/.codex", F_OK) != 0 && access("/mnt/c/Users", F_OK) != 0;
  int repo = access("/workspace/.git", F_OK) != 0 && access("/app/src/devhub", F_OK) != 0;
  printf("{\"host_canary_hidden\":%s,\"other_arm_hidden\":%s,"
         "\"source_and_oracle_hidden\":%s,\"network_denied\":%s,"
         "\"only_scoped_bridges\":%s,\"fresh_home\":%s,"
         "\"control_readable\":%s,\"control_readonly\":%s,"
         "\"task_files_initially_hidden\":%s,\"packet_tmpfs_writable\":%s,"
         "\"nonroot\":%s,\"capabilities_dropped\":%s,"
         "\"no_new_privileges\":%s,\"resource_limits_effective\":%s,"
         "\"docker_socket_absent\":%s,\"host_home_absent\":%s,\"repository_absent\":%s}\n",
         hidden?"true":"false", other?"true":"false", oracle?"true":"false",
         denied?"true":"false", allowed?"true":"false", home?"true":"false",
         control?"true":"false", readonly?"true":"false", task_hidden?"true":"false",
         packet_writable?"true":"false", uid?"true":"false", caps?"true":"false",
         nnp?"true":"false", limits?"true":"false", docker?"true":"false",
         hosthome?"true":"false", repo?"true":"false");
  return !(hidden && other && oracle && denied && allowed && home && control && readonly &&
           task_hidden && packet_writable && uid &&
           caps && nnp && limits && docker && hosthome && repo);
}
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--context", type=Path, required=True)
    opts = parser.parse_args()
    context = load_context(opts.context)
    if opts.image_id and not re.fullmatch(r"sha256:[a-f0-9]{64}", opts.image_id):
        parser.error("Only an immutable local image ID is allowed")
    with tempfile.TemporaryDirectory(prefix="devhub-isolation-") as temporary:
        root = Path(temporary)
        (root / "probe.c").write_text(C_SOURCE)
        subprocess.run(
            ["gcc", "-static", "-O2", str(root / "probe.c"), "-o", str(root / "probe")], check=True
        )
        (root / "Dockerfile").write_text("FROM scratch\nCOPY probe /probe\n")
        image = opts.image_id or (
            subprocess.check_output([*DOCKER, "build", "--network=none", "-q", str(root)])
            .decode()
            .strip()
        )
        packet = root / "control"
        packet.mkdir()
        (packet / "session.json").write_text("synthetic control only")
        bridge = root / "bridge"
        bridge.mkdir()
        (bridge / "proxy.sock").touch()
        capture = root / "capture"
        capture.mkdir()
        capture.chmod(0o777)
        bootstrap = Path(__file__).resolve().parent / "benchmark_guest.py"
        auth = root / "auth.json"
        auth.write_text("{}")
        forbidden = []
        for name in ("host-canary", "opposite-arm", "oracle-canary"):
            path = root / name
            path.write_text("not visible")
            forbidden.append(str(path))
        runtime = ContainerRuntimeSpec(
            image_id=image,
            bootstrap_sha256=digest(bootstrap.read_bytes()),
            protocol_sha256="0" * 64,
            reviewed_plan_sha256="0" * 64,
            codex_cli_version="not invoked",
        )
        session = PlannedSession(
            order=1,
            fixture_id="synthetic-only",
            fixture_sha256="0" * 64,
            oracle_sha256="0" * 64,
            arm="A",
            session_id="devhub-isolation-probe",
            packet_path="synthetic",
            available_mcp_tools=(),
        )
        args = container_command(session, runtime, packet, bridge, capture, bootstrap, auth)
        args[len(DOCKER)] = "run"
        args.insert(len(DOCKER) + 1, "--rm")
        pos = args.index("--entrypoint")
        args[pos + 1] = "/probe"
        args = (
            args[:pos]
            + ["--mount", f"type=bind,src={root / 'probe'},dst=/probe,readonly"]
            + args[pos : pos + 3]
            + forbidden
        )
        try:
            raw = subprocess.check_output(args, timeout=30)
            checks = json.loads(raw)
            assert all(value is True for value in checks.values())
            evidence = {
                **receipt_header(context, "isolation"),
                "kind": "synthetic_oci_isolation_probe",
                "image_id": image,
                "bootstrap_sha256": digest(bootstrap.read_bytes()),
                "checks": checks,
                "codex_executions": 0,
                "provider_sends": 0,
                "runtime_image_qualification": bool(opts.image_id),
                "qualification_passed": bool(opts.image_id),
                "limitation": "Kernel boundary only; Codex preflight still required.",
            }
            if opts.output:
                with opts.output.open("x", encoding="utf-8") as stream:
                    json.dump(evidence, stream, indent=2)
                    stream.write("\n")
            print(json.dumps(evidence))

        finally:
            if not opts.image_id:
                subprocess.run([*DOCKER, "image", "rm", image], check=False, capture_output=True)


if __name__ == "__main__":
    main()
