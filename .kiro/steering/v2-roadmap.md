# SSHCustom-Magisk Steering (Auto-loaded)

## Owner
- GitHub: `GoodyOG`
- Repo: `GoodyOG/SSHCustom-Magisk`

## Architecture
- **Module only** — no companion Android app (removed in v2.0.3).
- Users access the dashboard via browser at `http://127.0.0.1:9190/` or through KSU-Next's module WebUI.
- Go daemon (`cmd/sshcustomd/`) cross-compiled for `linux/arm64` and `linux/arm`.
- WebUI is a single HTML file embedded in the binary via `embed.FS` with on-disk override.
- Magisk/KernelSU module shell scripts handle lifecycle (`service.sh`, `action.sh`, `sshcustom.sh`).

## Key decisions
| Topic | Decision |
|---|---|
| License | Apache-2.0 |
| "Save, Use & Restart" | Uses `scheduleControl("restart")` — shells out to `sshcustom.sh restart` which kills+restarts the daemon process |
| API | `/api/v1/*` only, SSE at `/api/v1/events`, no auth (loopback-only) |
| Profile passwords | Plaintext in `profiles.json` (0600), accepted |
| Update channel | Single `update.json` on `main` |
| VERSION file | Single source → `module.prop`, `build.sh`, Go binary `-ldflags` |

## Build verification
```bash
go build ./...
go vet ./...
go test ./...
./build.sh
```

## File layout
```
cmd/sshcustomd/         Go daemon (single package)
internal/{apiv1,dnsx,iptables,metrics,version,webui}/
src/module/             Magisk module template (gets zipped)
  bin/{arm,arm64}/      Prebuilt daemon binaries
  scripts/              Control plane scripts
  webroot/index.html    Dashboard UI
docs/openapi.yaml       API spec
build.sh                Cross-compile + package
scripts/package_module.py  Deterministic ZIP packager
.github/workflows/build.yml  CI: build + release
VERSION                 Version source
```

## Resume after session loss
1. Read this file.
2. `git status` + `git log --oneline -5` to see current state.
3. Run build verification above.
4. Continue from where things left off.
