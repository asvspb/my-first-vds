# ZeroTier Auto-Join Plan

## Handover from Planning Session

---
## Discoveries

- **ZeroTier container runs with `network_mode: host`** — its Local API is accessible directly at `localhost:9993` from within the container via `docker exec`. No port mapping needed.
- **Controller IS the container itself** — `ztnet_zerotier` is both the ZeroTier node AND the controller. It can authorize itself via its own Controller API, eliminating the need for manual ZTNET Panel authorization.
- **`authtoken.secret`** is located at `/var/lib/zerotier-one/authtoken.secret` inside the container. Needed for all Local API calls (`X-ZT1-Auth` header).
- **`ZT_ADDR`** (node address) is already captured at line 145 from `zerotier-cli info` output — reused for member API endpoint `/controller/network/{NETWORK_ID}/member/{ZT_ADDR}`.
- **`ZT_SUBNET="10.121.15.0/24"` is hardcoded at line 334** — used for iptables NAT/FORWARD rules throughout the script (steps 5, 7, zt-nat-setup.sh, .env.info). This will likely NOT match the actual subnet ZTNET assigns, making dynamic detection critical.
- **`curl` is used inside `docker exec`** — the container image `zyclonite/zerotier:1.14.2` has `curl` available (already used in healthchecks). No need to install it.
- **No `jq` guaranteed on host or container** — JSON parsing must use grep/sed with fallbacks.
- **Step numbering mismatch**: step headers say "Шаг 7/7" and "Шаг 8/8" — actually 8 steps total, not 7. The header at line 122 says "ШАГ 1/7" but there are 8 steps.

## Relevant Files

- **`zt-install.sh`** (694 lines) — main file to modify
  - Line 145: `ZT_ADDR` — node address, needed for Controller API member endpoint
  - Lines 254–280: zerotier container definition (`network_mode: host`, `authtoken.secret` path)
  - Line 334: hardcoded `ZT_SUBNET="10.121.15.0/24"` — needs dynamic override
  - Lines 354–384: iptables NAT rules using `ZT_SUBNET` — need updating when subnet changes
  - Lines 466–472: ZT_INFO check — insertion point for `ZT_AUTHTOKEN` extraction
  - Lines 509–561: `zt-nat-setup.sh` template — uses `$ZT_SUBNET` variable, needs regeneration with dynamic value
  - Lines 566–585: `zt-nat-setup.service` systemd unit
  - Lines 590–641: Step 8 — main rewrite target
  - Lines 646–694: Final summary output — needs updated messaging
- **`README.md`** — project documentation (not modified in this task)

## Implementation Notes

- **Execution order matters**: `ZT_AUTHTOKEN` must be extracted AFTER containers are running (step 6) but BEFORE step 8. Best insertion point is ~line 470, right after the ZT_INFO check.
- **iptables `-D` (delete) before `-A`/`-I` (add)**: When updating ZT_SUBNET rules, delete old rules first. Use `-D` with full rule specification matching the old rules. The `|| true` is essential since rules may not exist.
- **OpenVZ branch**: When replacing MASQUERADE rules for OpenVZ, remember to use SNAT instead (lines 357–361). The dynamic update must also handle this branch.
- **`zt-nat-setup.sh` template uses `source /opt/ztnet/.env.info`** (line 514) — if `.env.info` is updated with the dynamic `ZT_SUBNET`, the nat-setup script will pick it up automatically on next run. But the embedded template should also be regenerated for consistency.
- **Route API gotcha**: The Controller API endpoint `POST /controller/network/{NETWORK_ID}` accepts a JSON body with `routes` field that REPLACES all routes. Must GET current routes first, append the new one, then POST the full array back.
- **`read -r NETWORK_ID` at line 602**: The script uses `set -euo pipefail` (line 13). If `read` returns empty and is used in a pipeline, it could cause an exit. The current code handles this with the `if [[ -z "${NETWORK_ID}" ]]` check — preserve this pattern.

## Changes Summary

1. **Save this plan** as `docs/zt-auto-join-plan.md`
2. **Fix step numbering** to 1/8 through 8/8
3. **Insert `ZT_AUTHTOKEN` extraction** after ZT_INFO check (after containers are running)
4. **Rewrite step 8** with auto-join flow:
   - Join network via `zerotier-cli join`
   - Self-authorize via Controller API (`POST /controller/network/{NETWORK_ID}/member/{ZT_ADDR}`)
   - Wait for ZT-IP assignment
   - Detect actual ZT subnet from Controller API
   - Update iptables rules if subnet changed
   - Add managed route `0.0.0.0/0` via Controller API
   - Regenerate `.env.info` and `zt-nat-setup.sh` with dynamic values
5. **Update final summary** to reflect auto-join capabilities
