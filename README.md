# cemu_re_mcp

MCP server wrapping Cemu's built-in GDB stub for live runtime analysis of Wii U games. Companion to [dolphin_re_mcp](../dolphin_re_mcp/) but built fresh — same MCP-shaped tool surface, different protocol layer.

Target game: Monster Hunter 3 Ultimate (MH3U), but format-agnostic for any Wii U title.

## Quick start

1. **Enable GDB stub in Cemu:**
   - Menu: `Debug → Launch with GDB stub`
   - Default port is `1337`
   - Restart Cemu and launch your game
2. **Install the MCP server:**
   ```
   cd E:\cemu_re_mcp
   pip install -e .
   ```
3. **Wire into Claude Code via `.mcp.json`:**
   ```json
   {
     "mcpServers": {
       "cemu": {
         "command": "python",
         "args": ["-m", "cemu_re_mcp.server"]
       }
     }
   }
   ```

## What it does

Cemu ships a [GDB Remote Serial Protocol](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Remote-Protocol.html) stub. This MCP server speaks that protocol over a TCP socket and exposes the primitives Claude needs for runtime reverse engineering:

- Connect / disconnect / health check
- Pause / resume / step
- Read & write memory (raw bytes, typed `u8/u16/u32/f32/s32`)
- Read & write registers (GPRs, FPRs, PC, LR, CTR, SPRs)
- Set / clear breakpoints + read/write watchpoints
- Wait-for-hit (block until a BP/WP fires; capture context)
- Higher-level helpers (struct read, pointer chase, memory search, hex dump, disasm)

## Why not fork dolphin_re_mcp

Cemu and Dolphin differ at the GDB-stub level in subtle ways (register set, address space layout, breakpoint kinds). A clean reimplementation is faster than reverse-grafting Cemu's quirks onto Dolphin's assumptions. Sister project for reference design only.

## Architecture

```
src/cemu_re_mcp/
  gdb_rsp.py     — GDB Remote Serial Protocol client (stdlib sockets, no deps)
  server.py      — MCP server entrypoint, tool wrappers
  state.py       — Connection state + paused/running tracking
```

## Status

- [x] Project skeleton
- [x] GDB RSP client (packet framing, checksum, RLE expansion)
- [x] MCP server with `connect` / `health_check` / `pause` / `resume`
- [x] Memory R/W tools (raw + typed u8/u16/u32/s32/f32)
- [x] Register tools (PC, LR, all GPRs)
- [x] Breakpoint / watchpoint tools (Z0/Z2/Z3/Z4)
- [ ] `wait_for_hit` (basic impl present; needs real BP-hit test)
- [ ] `capture_on_hit` higher-level helper
- [ ] Symbol-aware helpers (consume Cemu's coreinit + game symbols)
- [ ] Struct read / pointer chase / memory search helpers

## Cemu GDB stub quirks (confirmed 2026-05-27 with MH3U)

These behaviors are non-standard vs Dolphin's GDB stub; they shape how the MCP
server is designed.

1. **One-shot per game session.** After any TCP disconnect, the stub stops
   listening. Reconnect requires restarting Cemu + reloading the game. The MCP
   server therefore holds ONE long-lived connection for the entire session.

2. **`QStartNoAckMode` is not supported.** Connect skips negotiation and stays
   in always-ack mode (avoids a 5 sec connect-time timeout).

3. **Bare `c` does NOT continue all threads.** Wii U is multi-core; sending `c`
   resumes only the current thread, leaving the game frozen. The client uses
   `vCont;c` for all resumes (and `vCont;s` for steps). `vCont?` reply confirms
   the stub supports `vCont;c;C;s;S` (no per-thread targeting).

4. **No programmatic pause.** `vCtrlC` accepts the packet but doesn't halt. Raw
   `0x03` interrupt byte is silently ignored. To halt: either set a
   breakpoint/watchpoint and let the target stop itself, or pause from Cemu's UI.

5. **Inspection works while target runs.** Unlike most GDB stubs, `m`, `p`, `g`,
   `?` all return real values while the target is actively executing. No need to
   pause for basic memory/register reads. This actually simplifies most tooling
   — only break/step workflows need halt semantics.

6. **Splash halt on launch.** The stub halts the target at boot, before the
   intro plays. Game appears frozen at splash until the first `vCont;c`. Send
   it as the first action after connect, or use `scripts/cemu_resume.py`.

## Notes

- Cemu's main game module loads at `0x02000000` for MH3U US v1.3 (`mh3g_cafe_us`, size `0x11b2550`). First two instructions: `nop; blr`.
- WiiU virtual memory is flat (no MEM1/MEM2 split like Wii) — addresses are 32-bit virtual.
- coreinit symbols (FSAddClient, DCFlushRange, etc.) live around `0x00Exxxxx` and are pre-loaded in Cemu's PPC debugger UI. May be queryable via `qSymbol` (untested).
- Cemu is open-source — if the GDB stub is missing a feature we need (e.g. real pause support), patch the emulator. That's the escape hatch.
