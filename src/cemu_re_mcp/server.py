"""MCP server entrypoint for cemu_re_mcp.

Exposes Cemu's GDB stub as a set of MCP tools for runtime reverse engineering.

Start Cemu with: Debug -> Launch with GDB stub (default port 1337). Then
register this server in your project's `.mcp.json` and call `connect_tool`
once per session.

PowerPC register mapping (Cemu / Espresso, Wii U):
    0-31   r0-r31 (GPRs)
    32-63  f0-f31 (FPRs, 64-bit each)
    64     PC
    65     MSR
    66     CR
    67     LR
    68     CTR
    69     XER
The actual numbering is stub-dependent; verify via Cemu's PPC debugger window
if a register read returns unexpected bytes.
"""
from __future__ import annotations

import struct
from typing import Optional

from mcp.server.fastmcp import FastMCP

from .gdb_rsp import GdbRsp, GdbRspError, StopReason

mcp = FastMCP("cemu")

# Module-level singleton — the MCP server lives in a single process so one
# client connection is enough. If we ever need parallel sessions, this becomes
# a connection pool.
_client: Optional[GdbRsp] = None


def _require_client() -> GdbRsp:
    if _client is None or not _client.is_connected():
        raise RuntimeError("not connected — call connect_tool first")
    return _client


# ---------- connection lifecycle ----------

@mcp.tool()
def health_check_tool() -> dict:
    """Confirm the MCP server is alive. Does NOT require a Cemu connection."""
    return {
        "status": "ok",
        "connected_to_cemu": _client is not None and _client.is_connected(),
    }


@mcp.tool()
def connect_tool(host: str = "127.0.0.1", port: int = 1337, timeout: float = 5.0) -> dict:
    """Open a TCP connection to Cemu's GDB stub. Default port 1337."""
    global _client
    if _client is not None and _client.is_connected():
        return {"status": "already_connected", "host": _client.host, "port": _client.port}
    _client = GdbRsp(host=host, port=port, timeout=timeout)
    _client.connect()
    return {"status": "connected", "host": host, "port": port, "no_ack_mode": _client._no_ack}


@mcp.tool()
def disconnect_tool() -> dict:
    """Close the GDB connection. Cemu and the game keep running."""
    global _client
    if _client is None:
        return {"status": "not_connected"}
    _client.close()
    _client = None
    return {"status": "disconnected"}


# ---------- execution control ----------

@mcp.tool()
def pause_tool() -> dict:
    """Attempt to halt the running target.

    NOTE: Cemu's GDB stub does NOT implement programmatic pause. Both `vCtrlC`
    and the raw 0x03 interrupt byte are accepted but do not actually halt the
    target. To halt Cemu, the USER must press Pause in Cemu's UI, or you must
    set a breakpoint/watchpoint and `wait_for_hit_tool`. This tool sends the
    interrupt as a best-effort but will likely return a timeout."""
    c = _require_client()
    c.interrupt()
    try:
        stop = c.wait_for_stop(timeout=1.0)
        return {"status": "paused", "signal": stop.signal, "raw": stop.raw}
    except Exception as e:
        return {
            "status": "interrupt_ignored",
            "note": "Cemu does not implement programmatic pause. Use BP/WP + wait_for_hit, or pause via Cemu's UI.",
            "error": str(e),
        }


@mcp.tool()
def resume_tool() -> dict:
    """Continue execution. Does NOT block — use wait_for_hit to block until next stop."""
    c = _require_client()
    c.cont()
    return {"status": "resumed"}


@mcp.tool()
def step_tool() -> dict:
    """Single-step one PPC instruction. Blocks for the resulting stop."""
    c = _require_client()
    stop = c.step()
    return {"status": "stopped", "signal": stop.signal, "raw": stop.raw}


@mcp.tool()
def wait_for_hit_tool(timeout: float = 30.0) -> dict:
    """Block until the target hits a breakpoint, watchpoint, or other stop event."""
    c = _require_client()
    try:
        stop = c.wait_for_stop(timeout=timeout)
        return {"status": "stopped", "signal": stop.signal, "raw": stop.raw}
    except Exception as e:
        return {"status": "timeout", "error": str(e)}


@mcp.tool()
def is_paused_tool() -> dict:
    """Query halt reason. Note: GDB stubs always have a 'last halt reason' even
    if the target is currently running — this is best-effort."""
    c = _require_client()
    try:
        stop = c.query_halt_reason()
        return {"signal": stop.signal, "raw": stop.raw}
    except GdbRspError as e:
        return {"error": str(e)}


# ---------- memory: raw ----------

@mcp.tool()
def read_mem_tool(addr: str, length: int) -> dict:
    """Read `length` bytes from `addr`. addr is hex string like '0x02000000' or decimal."""
    c = _require_client()
    a = int(addr, 0)
    data = c.read_mem(a, length)
    return {"addr": f"0x{a:08x}", "length": length, "hex": data.hex()}


@mcp.tool()
def write_mem_tool(addr: str, hex_data: str) -> dict:
    """Write raw bytes (hex-encoded string) to `addr`."""
    c = _require_client()
    a = int(addr, 0)
    data = bytes.fromhex(hex_data)
    c.write_mem(a, data)
    return {"addr": f"0x{a:08x}", "wrote": len(data)}


# ---------- memory: typed (big-endian) ----------

@mcp.tool()
def read_u8_tool(addr: str) -> dict:
    c = _require_client()
    a = int(addr, 0)
    return {"addr": f"0x{a:08x}", "value": c.read_mem(a, 1)[0]}


@mcp.tool()
def read_u16_tool(addr: str) -> dict:
    c = _require_client()
    a = int(addr, 0)
    v = struct.unpack(">H", c.read_mem(a, 2))[0]
    return {"addr": f"0x{a:08x}", "value": v, "hex": f"0x{v:04x}"}


@mcp.tool()
def read_u32_tool(addr: str) -> dict:
    c = _require_client()
    a = int(addr, 0)
    v = struct.unpack(">I", c.read_mem(a, 4))[0]
    return {"addr": f"0x{a:08x}", "value": v, "hex": f"0x{v:08x}"}


@mcp.tool()
def read_s32_tool(addr: str) -> dict:
    c = _require_client()
    a = int(addr, 0)
    v = struct.unpack(">i", c.read_mem(a, 4))[0]
    return {"addr": f"0x{a:08x}", "value": v}


@mcp.tool()
def read_f32_tool(addr: str) -> dict:
    c = _require_client()
    a = int(addr, 0)
    v = struct.unpack(">f", c.read_mem(a, 4))[0]
    return {"addr": f"0x{a:08x}", "value": v}


@mcp.tool()
def write_u32_tool(addr: str, value: int) -> dict:
    c = _require_client()
    a = int(addr, 0)
    c.write_mem(a, struct.pack(">I", value & 0xFFFFFFFF))
    return {"addr": f"0x{a:08x}", "wrote": value}


@mcp.tool()
def write_f32_tool(addr: str, value: float) -> dict:
    c = _require_client()
    a = int(addr, 0)
    c.write_mem(a, struct.pack(">f", value))
    return {"addr": f"0x{a:08x}", "wrote": value}


# ---------- registers ----------

@mcp.tool()
def get_gprs_tool() -> dict:
    """Read all 32 general-purpose registers (r0-r31) as big-endian u32s."""
    c = _require_client()
    raw = c.read_all_registers()
    # First 32 registers * 4 bytes each = 128 bytes for GPRs
    gprs = struct.unpack(">32I", raw[:128])
    return {f"r{i}": f"0x{v:08x}" for i, v in enumerate(gprs)}


@mcp.tool()
def get_pc_tool() -> dict:
    """Read program counter (PPC reg #64 in standard mapping; verify against Cemu)."""
    c = _require_client()
    raw = c.read_register(64)
    v = struct.unpack(">I", raw)[0]
    return {"pc": f"0x{v:08x}"}


@mcp.tool()
def get_lr_tool() -> dict:
    """Read link register (PPC reg #67 in standard mapping)."""
    c = _require_client()
    raw = c.read_register(67)
    v = struct.unpack(">I", raw)[0]
    return {"lr": f"0x{v:08x}"}


# ---------- breakpoints / watchpoints ----------

@mcp.tool()
def add_breakpoint_tool(addr: str) -> dict:
    """Set a software breakpoint at `addr`. PPC instruction width is 4 bytes."""
    c = _require_client()
    a = int(addr, 0)
    c.add_breakpoint(a, kind=4)
    return {"status": "set", "addr": f"0x{a:08x}"}


@mcp.tool()
def remove_breakpoint_tool(addr: str) -> dict:
    c = _require_client()
    a = int(addr, 0)
    c.remove_breakpoint(a, kind=4)
    return {"status": "removed", "addr": f"0x{a:08x}"}


@mcp.tool()
def add_watchpoint_tool(addr: str, length: int = 4, kind: str = "w") -> dict:
    """Set a watchpoint. kind in {'w' write, 'r' read, 'a' access (rw)}."""
    c = _require_client()
    a = int(addr, 0)
    c.add_watchpoint(a, length, kind)
    return {"status": "set", "addr": f"0x{a:08x}", "length": length, "kind": kind}


@mcp.tool()
def remove_watchpoint_tool(addr: str, length: int = 4, kind: str = "w") -> dict:
    c = _require_client()
    a = int(addr, 0)
    c.remove_watchpoint(a, length, kind)
    return {"status": "removed", "addr": f"0x{a:08x}", "length": length, "kind": kind}


# ---------- high-level helpers ----------

@mcp.tool()
def capture_on_hit_tool(
    bp_addr: str,
    mem_addr: Optional[str] = None,
    mem_len: int = 0,
    capture_regs: bool = True,
    timeout: float = 30.0,
    auto_resume: bool = False,
    auto_remove_bp: bool = True,
) -> dict:
    """Set a breakpoint, wait for it to fire, snapshot context, return.

    Workhorse for runtime tracing — e.g. "set BP at the damage-apply function,
    wait for it to hit, snapshot all GPRs + the entity struct it points at."

    Args:
        bp_addr: address (hex string or decimal) to set the BP at
        mem_addr: optional address to snapshot bytes from when BP hits
        mem_len: how many bytes to snapshot at mem_addr (ignored if mem_addr None)
        capture_regs: include all GPRs + PC + LR in the snapshot
        timeout: seconds to wait for the BP to fire before giving up
        auto_resume: if True, send vCont;c after capture (BP will re-fire on next hit if not removed)
        auto_remove_bp: if True, remove the BP after the hit (so it's one-shot)

    Returns dict with: hit (bool), signal, raw_stop, regs (if requested),
    memory (hex, if requested), and a note describing what was captured.
    """
    c = _require_client()
    a = int(bp_addr, 0)

    c.add_breakpoint(a, kind=4)
    try:
        try:
            stop = c.wait_for_stop(timeout=timeout)
        except Exception as e:
            return {
                "hit": False,
                "bp_addr": f"0x{a:08x}",
                "error": f"BP did not fire within {timeout}s: {e}",
            }

        result: dict = {
            "hit": True,
            "bp_addr": f"0x{a:08x}",
            "signal": stop.signal,
            "raw_stop": stop.raw,
        }

        if capture_regs:
            try:
                raw = c.read_all_registers()
                gprs = struct.unpack(">32I", raw[:128])
                result["regs"] = {f"r{i}": f"0x{v:08x}" for i, v in enumerate(gprs)}
                try:
                    pc_raw = c.read_register(64)
                    result["regs"]["pc"] = f"0x{struct.unpack('>I', pc_raw)[0]:08x}"
                except Exception:
                    pass
                try:
                    lr_raw = c.read_register(67)
                    result["regs"]["lr"] = f"0x{struct.unpack('>I', lr_raw)[0]:08x}"
                except Exception:
                    pass
            except Exception as e:
                result["regs_error"] = str(e)

        if mem_addr is not None and mem_len > 0:
            try:
                ma = int(mem_addr, 0)
                data = c.read_mem(ma, mem_len)
                result["memory"] = {"addr": f"0x{ma:08x}", "length": mem_len, "hex": data.hex()}
            except Exception as e:
                result["memory_error"] = str(e)

        return result
    finally:
        if auto_remove_bp:
            try:
                c.remove_breakpoint(a, kind=4)
            except Exception:
                pass
        if auto_resume:
            try:
                c.cont()
            except Exception:
                pass


# ---------- entrypoint ----------

def main() -> None:
    """Console-script entrypoint (`cemu-re-mcp`)."""
    mcp.run()


if __name__ == "__main__":
    main()
