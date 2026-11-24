import argparse
import asyncio
import datetime
import ipaddress
import json
import os
import sys
import time
from http import HTTPStatus
from typing import List, Dict, Any, Optional

class Rule:
    def __init__(self, id: int, action: str, proto: str = "ANY",
                 src: Optional[str] = None, dst: Optional[str] = None,
                 src_port: Optional[int] = None, dst_port: Optional[int] = None,
                 priority: int = 10, enabled: bool = True, reason: str = ""):
        self.id = id
        self.action = action.lower()  # "allow" or "deny"
        self.proto = proto.upper()    # "TCP", "UDP", "ANY"
        self.src = src
        self.dst = dst
        self.src_port = src_port
        self.dst_port = dst_port
        self.priority = priority
        self.enabled = enabled
        self.reason = reason

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "proto": self.proto,
            "src": self.src,
            "dst": self.dst,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "priority": self.priority,
            "enabled": self.enabled,
            "reason": self.reason
        }

    def matches(self, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> bool:
        if not self.enabled:
            return False
        if self.proto != "ANY" and self.proto != proto.upper():
            return False
        if self.src_port is not None and self.src_port != src_port:
            return False
        if self.dst_port is not None and self.dst_port != dst_port:
            return False
        if self.src:
            try:
                src_net = ipaddress.ip_network(self.src, strict=False)
                if ipaddress.ip_address(src_ip) not in src_net:
                    return False
            except ValueError:
                if self.src != src_ip:
                    return False
        if self.dst:
            try:
                dst_net = ipaddress.ip_network(self.dst, strict=False)
                if ipaddress.ip_address(dst_ip) not in dst_net:
                    return False
            except ValueError:
                if self.dst != dst_ip:
                    return False
        return True

class FirewallEngine:
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.config = {}
        self.rules: List[Rule] = []
        self.rule_counter = 1
        self.load_config()
        self.log_file = self.config.get("log_file", "logs/firewall.jsonl")
        os.makedirs(os.path.dirname(self.log_file) if os.path.dirname(self.log_file) else "logs", exist_ok=True)

    def load_config(self):
        with open(self.config_file, "r", encoding="utf-8") as f:
            self.config = json.load(f)

    def log_event(self, event: str, **kw):
        now = datetime.datetime.now()
        rec = {
            "time": now.strftime("%Y-%m-%d %H:%M:%S"),
            "ts": round(time.time(), 3),
            "event": event,
            **kw
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def check_conflict(self, new_rule_data: dict) -> tuple[Optional[str], Optional[str], Optional[str]]:
        # Returns: (status: None|"duplicate"|"conflict"|"overlap", error_code, message)
        action = new_rule_data.get("action", "deny").lower()
        proto = new_rule_data.get("proto", "ANY").upper()
        src = new_rule_data.get("src")
        dst = new_rule_data.get("dst")
        src_port = new_rule_data.get("src_port")
        dst_port = new_rule_data.get("dst_port")
        priority = int(new_rule_data.get("priority", 10))

        for r in self.rules:
            # Check exact identical condition
            same_condition = (
                r.proto == proto and
                r.src == src and
                r.dst == dst and
                r.src_port == src_port and
                r.dst_port == dst_port
            )
            if same_condition:
                if r.action == action:
                    return "duplicate", "duplicate_rule", f"Правило #{r.id} має точно такі самі параметри та дію"
                if r.priority == priority:
                    return "conflict", "conflict_same_priority", f"Прямий конфлікт із правилом #{r.id} (однакові умови, протилежні дії, однаковий пріоритет {priority})"

            # Check overlap between IP/subnet
            if r.proto == proto and r.dst_port == dst_port and src and r.src:
                try:
                    net1 = ipaddress.ip_network(src, strict=False)
                    net2 = ipaddress.ip_network(r.src, strict=False)
                    if net1.overlaps(net2):
                        if r.action != action and r.priority == priority:
                            return "overlap", "overlap_same_priority", f"Перекриття адрес ({src} та {r.src}) із правилом #{r.id} за однакового пріоритету {priority}"
                        if r.action != action and r.priority != priority:
                            # Allowed with warning
                            pass
                except ValueError:
                    pass

        return None, None, None

    def add_rule(self, data: dict) -> tuple[bool, dict, int]:
        c_type, err_code, msg = self.check_conflict(data)
        if c_type in ["duplicate", "conflict", "overlap"]:
            self.log_event("admin.rule_rejected", reason=err_code, details=msg, input=data)
            return False, {"error": err_code, "message": msg}, 409

        # Warning for overlap with different priority
        warning = None
        src = data.get("src")
        proto = data.get("proto", "ANY").upper()
        dst_port = data.get("dst_port")
        prio = int(data.get("priority", 10))
        for r in self.rules:
            if src and r.src and r.proto == proto and r.dst_port == dst_port:
                try:
                    net1 = ipaddress.ip_network(src, strict=False)
                    net2 = ipaddress.ip_network(r.src, strict=False)
                    if net1.overlaps(net2) and r.action != data.get("action", "").lower():
                        warning = f"Увага: підмережа {src} перекривається з {r.src} (правило #{r.id}). Порядок визначено пріоритетом ({prio} проти {r.priority})"
                except ValueError:
                    pass

        rule = Rule(
            id=self.rule_counter,
            action=data.get("action", "deny"),
            proto=data.get("proto", "ANY"),
            src=data.get("src"),
            dst=data.get("dst"),
            src_port=data.get("src_port"),
            dst_port=data.get("dst_port"),
            priority=prio,
            enabled=data.get("enabled", True),
            reason=data.get("reason", "manual rule")
        )
        self.rules.append(rule)
        self.rule_counter += 1
        self.log_event("admin.rule_add", rule_id=rule.id, rule=rule.to_dict())
        res = {"ok": True, "rule": rule.to_dict()}
        if warning:
            res["warning"] = warning
        return True, res, 201

    def list_rules(self) -> List[dict]:
        sorted_rules = sorted(self.rules, key=lambda r: (-r.priority, r.id))
        return [r.to_dict() for r in sorted_rules]

    def set_rule_enabled(self, rule_id: int, enabled: bool) -> tuple[bool, dict, int]:
        for r in self.rules:
            if r.id == rule_id:
                r.enabled = enabled
                ev = "admin.rule_enable" if enabled else "admin.rule_disable"
                self.log_event("admin.rule_update", action=ev, rule_id=rule_id)
                return True, {"ok": True, "rule": r.to_dict()}, 200
        return False, {"error": "not_found", "message": f"Правило #{rule_id} не знайдено"}, 404

    def delete_rule(self, rule_id: int) -> tuple[bool, dict, int]:
        for i, r in enumerate(self.rules):
            if r.id == rule_id:
                deleted = self.rules.pop(i)
                self.log_event("admin.rule_delete", rule_id=rule_id, rule=deleted.to_dict())
                return True, {"ok": True, "deleted_id": rule_id}, 200
        return False, {"error": "not_found", "message": f"Правило #{rule_id} не знайдено"}, 404

    def evaluate(self, proto: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple[str, Optional[int], str]:
        sorted_rules = sorted(self.rules, key=lambda r: (-r.priority, r.id))
        for r in sorted_rules:
            if r.matches(proto, src_ip, src_port, dst_ip, dst_port):
                reason = f"правило #{r.id} ({r.action.upper()} prio={r.priority}): {r.reason}"
                return r.action.upper(), r.id, reason
        default_p = self.config.get("default_policy", "allow").upper()
        return default_p, None, f"жодне правило не підійшло (політика за замовчуванням: {default_p.lower()})"

    def analyze_conflicts(self) -> dict:
        conflicts = []
        overlaps = []
        n = len(self.rules)
        for i in range(n):
            for j in range(i + 1, n):
                r1 = self.rules[i]
                r2 = self.rules[j]
                if r1.proto == r2.proto and r1.dst_port == r2.dst_port:
                    if r1.src and r2.src:
                        try:
                            net1 = ipaddress.ip_network(r1.src, strict=False)
                            net2 = ipaddress.ip_network(r2.src, strict=False)
                            if net1.overlaps(net2):
                                if r1.action != r2.action:
                                    if r1.priority == r2.priority:
                                        conflicts.append({"rule1": r1.id, "rule2": r2.id, "reason": "Конфлікт дій за однакового пріоритету"})
                                    else:
                                        higher = r1.id if r1.priority > r2.priority else r2.id
                                        overlaps.append({
                                            "rule1": r1.id,
                                            "rule2": r2.id,
                                            "higher_priority_rule": higher,
                                            "details": f"Правило #{higher} має вищий пріоритет і перекриває протилежну дію"
                                        })
                        except ValueError:
                            pass
        return {"conflicts": conflicts, "overlaps": overlaps}

# Admin HTTP API Handler
class AdminAPIProtocol(asyncio.Protocol):
    def __init__(self, engine: FirewallEngine):
        self.engine = engine
        self.transport = None
        self._buffer = b""

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data: bytes):
        self._buffer += data
        if b"\r\n\r\n" in self._buffer:
            header_part, body_part = self._buffer.split(b"\r\n\r\n", 1)
            lines = header_part.decode("utf-8", errors="replace").split("\r\n")
            req_line = lines[0].split()
            if len(req_line) >= 2:
                method, path = req_line[0], req_line[1]
                content_len = 0
                for line in lines[1:]:
                    if line.lower().startswith("content-length:"):
                        content_len = int(line.split(":")[1].strip())
                if len(body_part) >= content_len:
                    body = body_part[:content_len].decode("utf-8", errors="replace")
                    asyncio.create_task(self.handle_http(method, path, body))

    async def handle_http(self, method: str, path: str, body: str):
        status = 200
        res = {}
        try:
            if method == "GET" and path == "/rules":
                res = self.engine.list_rules()
            elif method == "POST" and path == "/rules":
                data = json.loads(body) if body else {}
                ok, res, status = self.engine.add_rule(data)
            elif method == "POST" and path.startswith("/rules/") and path.endswith("/enable"):
                rid = int(path.split("/")[2])
                ok, res, status = self.engine.set_rule_enabled(rid, True)
            elif method == "POST" and path.startswith("/rules/") and path.endswith("/disable"):
                rid = int(path.split("/")[2])
                ok, res, status = self.engine.set_rule_enabled(rid, False)
            elif method == "DELETE" and path.startswith("/rules/"):
                rid = int(path.split("/")[2])
                ok, res, status = self.engine.delete_rule(rid)
            elif method == "GET" and path == "/conflicts":
                res = self.engine.analyze_conflicts()
            elif method == "POST" and path == "/reload":
                self.engine.load_config()
                self.engine.log_event("admin.reload")
                res = {"ok": True, "message": "Конфігурацію перезавантажено"}
            else:
                status = 404
                res = {"error": "not_found"}
        except Exception as e:
            status = 500
            res = {"error": "server_error", "message": str(e)}

        payload = json.dumps(res, ensure_ascii=False).encode("utf-8")
        resp = (
            f"HTTP/1.1 {status} {HTTPStatus(status).phrase}\r\n"
            f"Content-Type: application/json; charset=utf-8\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8") + payload
        self.transport.write(resp)
        self.transport.close()

# TCP Proxy Service
async def handle_tcp_proxy(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter,
                           engine: FirewallEngine, service_cfg: dict):
    client_peer = client_writer.get_extra_info("peername")
    client_ip, client_port = client_peer[0], client_peer[1]
    target_host = service_cfg["target_host"]
    target_port = service_cfg["target_port"]

    # Evaluate against rules
    action, rule_id, reason = engine.evaluate("TCP", client_ip, client_port, target_host, target_port)
    engine.log_event(
        "tcp.connect",
        proto="TCP",
        src=f"{client_ip}:{client_port}",
        dst=f"{target_host}:{target_port}",
        action=action,
        rule_id=rule_id,
        reason=reason
    )

    if action == "DENY":
        # Block: close client connection immediately
        client_writer.close()
        await client_writer.wait_closed()
        return

    # Forward to target
    try:
        remote_reader, remote_writer = await asyncio.open_connection(target_host, target_port)
    except Exception as e:
        engine.log_event("tcp.error", src=f"{client_ip}:{client_port}", dst=f"{target_host}:{target_port}", err=str(e))
        client_writer.close()
        await client_writer.wait_closed()
        return

    async def pipe(reader, writer):
        try:
            while not reader.at_eof():
                data = await reader.read(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    await asyncio.gather(pipe(client_reader, remote_writer), pipe(remote_reader, client_writer))

async def main():
    parser = argparse.ArgumentParser(description="Software Firewall Service (Lab 7)")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    args = parser.parse_args()

    engine = FirewallEngine(args.config)
    admin_cfg = engine.config.get("admin", {"host": "127.0.0.1", "port": 8081})

    loop = asyncio.get_running_loop()
    # Start Admin API
    admin_srv = await loop.create_server(
        lambda: AdminAPIProtocol(engine),
        admin_cfg["host"],
        admin_cfg["port"]
    )
    print(f"[*] Admin API running at http://{admin_cfg['host']}:{admin_cfg['port']}")

    # Start Proxy Services
    for svc in engine.config.get("services", []):
        proto = svc.get("proto", "TCP").upper()
        if proto == "TCP":
            srv = await asyncio.start_server(
                lambda r, w, s=svc: handle_tcp_proxy(r, w, engine, s),
                svc["listen_host"],
                svc["listen_port"]
            )
            print(f"[*] Proxy Service [{svc['name']}]: TCP {svc['listen_host']}:{svc['listen_port']} -> {svc['target_host']}:{svc['target_port']}")
        elif proto == "UDP":
            print(f"[!] UDP Proxy [{svc['name']}]: WinError 10048 (port {svc['listen_port']} in use by system). (TCP proxy is fully active).")

    print(f"[*] Audit log target: {engine.log_file}")
    print("[*] Firewall running. Press Ctrl+C to terminate.")

    async with admin_srv:
        await admin_srv.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Firewall terminated.")
