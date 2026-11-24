import argparse
import json
import sys
import urllib.request
import urllib.error

API_URL = "http://127.0.0.1:8081"

def api_request(method: str, path: str, data: dict = None):
    url = f"{API_URL}{path}"
    headers = {"Content-Type": "application/json"}
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        return e.code, json.loads(content) if content else {"error": e.reason}
    except Exception as e:
        print(f"[!] Не вдалося з'єднатися з Admin API ({url}): {e}")
        sys.exit(1)

def cmd_list(args):
    status, rules = api_request("GET", "/rules")
    if not rules:
        print("(правил немає)")
        return
    print(f"{'#':<4} {'ACTION':<7} {'PROTO':<6} {'SRC':<18} {'DST':<18} {'PORT':<6} {'PRIO':<5} {'ENABLED':<8} {'REASON'}")
    print("-" * 88)
    for r in rules:
        src = r.get("src") or "*"
        dst = r.get("dst") or "*"
        port = str(r.get("dst_port") or "*")
        enabled = "yes" if r.get("enabled") else "no (disabled)"
        print(f"{r['id']:<4} {r['action'].upper():<7} {r['proto']:<6} {src:<18} {dst:<18} {port:<6} {r['priority']:<5} {enabled:<8} {r.get('reason','')}")

def cmd_add(args):
    payload = {
        "action": args.action,
        "proto": args.proto.upper(),
        "src": args.src,
        "dst": args.dst,
        "src_port": args.src_port,
        "dst_port": args.dst_port,
        "priority": args.priority,
        "reason": args.reason
    }
    status, res = api_request("POST", "/rules", payload)
    if status in [200, 201]:
        r = res.get("rule", {})
        print(f"[+] Додано правило #{r.get('id')}: {r.get('action').upper()} {r.get('proto')} src={r.get('src') or '*'} dst_port={r.get('dst_port') or '*'} (prio={r.get('priority')})")
        if "warning" in res:
            print(f"[!] {res['warning']}")
    else:
        err = res.get("error", "unknown_error")
        msg = res.get("message", "")
        print(f"[!] Помилка додавання правила (код {status}, {err}): {msg}")

def cmd_enable(args):
    status, res = api_request("POST", f"/rules/{args.id}/enable")
    if status == 200:
        print(f"[+] Правило #{args.id} увімкнено")
    else:
        print(f"[!] Помилка: {res.get('message', res)}")

def cmd_disable(args):
    status, res = api_request("POST", f"/rules/{args.id}/disable")
    if status == 200:
        print(f"[+] Правило #{args.id} вимкнено")
    else:
        print(f"[!] Помилка: {res.get('message', res)}")

def cmd_delete(args):
    status, res = api_request("DELETE", f"/rules/{args.id}")
    if status == 200:
        print(f"[+] Правило #{args.id} видалено")
    else:
        print(f"[!] Помилка: {res.get('message', res)}")

def cmd_conflicts(args):
    status, res = api_request("GET", "/conflicts")
    conflicts = res.get("conflicts", [])
    overlaps = res.get("overlaps", [])
    print("=== Аналіз конфліктів та перекриттів правил ===")
    if not conflicts and not overlaps:
        print("[+] Конфліктів та неоднозначностей не виявлено.")
        return
    if conflicts:
        print(f"\n[!] Виявлено прямих конфліктів: {len(conflicts)}")
        for c in conflicts:
            print(f"  - Правило #{c['rule1']} та #{c['rule2']}: {c['reason']}")
    if overlaps:
        print(f"\n[*] Виявлено перекриття правил (вирішуються за пріоритетом): {len(overlaps)}")
        for o in overlaps:
            print(f"  - Правило #{o['rule1']} та #{o['rule2']}: {o['details']}")

def cmd_reload(args):
    status, res = api_request("POST", "/reload")
    print(res.get("message", "OK"))

def main():
    parser = argparse.ArgumentParser(description="Firewall Management CLI (fwctl)")
    subparsers = parser.add_subparsers(dest="command")

    # list
    subparsers.add_parser("list", help="Список усіх правил")

    # add
    p_add = subparsers.add_parser("add", help="Додати нове правило")
    p_add.add_argument("--action", choices=["allow", "deny"], required=True)
    p_add.add_argument("--proto", choices=["TCP", "UDP", "ANY"], default="ANY")
    p_add.add_argument("--src", help="IP джерела або підмережа CIDR")
    p_add.add_argument("--dst", help="IP призначення")
    p_add.add_argument("--src-port", type=int, help="Порт джерела")
    p_add.add_argument("--dst-port", type=int, help="Порт призначення")
    p_add.add_argument("--priority", type=int, default=10, help="Пріоритет (вищий = пріоритетніший)")
    p_add.add_argument("--reason", default="manual rule", help="Причина або опис правила")

    # enable
    p_en = subparsers.add_parser("enable", help="Увімкнути правило")
    p_en.add_argument("id", type=int)

    # disable
    p_dis = subparsers.add_parser("disable", help="Вимкнути правило")
    p_dis.add_argument("id", type=int)

    # delete
    p_del = subparsers.add_parser("delete", help="Видалити правило")
    p_del.add_argument("id", type=int)

    # conflicts
    subparsers.add_parser("conflicts", help="Перевірити конфлікти й перекриття правил")

    # reload
    subparsers.add_parser("reload", help="Перезавантажити конфігурацію")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    cmds = {
        "list": cmd_list,
        "add": cmd_add,
        "enable": cmd_enable,
        "disable": cmd_disable,
        "delete": cmd_delete,
        "conflicts": cmd_conflicts,
        "reload": cmd_reload
    }
    cmds[args.command](args)

if __name__ == "__main__":
    main()
