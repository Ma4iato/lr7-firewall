import argparse
import collections
import json
import os
import sys

def parse_logs(log_path: str):
    if not os.path.exists(log_path):
        return []
    records = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except Exception:
                    pass
    return records

def print_record(r: dict):
    t = r.get("time", "")
    ev = r.get("event", "")
    if ev.startswith("admin"):
        details = r.get("rule") or r.get("details") or r.get("action") or ""
        print(f"[{t}] {ev:<20} | rule_id={r.get('rule_id','-')} | {details}")
    else:
        proto = r.get("proto", "-")
        src = r.get("src", "-")
        dst = r.get("dst", "-")
        act = r.get("action", "-")
        rid = r.get("rule_id")
        reason = r.get("reason", "")
        print(f"[{t}] {ev:<12} {proto:<4} {src:<22} -> {dst:<22} | {act:<5} | rule={rid or '-'} | {reason}")

def print_summary(records: list):
    print("=== Зведена статистика журналу брандмауера ===")
    print(f"Загальна кількість записів у журналі: {len(records)}\n")

    events = collections.Counter(r.get("event", "unknown") for r in records)
    print("Розподіл за типами подій:")
    for ev, cnt in events.most_common():
        print(f"  - {ev:<22}: {cnt}")

    conn_events = [r for r in records if r.get("event") in ["tcp.connect", "udp.packet"]]
    print(f"\nПодії мережевих з'єднань: {len(conn_events)}")
    actions = collections.Counter(r.get("action", "?") for r in conn_events)
    for act, cnt in actions.items():
        print(f"  - {act.upper()}: {cnt}")

    denied = [r for r in conn_events if r.get("action") == "DENY"]
    if denied:
        print(f"\nДеталі заблокованих з'єднань ({len(denied)}):")
        protos = collections.Counter(r.get("proto", "?") for r in denied)
        srcs = collections.Counter(r.get("src", "?").split(":")[0] for r in denied)
        rules = collections.Counter(f"Правило #{r.get('rule_id')}" for r in denied)
        print(f"  - За протоколами:  {dict(protos)}")
        print(f"  - За джерелами:    {dict(srcs)}")
        print(f"  - Спрацювали:      {dict(rules)}")
        times = [r.get("time") for r in denied if r.get("time")]
        if times:
            print(f"  - Час першого блокування: {times[0]}")
            print(f"  - Час останнього блокування: {times[-1]}")

def main():
    parser = argparse.ArgumentParser(description="Firewall Log Analysis Tool")
    parser.add_argument("logfile", nargs="?", default="logs/firewall.jsonl", help="Шлях до файлу журналу")
    parser.add_argument("--last", type=int, help="Показати останні N записів")
    parser.add_argument("--src", help="Фільтр за IP джерела")
    parser.add_argument("--dst", help="Фільтр за IP призначення")
    parser.add_argument("--proto", help="Фільтр за протоколом (TCP/UDP)")
    parser.add_argument("--action", help="Фільтр за дією (allow/deny)")
    parser.add_argument("--reason", help="Пошук підрядка в тексті причини")
    parser.add_argument("--event", help="Фільтр за типом події (або префіксом, наприклад admin)")
    args = parser.parse_args()

    records = parse_logs(args.logfile)
    if not records:
        print(f"[!] Файл журналу порожній або не знайдений: {args.logfile}")
        return

    # Check if any filter is supplied
    is_filtered = any([args.last, args.src, args.dst, args.proto, args.action, args.reason, args.event])

    if not is_filtered:
        print_summary(records)
        return

    filtered = records
    if args.event:
        filtered = [r for r in filtered if r.get("event", "").startswith(args.event)]
    if args.src:
        filtered = [r for r in filtered if args.src in str(r.get("src", ""))]
    if args.dst:
        filtered = [r for r in filtered if args.dst in str(r.get("dst", ""))]
    if args.proto:
        filtered = [r for r in filtered if r.get("proto", "").upper() == args.proto.upper()]
    if args.action:
        filtered = [r for r in filtered if r.get("action", "").lower() == args.action.lower()]
    if args.reason:
        filtered = [r for r in filtered if args.reason.lower() in str(r.get("reason", "")).lower()]
    if args.last:
        filtered = filtered[-args.last:]

    print(f"Знайдено записів: {len(filtered)}")
    for r in filtered:
        print_record(r)

if __name__ == "__main__":
    main()
