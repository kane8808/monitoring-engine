from __future__ import annotations

from security_app.api.routes_incidents import list_incidents, get_incident_detail


def main():
    items = list_incidents()

    print("\n=== INCIDENT LIST ===")
    for i in items:
        print(i["incident_dir"])

    if items:
        print("\n=== FIRST INCIDENT DETAIL ===")

        detail = get_incident_detail(items[0]["incident_dir"])

        if not detail:
            print("❌ detail not found")
            return

        decision = detail.get("decision")

        if not decision:
            print("❌ decision not found")
            return

        print(decision)


if __name__ == "__main__":
    main()