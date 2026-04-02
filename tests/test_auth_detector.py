from monitoring_engine.detector.manager import DetectorManager


def main():
    context = {
        "logs": {
            "auth": [
                "Mar 31 10:11:01 host sshd[111]: Failed password for root from 10.10.10.5 port 52100 ssh2",
                "Mar 31 10:11:04 host sshd[112]: Failed password for root from 10.10.10.5 port 52101 ssh2",
                "Mar 31 10:11:07 host sshd[113]: Failed password for root from 10.10.10.5 port 52102 ssh2",
                "Mar 31 10:11:09 host sshd[114]: Failed password for admin from 10.10.10.8 port 52103 ssh2",
                "Mar 31 10:11:11 host sshd[115]: Failed password for admin from 10.10.10.8 port 52104 ssh2",
            ]
        },
        "config": {
            "detector": {
                "auth_trace": {
                    "threshold": 3
                }
            }
        }
    }

    manager = DetectorManager()
    findings = manager.run_all(context)

    for item in findings:
        print(item)


if __name__ == "__main__":
    main()