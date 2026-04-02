from monitoring_engine.config.config_loader import load_config
from monitoring_engine.runner.run_pipeline import run_pipeline

def main():
    print(">>> MONITORING ENGINE STARTED")

    cfg = load_config()
    run_pipeline(cfg)

if __name__ == "__main__":
    main()