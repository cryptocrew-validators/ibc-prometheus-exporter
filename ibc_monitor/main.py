import argparse
import logging
from pathlib import Path
from ibc_monitor.config import Config
from ibc_monitor.exporter import IBCExporter


def main():
    parser = argparse.ArgumentParser(
        description="IBC Prometheus Exporter",
    )
    parser.add_argument(
        '--config', '-c', type=Path,
        default=Path('config.toml.example'),
        help="Path to TOML configuration file",
    )
    args = parser.parse_args()
    cfg = Config(args.config)
    level = getattr(logging, cfg.log_level.upper(), logging.INFO)
    logging.basicConfig(level=level)
    exporter = IBCExporter(cfg)
    exporter.run()


if __name__ == '__main__':
    main()
