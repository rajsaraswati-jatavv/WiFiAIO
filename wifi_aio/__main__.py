"""Entry point for running WiFiAIO as a module: python -m wifi_aio"""

import sys


def main():
    """Run the WiFiAIO CLI."""
    try:
        from wifi_aio.cli import main as cli_main
        sys.exit(cli_main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
    except Exception as exc:
        print(f"Fatal error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
