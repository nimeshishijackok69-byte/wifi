"""Entry point for `python -m netguard`."""

from .app import NetGuardApp


def main() -> None:
    app = NetGuardApp()
    app.mainloop()


if __name__ == "__main__":
    main()
