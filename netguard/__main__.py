"""Entry point for `python -m netguard`."""

import os
import traceback

from .app import NetGuardApp
from .store import APP_DIR


def main() -> None:
    try:
        app = NetGuardApp()
        app.mainloop()
    except Exception:
        # M3: pythonw has no console — an uncaught startup error used to
        # exit silently. Log it and tell the user with a dialog when possible.
        try:
            os.makedirs(APP_DIR, exist_ok=True)
            with open(os.path.join(APP_DIR, "netguard.log"), "a", encoding="utf-8") as fh:
                fh.write(traceback.format_exc() + "\n")
        except Exception:
            pass
        try:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "NetGuard failed to start",
                "NetGuard hit a startup error. Details were written to:\n"
                + os.path.join(APP_DIR, "netguard.log"),
            )
        except Exception:
            pass
        raise SystemExit(1)


if __name__ == "__main__":
    main()
