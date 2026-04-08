#!/usr/bin/env python
import sys
import traceback
import logging

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
logging.info("Script launched")

try:
    logging.info("Importing MasterOfParser...")
    from MasterOfParser import MasterOfParserGUI
    import tkinter as tk

    logging.info("Creating root window...")
    root = tk.Tk()

    logging.info("Creating GUI instance...")
    gui = MasterOfParserGUI(root)

    logging.info("Running mainloop...")
    root.mainloop()

except Exception as e:
    logging.error(f"Error: {e}")
    traceback.print_exc()
    sys.exit(1)
