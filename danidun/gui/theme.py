"""Dark, flat ttk theme."""
from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

BG = "#0f141a"
SURFACE = "#161d26"
SURFACE_2 = "#1d2733"
BORDER = "#2a3644"
TEXT = "#e6edf3"
MUTED = "#8b98a5"
ACCENT = "#2ec4a6"
ACCENT_DARK = "#1f8f79"
DANGER = "#e5534b"
WARNING = "#d29922"
SUCCESS = "#3fb950"
SELECT = "#22536a"

CONFIDENCE_COLORS = {"HIGH": SUCCESS, "MEDIUM": WARNING, "LOW": MUTED}


def apply(root: tk.Tk) -> None:
    root.configure(bg=BG)
    base = tkfont.nametofont("TkDefaultFont")
    family = "Segoe UI" if "Segoe UI" in tkfont.families(root) else base.actual("family")
    base.configure(family=family, size=10)
    tkfont.nametofont("TkTextFont").configure(family=family, size=10)
    tkfont.nametofont("TkHeadingFont").configure(family=family, size=10, weight="bold")
    root.option_add("*TCombobox*Listbox.background", SURFACE_2)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", SELECT)
    root.option_add("*Menu.background", SURFACE)
    root.option_add("*Menu.foreground", TEXT)
    root.option_add("*Menu.activeBackground", SELECT)
    root.option_add("*Menu.activeForeground", TEXT)

    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure(".", background=BG, foreground=TEXT, fieldbackground=SURFACE_2, bordercolor=BORDER,
                lightcolor=BORDER, darkcolor=BORDER, troughcolor=SURFACE, focuscolor=ACCENT,
                selectbackground=SELECT, selectforeground=TEXT, insertcolor=TEXT, font=(family, 10))
    s.configure("TFrame", background=BG)
    s.configure("Card.TFrame", background=SURFACE)
    s.configure("TLabel", background=BG, foreground=TEXT)
    s.configure("Card.TLabel", background=SURFACE, foreground=TEXT)
    s.configure("Muted.TLabel", background=BG, foreground=MUTED)
    s.configure("CardMuted.TLabel", background=SURFACE, foreground=MUTED)
    s.configure("Title.TLabel", background=BG, foreground=ACCENT, font=(family, 20, "bold"))
    s.configure("H2.TLabel", background=BG, foreground=TEXT, font=(family, 13, "bold"))
    s.configure("Warn.TLabel", background=BG, foreground=WARNING)
    s.configure("Danger.TLabel", background=BG, foreground=DANGER)
    s.configure("Badge.TLabel", background=SURFACE_2, foreground=MUTED, padding=(8, 2))
    s.configure("BadgeAdmin.TLabel", background=ACCENT_DARK, foreground=TEXT, padding=(8, 2))

    s.configure("TButton", background=SURFACE_2, foreground=TEXT, padding=(12, 6), borderwidth=1, relief="flat")
    s.map("TButton", background=[("disabled", SURFACE), ("pressed", BORDER), ("active", BORDER)],
          foreground=[("disabled", MUTED)])
    s.configure("Accent.TButton", background=ACCENT_DARK, foreground="#ffffff")
    s.map("Accent.TButton", background=[("disabled", SURFACE), ("pressed", ACCENT_DARK), ("active", ACCENT)])
    s.configure("Danger.TButton", background="#8c2d29", foreground="#ffffff")
    s.map("Danger.TButton", background=[("disabled", SURFACE), ("active", DANGER)])
    s.configure("Link.TButton", background=BG, foreground=ACCENT, padding=(4, 2), borderwidth=0)
    s.map("Link.TButton", background=[("active", BG)], foreground=[("active", TEXT)])

    s.configure("TEntry", fieldbackground=SURFACE_2, foreground=TEXT, padding=6)
    s.configure("TCombobox", fieldbackground=SURFACE_2, background=SURFACE_2, foreground=TEXT, arrowcolor=TEXT)
    s.map("TCombobox", fieldbackground=[("readonly", SURFACE_2)], foreground=[("readonly", TEXT)])
    for widget in ("TCheckbutton", "TRadiobutton"):
        s.configure(widget, background=BG, foreground=TEXT, indicatorbackground=SURFACE_2, indicatorforeground=ACCENT)
        s.map(widget, background=[("active", BG)], foreground=[("disabled", MUTED)],
              indicatorbackground=[("selected", ACCENT_DARK)])
    s.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=TEXT, rowheight=26, borderwidth=0)
    s.map("Treeview", background=[("selected", SELECT)], foreground=[("selected", TEXT)])
    s.configure("Treeview.Heading", background=SURFACE_2, foreground=MUTED, relief="flat", padding=(6, 4))
    s.map("Treeview.Heading", background=[("active", BORDER)])
    s.configure("TProgressbar", background=ACCENT, troughcolor=SURFACE, bordercolor=SURFACE, thickness=6)
    for name in ("TScrollbar", "Vertical.TScrollbar", "Horizontal.TScrollbar"):
        s.configure(name, background=SURFACE_2, troughcolor=SURFACE, arrowcolor=MUTED, bordercolor=SURFACE,
                    lightcolor=SURFACE_2, darkcolor=SURFACE_2, gripcount=0, relief="flat")
        s.map(name, background=[("active", BORDER), ("pressed", BORDER)])
    s.configure("TSeparator", background=BORDER)
    s.configure("TLabelframe", background=BG, bordercolor=BORDER)
    s.configure("TLabelframe.Label", background=BG, foreground=MUTED)


def text_widget(parent, height: int = 6, **kw) -> tk.Text:
    return tk.Text(parent, height=height, bg=SURFACE, fg=TEXT, insertbackground=TEXT, relief="flat",
                   highlightthickness=1, highlightbackground=BORDER, highlightcolor=BORDER, wrap="word",
                   padx=8, pady=6, **kw)
