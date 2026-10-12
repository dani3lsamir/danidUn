"""Checkable, categorised leftover list with an evidence panel."""
from __future__ import annotations

from tkinter import ttk

from ..i18n import t
from ..models import Category, Confidence, Leftover
from ..paths import human_size
from ..scanner.scoring import WEIGHTS
from . import theme

CHECKED, UNCHECKED, LOCKED, DONE = "☑", "☐", "🔒", "✔"
CATEGORY_KEYS = {c: "cat." + c.value for c in Category}


class LeftoverView(ttk.Frame):
    def __init__(self, master, on_change=None) -> None:
        super().__init__(master)
        self.on_change = on_change
        self.items: dict[str, Leftover] = {}
        self.checked: set[str] = set()
        self.done: dict[str, str] = {}  # iid -> status after removal

        cols = ("confidence", "score", "kind", "size")
        self.tree = ttk.Treeview(self, columns=cols, show="tree headings", selectmode="browse")
        self.tree.heading("#0", text=t("col.item"))
        self.tree.column("#0", width=560, stretch=True)
        for col, key, width in (("confidence", "col.confidence", 105), ("score", "col.score", 60),
                                ("kind", "col.type", 80), ("size", "col.size", 80)):
            self.tree.heading(col, text=t(key))
            self.tree.column(col, width=width, stretch=False, anchor="w")
        for conf, color in theme.CONFIDENCE_COLORS.items():
            self.tree.tag_configure(conf, foreground=color)
        self.tree.tag_configure("protected", foreground="#5d6b78")
        self.tree.tag_configure("category", foreground=theme.ACCENT)
        self.tree.tag_configure("done", foreground="#5d6b78")
        scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)

        self.detail = theme.text_widget(self, height=7)
        self.detail.configure(state="disabled")
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.detail.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)

        self.tree.bind("<Button-1>", self._click)
        self.tree.bind("<space>", lambda _e: self._toggle(self.tree.focus()))
        self.tree.bind("<Double-1>", lambda _e: self._toggle(self.tree.focus()))
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show(self.tree.focus()))

    # ---------------------------------------------------------------- data
    def load(self, leftovers: list[Leftover]) -> None:
        self.tree.delete(*self.tree.get_children())
        self.items.clear()
        self.checked.clear()
        self.done.clear()
        groups: dict[Category, list[Leftover]] = {}
        for lo in leftovers:
            groups.setdefault(lo.category, []).append(lo)
        for cat in Category:
            items = groups.get(cat)
            if not items:
                continue
            parent = self.tree.insert("", "end", iid="cat:" + cat.value, open=True, tags=("category",),
                                      text=f"{t(CATEGORY_KEYS[cat])}  ({len(items)})")
            for index, lo in enumerate(items):
                iid = f"{cat.value}:{index}"
                self.items[iid] = lo
                if lo.selectable and lo.confidence == Confidence.HIGH:
                    self.checked.add(iid)
                self.tree.insert(parent, "end", iid=iid, values=self._values(lo), text=self._text(iid),
                                 tags=(("protected",) if lo.protected else (lo.confidence.name,)))
        if self.items:
            first = next(iter(self.items))
            self.tree.focus(first)
            self.tree.selection_set(first)
            self._show(first)
        self._changed()

    def _values(self, lo: Leftover) -> tuple:
        return (t("conf." + lo.confidence.name), lo.score, t("kind." + lo.kind.value), human_size(lo.size))

    def _text(self, iid: str) -> str:
        lo = self.items[iid]
        if iid in self.done:
            mark = DONE if self.done[iid] in ("removed", "partial") else "✖"
        elif lo.protected:
            mark = LOCKED
        else:
            mark = CHECKED if iid in self.checked else UNCHECKED
        return f"{mark}  {lo.display}"

    def _refresh(self, iid: str) -> None:
        if iid in self.items:
            self.tree.item(iid, text=self._text(iid))

    # ---------------------------------------------------------------- interaction
    def _click(self, event) -> str | None:
        iid = self.tree.identify_row(event.y)
        element = self.tree.identify_element(event.x, event.y)
        if iid in self.items and self.tree.identify_column(event.x) == "#0" and "indicator" not in element:
            bbox = self.tree.bbox(iid, "#0")
            # Toggle only when the click lands on the check mark area.
            if bbox and event.x - bbox[0] < 70:
                self.tree.focus(iid)
                self.tree.selection_set(iid)
                self._toggle(iid)
                return "break"
        return None

    def _toggle(self, iid: str) -> None:
        if iid.startswith("cat:"):
            children = [c for c in self.tree.get_children(iid) if self.items[c].selectable and c not in self.done]
            target_state = not all(c in self.checked for c in children)
            for c in children:
                (self.checked.add if target_state else self.checked.discard)(c)
                self._refresh(c)
            self._changed()
            return
        lo = self.items.get(iid)
        if lo is None or not lo.selectable or iid in self.done:
            return
        if iid in self.checked:
            self.checked.discard(iid)
        else:
            self.checked.add(iid)
        self._refresh(iid)
        self._changed()

    def select_recommended(self) -> None:
        self.checked = {i for i, lo in self.items.items()
                        if lo.selectable and lo.confidence == Confidence.HIGH and i not in self.done}
        for iid in self.items:
            self._refresh(iid)
        self._changed()

    def select_none(self) -> None:
        self.checked.clear()
        for iid in self.items:
            self._refresh(iid)
        self._changed()

    def selected(self) -> list[Leftover]:
        return [self.items[i] for i in self.items if i in self.checked]

    def mark_results(self, results: list[tuple[Leftover, str]]) -> None:
        index = {id(lo): iid for iid, lo in self.items.items()}
        for lo, status in results:
            iid = index.get(id(lo))
            if iid:
                self.done[iid] = status
                self.checked.discard(iid)
                self._refresh(iid)
                self.tree.item(iid, tags=("done",))
        self._changed()

    def _changed(self) -> None:
        if self.on_change:
            sel = self.selected()
            self.on_change(len(self.items), len(sel), sum(lo.size for lo in sel))

    def _show(self, iid: str) -> None:
        lo = self.items.get(iid)
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        if lo is not None:
            lines = [f"{t('res.target')}: {lo.display}"]
            if lo.note and lo.note != lo.target:
                lines.append(f"→ {lo.note}")
            lines.append(f"{t('col.confidence')}: {t('conf.' + lo.confidence.name)} ({lo.score}/100)")
            lines.append(t("res.evidence") + ":")
            for ev in lo.evidence:
                weight = WEIGHTS.get(ev.signal, 0)
                sign = "+" if weight >= 0 else ""
                detail = f" — {ev.detail}" if ev.detail else ""
                lines.append(f"   {sign}{weight:<4} {t('sig.' + ev.signal)}{detail}")
            if lo.protected:
                lines.append(f"{t('res.protection')}: {t(lo.protected)}")
                lines.append(t("res.protected_hint"))
            self.detail.insert("1.0", "\n".join(lines))
        self.detail.configure(state="disabled")
