"""Building blocks in the dashboard's design language: the circuit trace and ring node, panels,
page headers, the navy rail's navigation bus, the live dot, the trace loader and the theme switch."""

from __future__ import annotations

import sys
from typing import Callable, Iterable, Optional

from PySide6.QtCore import QEasingCurve, QEvent, QModelIndex, QPointF, QRectF, QSize, Qt, QVariantAnimation
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView, QButtonGroup, QFrame, QGridLayout, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
    QPushButton, QSizePolicy, QStyle, QStyledItemDelegate, QStyleOptionViewItem, QToolButton, QVBoxLayout, QWidget,
)

from . import theme

EXPO_OUT = QEasingCurve.Type.OutExpo


def reduced_motion() -> bool:
    """Windows "Show animations in Windows" switched off."""
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        value = ctypes.c_int(1)
        ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(value), 0)  # SPI_GETCLIENTAREAANIMATION
        return not value.value
    except (AttributeError, OSError):
        return False


def label(text: str = "", role: Optional[str] = None, wrap: bool = False, selectable: bool = False) -> QLabel:
    lab = QLabel(text)
    if role:
        lab.setProperty("role", role)
    if wrap:
        lab.setWordWrap(True)
    if selectable:
        lab.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return lab


def set_tone(widget: QWidget, tone: Optional[str]) -> None:
    """ok / warn / error / muted, or None for the default colour; repolishes so QSS picks it up."""
    if widget.property("tone") == tone:
        return
    widget.setProperty("tone", tone)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


class Button(QPushButton):
    """A push button whose cursor says whether it can be pressed."""

    def changeEvent(self, event) -> None:  # noqa: N802 - Qt API
        if event.type() == QEvent.Type.EnabledChange:
            self._cursor()
        super().changeEvent(event)

    def _cursor(self) -> None:
        self.setCursor(Qt.CursorShape.PointingHandCursor if self.isEnabled() else Qt.CursorShape.ForbiddenCursor)


class ElidedLabel(QLabel):
    """One line that ends in an ellipsis when it does not fit; the full text is the tooltip."""

    def __init__(self, text: str = "") -> None:
        super().__init__()
        self._full = ""
        self.setMinimumWidth(0)
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.setText(text)

    def setText(self, text: str) -> None:  # noqa: N802 - Qt API
        self._full = text
        self._elide()

    def full_text(self) -> str:
        return self._full

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt API
        super().resizeEvent(event)
        self._elide()

    def _elide(self) -> None:
        shown = self.fontMetrics().elidedText(self._full, Qt.TextElideMode.ElideRight, max(0, self.width()))
        super().setText(shown)
        self.setToolTip(self._full if shown != self._full else "")


def button(text: str, role: Optional[str] = None, icon: Optional[str] = None,
           slot: Optional[Callable[[], object]] = None) -> QPushButton:
    b = Button(text)
    if role:
        b.setProperty("role", role)
    b._cursor()
    b.setFocusPolicy(Qt.FocusPolicy.TabFocus)          # a click does not leave a focus ring behind
    if icon:
        b.setProperty("iconName", icon)
        _paint_button_icon(b)
    if slot is not None:
        b.clicked.connect(slot)
    return b


def _paint_button_icon(b: QPushButton) -> None:
    name = b.property("iconName")
    if not name:
        return
    p = theme.current()
    role = b.property("role")
    colour = p.hex("on_brand") if role == "primary" else p.hex("red") if role == "danger" else p.hex("text_muted")
    b.setIcon(theme.icon(name, colour, 16, disabled=p.hex("text_faint") if role != "primary" else None))
    b.setIconSize(QSize(16, 16))


def refresh_icons(root: QWidget) -> None:
    """Re-colour the icons of every button below `root` after a theme change."""
    for b in root.findChildren(QPushButton):
        _paint_button_icon(b)


# ── Circuit trace ─────────────────────────────────────────────────────────
def _draw_ring(p: QPainter, centre: QPointF, diameter: float, fill: QColor, stroke: QColor, width: float = 1.5) -> None:
    p.setPen(QPen(stroke, width))
    p.setBrush(fill)
    r = (diameter - width) / 2
    p.drawEllipse(centre, r, r)


class RingNode(QWidget):
    """The 7px ring node that leads panel headings."""

    def __init__(self, diameter: int = 7, ground: str = "surface", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.diameter = diameter
        self.ground = ground
        self.setFixedSize(diameter + 2, diameter + 2)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt API
        pal = theme.current()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        _draw_ring(p, QPointF(self.width() / 2, self.height() / 2), self.diameter, pal.q(self.ground), pal.q("eagle_bright"))


class Trace(QWidget):
    """A 1px line fading from the ink line to 55% Electric Wing Blue, ending in a ring node."""

    def __init__(self, length: int = 44, ground: str = "ground", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.length = length
        self.ground = ground
        self.setFixedSize(length + 9, 11)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt API
        pal = theme.current()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        y = self.height() / 2
        grad = QLinearGradient(0, y, self.length, y)
        grad.setColorAt(0, pal.q("line"))
        grad.setColorAt(1, pal.q("eagle", 0.55))
        p.setPen(QPen(grad, 1))
        p.drawLine(QPointF(0, y), QPointF(self.length, y))
        _draw_ring(p, QPointF(self.length + 4, y), 7, pal.q(self.ground), pal.q("eagle_bright"))


class TraceLoader(QWidget):
    """Busy indicator: a ring node travelling along a 72px trace."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedSize(84, 11)
        self._t = 0.5
        self._anim = QVariantAnimation(self)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setDuration(1600)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self._anim.setLoopCount(-1)
        self._anim.valueChanged.connect(self._step)

    def _step(self, value: float) -> None:
        # there and back: 0→1→0 over one loop
        self._t = value * 2 if value <= 0.5 else (1 - value) * 2
        self.update()

    def showEvent(self, event) -> None:  # noqa: N802 - Qt API
        if not reduced_motion():
            self._anim.start()
        super().showEvent(event)

    def hideEvent(self, event) -> None:  # noqa: N802 - Qt API
        self._anim.stop()
        super().hideEvent(event)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt API
        pal = theme.current()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        y = self.height() / 2
        x0, x1 = 5.0, self.width() - 5.0
        p.setPen(QPen(pal.q("line"), 1))
        p.drawLine(QPointF(x0, y), QPointF(x1, y))
        x = x0 + (x1 - x0) * self._t
        p.setPen(QPen(pal.q("eagle", 0.7), 1))
        p.drawLine(QPointF(x0, y), QPointF(x, y))
        _draw_ring(p, QPointF(x, y), 7, pal.q("surface"), pal.q("eagle_bright"))


# ── Live dot ──────────────────────────────────────────────────────────────
class LiveDot(QWidget):
    """An 8px status dot. While live it sends out a radar ping in its own colour (2.2s, expo out).
    Tones: live (cyan: something is happening now), ok, warn, down, off."""

    def __init__(self, on_rail: bool = False, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.on_rail = on_rail
        self.tone = "off"
        self.setFixedSize(20, 20)
        self._t = 0.0
        self._anim = QVariantAnimation(self)
        self._anim.setStartValue(0.0)
        self._anim.setEndValue(1.0)
        self._anim.setDuration(2200)
        self._anim.setEasingCurve(EXPO_OUT)
        self._anim.setLoopCount(-1)
        self._anim.valueChanged.connect(self._step)

    def _step(self, value: float) -> None:
        self._t = value
        self.update()

    def set_tone(self, tone: str) -> None:
        if tone == self.tone:
            return
        self.tone = tone
        pulsing = tone in ("live", "ok") and not reduced_motion()
        if pulsing and self._anim.state() != QVariantAnimation.State.Running:
            self._anim.start()
        elif not pulsing:
            self._anim.stop()
            self._t = 0.0
        self.update()

    def colour(self) -> QColor:
        pal = theme.current()
        if self.on_rail:
            key = {"live": "brand_cyan", "ok": "brand_cyan", "warn": "rail_amber", "down": "rail_red"}.get(self.tone, "rail_muted")
        else:
            key = {"live": "cyan", "ok": "green", "warn": "amber", "down": "red"}.get(self.tone, "text_faint")
        return pal.q(key)

    def paintEvent(self, _event) -> None:  # noqa: N802 - Qt API
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = self.colour()
        centre = QPointF(self.width() / 2, self.height() / 2)
        if self._anim.state() == QVariantAnimation.State.Running:
            ping = QColor(c)
            ping.setAlphaF(0.55 * (1 - self._t))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(ping)
            r = 4 + 5.5 * self._t
            p.drawEllipse(centre, r, r)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(c)
        p.drawEllipse(centre, 4, 4)


# ── Page structure ────────────────────────────────────────────────────────
class PageHeader(QWidget):
    """The page title (display type) closed by a 44px trace and ring node, then a short description."""

    def __init__(self, title: str, description: str = "", actions: Iterable[QWidget] = ()) -> None:
        super().__init__()
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        row = QHBoxLayout()
        row.setSpacing(12)
        self.title = label(title, "display")
        row.addWidget(self.title)
        row.addWidget(Trace(44, "ground"), 0, Qt.AlignmentFlag.AlignVCenter)
        row.addStretch(1)
        for w in actions:
            row.addWidget(w)
        v.addLayout(row)
        self.description = label(description, "description", wrap=True)
        self.description.setVisible(bool(description))
        v.addWidget(self.description)


class Panel(QFrame):
    """A solid surface with a 1px line and 10px corners. The heading leads with a ring node; actions
    sit at its right. `flush` drops the body padding so a table runs edge to edge."""

    def __init__(self, title: str = "", actions: Iterable[QWidget] = (), flush: bool = False) -> None:
        super().__init__()
        self.setProperty("role", "panel")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(1, 1, 1, 1)
        outer.setSpacing(0)
        self.header: Optional[QWidget] = None
        if title:
            self.header = QWidget()
            h = QHBoxLayout(self.header)
            h.setContentsMargins(19, 16, 19, 4 if flush else 0)
            h.setSpacing(10)
            h.addWidget(RingNode(7, "surface"), 0, Qt.AlignmentFlag.AlignVCenter)
            self.title = label(title, "title")
            h.addWidget(self.title)
            h.addStretch(1)
            for w in actions:
                h.addWidget(w)
            outer.addWidget(self.header)
        holder = QWidget()
        self.body = QVBoxLayout(holder)
        if flush:
            self.body.setContentsMargins(0, 12, 0, 0)
        else:
            self.body.setContentsMargins(19, 14 if title else 19, 19, 19)
        self.body.setSpacing(12)
        outer.addWidget(holder, 1)

    def add(self, *widgets: QWidget) -> "Panel":
        for w in widgets:
            self.body.addWidget(w)
        return self

    def add_layout(self, layout) -> "Panel":  # type: ignore[no-untyped-def]
        self.body.addLayout(layout)
        return self


def divider() -> QFrame:
    line = QFrame()
    line.setProperty("role", "divider")
    line.setFixedHeight(1)
    return line


class Notice(QFrame):
    """One line that says what is wrong and offers the way out."""

    def __init__(self) -> None:
        super().__init__()
        self.setProperty("role", "notice")
        h = QHBoxLayout(self)
        h.setContentsMargins(14, 10, 10, 10)
        h.setSpacing(10)
        self.glyph = QLabel()
        self.glyph.setFixedSize(16, 16)
        h.addWidget(self.glyph, 0, Qt.AlignmentFlag.AlignVCenter)
        self.label = label("", wrap=True)
        self.label.setTextFormat(Qt.TextFormat.RichText)
        h.addWidget(self.label, 1)
        self.action = button("", "secondary")
        self.action.hide()
        h.addWidget(self.action, 0, Qt.AlignmentFlag.AlignVCenter)
        self._slot: Optional[Callable[[], object]] = None
        self.action.clicked.connect(lambda: self._slot and self._slot())
        self.restyle()

    def restyle(self) -> None:
        pal = theme.current()
        self.glyph.setPixmap(theme.pixmap("circle-alert", pal.hex("amber"), 16))

    def text(self) -> str:
        return self.label.text()

    def setText(self, text: str) -> None:  # noqa: N802 - Qt naming, like QLabel
        self.label.setText(text)

    def set_action(self, text: str, slot: Optional[Callable[[], object]]) -> None:
        self._slot = slot
        self.action.setText(text)
        self.action.setVisible(bool(text and slot))


class FieldGrid(QGridLayout):
    """Label / value pairs in one or two columns."""

    def __init__(self, columns: int = 1) -> None:
        super().__init__()
        self.columns = columns
        self.setHorizontalSpacing(16)
        self.setVerticalSpacing(10)
        self._count = 0
        for c in range(columns):
            self.setColumnStretch(c * 2 + 1, 1)
            if c:
                self.setColumnMinimumWidth(c * 2, 0)

    def add(self, name: str, widget: QWidget, column: Optional[int] = None) -> QLabel:
        col = (self._count % self.columns) if column is None else column
        row = self._rows_in(col)
        lab = label(name, "field")
        lab.setMinimumWidth(96)
        top = Qt.AlignmentFlag.AlignTop
        self.addWidget(lab, row, col * 2, top | Qt.AlignmentFlag.AlignLeft)
        if isinstance(widget, QLabel):
            self.addWidget(widget, row, col * 2 + 1, top)
        else:
            self.addWidget(widget, row, col * 2 + 1)
            # a field: centre its label on the control's first line
            lab.setMinimumHeight(min(widget.sizeHint().height(), 34))
            lab.setAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
        self._count += 1
        return lab

    def _rows_in(self, col: int) -> int:
        return sum(1 for i in range(self.count())
                   if self.getItemPosition(i)[1] == col * 2)


# ── Navigation rail ───────────────────────────────────────────────────────
KIND_ROLE = Qt.ItemDataRole.UserRole + 1
PAGE_ROLE = Qt.ItemDataRole.UserRole + 2
ICON_ROLE = Qt.ItemDataRole.UserRole + 3

BUS_X = 20.0          # the bus line, in the rail's coordinates
ITEM_LEFT = 32.0      # items start 12px right of the bus


class NavDelegate(QStyledItemDelegate):
    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:  # noqa: N802 - Qt API
        if index.data(KIND_ROLE) == "group":
            return QSize(option.rect.width(), 30 if index.row() == 0 else 48)
        return QSize(option.rect.width(), 38)

    def _same_group(self, index: QModelIndex, step: int) -> bool:
        other = index.sibling(index.row() + step, 0)
        return other.isValid() and other.data(KIND_ROLE) == "page"

    def paint(self, p: QPainter, option: QStyleOptionViewItem, index: QModelIndex) -> None:
        pal = theme.current()
        p.save()
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(option.rect)
        if index.data(KIND_ROLE) == "group":
            f = theme.font("nav_group")
            p.setFont(f)
            p.setPen(pal.q("rail_muted", 0.8))
            text_rect = QRectF(r.left() + 13, r.bottom() - 22, r.width() - 26, 16)
            p.drawText(text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, index.data())
            p.restore()
            return

        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        hover = bool(option.state & QStyle.StateFlag.State_MouseOver)
        cy = r.center().y()
        # the bus: a vertical line through every item of the group, from the first centre to the last
        p.setPen(QPen(pal.q("rail_line"), 1))
        top = cy if not self._same_group(index, -1) else r.top()
        bottom = cy if not self._same_group(index, 1) else r.bottom() + 1
        if bottom > top:
            p.drawLine(QPointF(BUS_X + 0.5, top), QPointF(BUS_X + 0.5, bottom))

        item = QRectF(ITEM_LEFT, r.top() + 1, r.width() - ITEM_LEFT - 12, r.height() - 2)
        if selected or hover:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(pal.q("rail_raised") if selected else pal.q("rail_raised", 0.6))
            p.drawRoundedRect(item, 6, 6)
        if option.state & QStyle.StateFlag.State_HasFocus and option.state & QStyle.StateFlag.State_KeyboardFocusChange:
            p.setPen(QPen(pal.q("brand_sky"), 1.5))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(item.adjusted(0.75, 0.75, -0.75, -0.75), 6, 6)

        if selected:
            _draw_ring(p, QPointF(BUS_X + 0.5, cy), 9, pal.q("rail"), pal.q("brand_sky"), 2.0)
            p.setPen(QPen(pal.q("brand_sky"), 1))
            p.drawLine(QPointF(BUS_X + 5, cy), QPointF(ITEM_LEFT, cy))
        else:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(pal.q("rail_muted") if hover else pal.q("rail_line"))
            p.drawEllipse(QPointF(BUS_X + 0.5, cy), 2.5, 2.5)

        text_colour = pal.q("on_brand") if selected else pal.q("rail_text") if hover else pal.q("rail_muted")
        icon_colour = pal.hex("brand_pale") if selected else text_colour.name()
        name = index.data(ICON_ROLE)
        if name:
            pm = theme.pixmap(name, icon_colour, 16)
            p.drawPixmap(QPointF(item.left() + 10, cy - 8), pm)
        p.setFont(theme.font("body_medium" if selected else "body"))
        p.setPen(text_colour)
        p.drawText(QRectF(item.left() + 38, item.top(), item.width() - 44, item.height()),
                   Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, index.data())
        p.restore()


class RailNav(QListWidget):
    """The rail's navigation. Group labels are plain rows; page rows carry their stack index."""

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("nav")
        self.setItemDelegate(NavDelegate(self))
        self.setMouseTracking(True)
        self.viewport().setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Expanding)

    def add_group(self, title: str) -> None:
        item = QListWidgetItem(title)
        item.setData(KIND_ROLE, "group")
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.addItem(item)

    def add_page(self, title: str, icon: str, page_index: int) -> None:
        item = QListWidgetItem(title)
        item.setData(KIND_ROLE, "page")
        item.setData(PAGE_ROLE, page_index)
        item.setData(ICON_ROLE, icon)
        self.addItem(item)

    def row_for_page(self, page_index: int) -> int:
        for row in range(self.count()):
            if self.item(row).data(PAGE_ROLE) == page_index:
                return row
        return -1


# ── Theme switch ──────────────────────────────────────────────────────────
class ThemeSwitch(QWidget):
    """Dark, light or system, like the dashboard's header switch."""

    MODES = (("dark", "moon", "Dark"), ("light", "sun", "Light"), ("system", "monitor", "System (follows Windows)"))

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("segmented")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setFixedHeight(32)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        h = QHBoxLayout(self)
        h.setContentsMargins(2, 2, 2, 2)
        h.setSpacing(2)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.buttons: dict[str, QToolButton] = {}
        mgr = theme.manager()
        for mode, icon_name, tip in self.MODES:
            b = QToolButton()
            b.setProperty("role", "seg")
            b.setProperty("iconName", icon_name)
            b.setCheckable(True)
            b.setToolTip(tip)
            b.setAccessibleName(f"{tip} theme")
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setIconSize(QSize(16, 16))
            b.setFixedSize(28, 26)
            b.clicked.connect(lambda _=False, m=mode: self._choose(m))
            self.group.addButton(b)
            self.buttons[mode] = b
            h.addWidget(b)
        self.buttons[mgr.mode if mgr else "dark"].setChecked(True)
        self.setEnabled(mgr is not None)
        self.restyle()

    def _choose(self, mode: str) -> None:
        mgr = theme.manager()
        if mgr is not None:
            mgr.set_mode(mode)

    def restyle(self) -> None:
        pal = theme.current()
        for b in self.buttons.values():
            b.setIcon(theme.icon(b.property("iconName"), pal.hex("text_muted"), 16, on=pal.hex("eagle_bright")))
