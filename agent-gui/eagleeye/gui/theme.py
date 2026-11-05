"""The look of the desktop app: the UMEagleEye dashboard's design system (DESIGN.md at the
repository root) translated to Qt.

Colours are the dashboard's theme tokens. The navy rail and the brand blues are the same in
every theme; everything else swaps between dark and light. "System" follows the Windows app
theme and changes with it. The choice is saved per user (QSettings), not in the agent config.

Fonts are bundled (assets/fonts, SIL Open Font License): Chakra Petch for headings, Geist for
the interface, Geist Mono for identifiers only.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QByteArray, QObject, QRectF, QSettings, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QGuiApplication, QIcon, QPainter, QPalette, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QAbstractSpinBox, QApplication, QLineEdit

from . import icons

# Next to this module both from source and in the PyInstaller build (the spec copies the folder).
ASSETS = Path(__file__).resolve().parent / "assets"

DISPLAY = "Chakra Petch"
BODY = "Geist"
MONO = "Geist Mono"

MODES = ("dark", "light", "system")

RGB = tuple[int, int, int]

# ── Tokens ────────────────────────────────────────────────────────────────
# The rail world: identical in every theme (The Navy Rail Rule).
RAIL: dict[str, RGB] = {
    "rail": (8, 16, 31),
    "rail_raised": (17, 30, 54),
    "rail_line": (27, 42, 70),
    "rail_text": (226, 234, 246),
    "rail_muted": (134, 152, 184),
    "brand_blue": (26, 140, 255),
    "brand_sky": (56, 168, 255),
    "brand_pale": (112, 194, 255),
    "brand_cyan": (43, 200, 255),
    "brand_deep": (11, 111, 240),
    "on_brand": (255, 255, 255),
    "rail_amber": (255, 184, 46),
    "rail_red": (255, 92, 102),
}

DARK: dict[str, RGB] = {
    "ground": (6, 11, 23),
    "sunken": (11, 18, 33),
    "surface": (19, 29, 50),
    "line": (38, 51, 77),
    "line_strong": (72, 87, 117),
    "text_strong": (243, 246, 252),
    "text": (225, 232, 244),
    "text_secondary": (196, 208, 228),
    "text_muted": (138, 155, 184),
    "text_faint": (116, 133, 163),
    "eagle": (26, 140, 255),          # eagle-500: hover, focus border, selection tint
    "eagle_deep": (11, 111, 240),     # eagle-600: primary fill
    "eagle_bright": (56, 168, 255),   # eagle-400: ring strokes, links, active text
    "cyan": (43, 200, 255),
    "green": (34, 211, 145),
    "amber": (255, 184, 46),
    "red": (255, 92, 102),
    "shadow": (0, 0, 0),
}

LIGHT: dict[str, RGB] = {
    "ground": (236, 241, 248),
    "sunken": (244, 247, 251),
    "surface": (255, 255, 255),
    "line": (219, 226, 237),
    "line_strong": (190, 201, 218),
    "text_strong": (5, 11, 25),
    "text": (13, 22, 41),
    "text_secondary": (30, 42, 66),
    "text_muted": (75, 90, 117),
    "text_faint": (96, 111, 138),
    "eagle": (11, 111, 240),
    "eagle_deep": (11, 100, 224),
    "eagle_bright": (10, 99, 214),
    "cyan": (8, 120, 170),
    "green": (4, 128, 84),
    "amber": (180, 100, 0),
    "red": (205, 30, 45),
    "shadow": (15, 30, 60),
}


@dataclass(frozen=True)
class Palette:
    name: str
    tokens: dict[str, RGB]

    def __getitem__(self, key: str) -> RGB:
        return self.tokens[key] if key in self.tokens else RAIL[key]

    def q(self, key: str, alpha: float = 1.0) -> QColor:
        r, g, b = self[key]
        return QColor(r, g, b, round(alpha * 255))

    def css(self, key: str, alpha: float = 1.0) -> str:
        r, g, b = self[key]
        return f"rgb({r}, {g}, {b})" if alpha >= 1 else f"rgba({r}, {g}, {b}, {round(alpha * 255)})"

    def hex(self, key: str) -> str:
        return "#%02x%02x%02x" % self[key]


PALETTES = {"dark": Palette("dark", DARK), "light": Palette("light", LIGHT)}
_current: Palette = PALETTES["dark"]


def current() -> Palette:
    return _current


# ── Fonts ─────────────────────────────────────────────────────────────────
_fonts_loaded = False


def load_fonts() -> None:
    global _fonts_loaded
    if _fonts_loaded:
        return
    for path in sorted((ASSETS / "fonts").glob("*.ttf")):
        QFontDatabase.addApplicationFont(str(path))
    _fonts_loaded = True


def font(kind: str = "body") -> QFont:
    """A font for one role of the type scale (DESIGN.md, Typography)."""
    spec = {
        "display": (DISPLAY, 24, QFont.Weight.DemiBold, 0.0),
        "headline": (DISPLAY, 18, QFont.Weight.DemiBold, 0.0),
        "title": (DISPLAY, 15, QFont.Weight.DemiBold, 0.0),
        "nav_group": (DISPLAY, 11, QFont.Weight.DemiBold, 12.0),
        "label": (BODY, 11, QFont.Weight.Medium, 6.0),
        "body": (BODY, 14, QFont.Weight.Normal, 0.0),
        "body_medium": (BODY, 14, QFont.Weight.Medium, 0.0),
        "small": (BODY, 12, QFont.Weight.Normal, 0.0),
        "mono": (MONO, 12, QFont.Weight.Normal, 0.0),
    }[kind]
    family, px, weight, tracking = spec
    f = QFont(family)
    f.setPixelSize(px)
    f.setWeight(weight)
    if tracking:
        f.setLetterSpacing(QFont.SpacingType.PercentageSpacing, 100 + tracking)
    if kind in ("nav_group", "label"):
        f.setCapitalization(QFont.Capitalization.AllUppercase)
    f.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    return f


# ── Icons ─────────────────────────────────────────────────────────────────
_icon_cache: dict[tuple[str, str, int], QPixmap] = {}


def pixmap(name: str, colour: QColor | str, size: int = 16, stroke: float = 2.0) -> QPixmap:
    """A Lucide icon drawn in one colour, at 2x for high-DPI screens."""
    hex_colour = colour if isinstance(colour, str) else colour.name()
    key = (name, hex_colour, size)
    if key not in _icon_cache:
        ratio = 2
        pm = QPixmap(size * ratio, size * ratio)
        pm.fill(Qt.GlobalColor.transparent)
        renderer = QSvgRenderer(QByteArray(icons.svg(name, hex_colour, stroke).encode()))
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        renderer.render(p, QRectF(0, 0, size * ratio, size * ratio))
        p.end()
        pm.setDevicePixelRatio(ratio)
        _icon_cache[key] = pm
    return _icon_cache[key]


def icon(name: str, colour: QColor | str, size: int = 16, on: Optional[QColor | str] = None,
         disabled: Optional[QColor | str] = None) -> QIcon:
    ic = QIcon()
    ic.addPixmap(pixmap(name, colour, size), QIcon.Mode.Normal, QIcon.State.Off)
    if on is not None:
        ic.addPixmap(pixmap(name, on, size), QIcon.Mode.Normal, QIcon.State.On)
    if disabled is not None:
        ic.addPixmap(pixmap(name, disabled, size), QIcon.Mode.Disabled, QIcon.State.Off)
    return ic


def brand_pixmap(name: str) -> QPixmap:
    """`lockup-on-dark` (silver wordmark, for the navy rail) or `mark` (the emblem)."""
    return QPixmap(str(ASSETS / f"{name}.png"))


# ── Stylesheet ────────────────────────────────────────────────────────────
def _indicator_files(p: Palette) -> dict[str, str]:
    """QSS can only take images from files: write the themed control glyphs once per theme."""
    folder = Path(tempfile.gettempdir()) / "eagleeye-agent-ui" / p.name
    folder.mkdir(parents=True, exist_ok=True)
    wanted = {
        "chevron-down": ("chevron-down", p.hex("text_muted"), 2.0),
        "chevron-down-hover": ("chevron-down", p.hex("eagle_bright"), 2.0),
        "chevron-up": ("chevron-up", p.hex("text_muted"), 2.0),
        "chevron-down-disabled": ("chevron-down", p.hex("line_strong"), 2.0),
        "chevron-up-disabled": ("chevron-up", p.hex("line_strong"), 2.0),
        "check": ("check", "#ffffff", 3.0),
    }
    out: dict[str, str] = {}
    for key, (name, colour, stroke) in wanted.items():
        path = folder / f"{key}.svg"
        text = icons.svg(name, colour, stroke)
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
        out[key] = path.as_posix()
    return out


def stylesheet(p: Palette) -> str:
    c = p.css
    img = _indicator_files(p)
    return f"""
* {{ outline: none; }}
QMainWindow, QDialog, QWidget#workspace, QWidget#pageBody, QWidget#pageRoot {{ background: {c('ground')}; }}
QWidget {{ color: {c('text')}; }}
QToolTip {{ background: {c('surface')}; color: {c('text')}; border: 1px solid {c('line')}; border-radius: 6px; padding: 6px 8px; }}

/* rail: navy in every theme */
QWidget#rail {{ background: {c('rail')}; border-right: 1px solid {c('rail_line')}; }}
QWidget#railBrand {{ border-bottom: 1px solid {c('rail_line')}; }}
QWidget#railFoot {{ border-top: 1px solid {c('rail_line')}; }}
QListWidget#nav {{ background: transparent; border: none; }}
QLabel#railName {{ color: {c('rail_text')}; font-weight: 500; }}
QLabel#railSub {{ color: {c('rail_muted')}; font-size: 11px; }}
QLabel#railTile {{ background: {c('brand_deep')}; color: {c('on_brand')}; border-radius: 6px;
                   font-family: "{DISPLAY}"; font-size: 14px; font-weight: 600; }}

/* header */
QWidget#topbar {{ background: {c('sunken')}; border-bottom: 1px solid {c('line', 0.8)}; }}
QLabel#state {{ color: {c('text_strong')}; font-weight: 500; }}
QLabel#stateDetail, QLabel#admin {{ color: {c('text_muted')}; font-size: 13px; }}
QFrame#vsep {{ background: {c('line')}; }}
QWidget#segmented {{ background: {c('ground')}; border: 1px solid {c('line', 0.8)}; border-radius: 7px; }}
QToolButton[role="seg"] {{ background: transparent; border: 1px solid transparent; border-radius: 5px; padding: 4px; }}
QToolButton[role="seg"]:hover {{ background: {c('line', 0.4)}; }}
QToolButton[role="seg"]:checked {{ background: {c('surface')}; border: 1px solid {c('eagle', 0.45)}; }}
QToolButton[role="seg"]:focus {{ border: 2px solid {c('eagle_bright')}; }}

/* text roles */
QLabel[role="display"] {{ color: {c('text_strong')}; font-family: "{DISPLAY}"; font-size: 24px; font-weight: 600; }}
QLabel[role="title"] {{ color: {c('text_strong')}; font-family: "{DISPLAY}"; font-size: 15px; font-weight: 600; }}
QLabel[role="lead"] {{ color: {c('text_strong')}; font-size: 15px; font-weight: 500; }}
QLabel[role="description"] {{ color: {c('text_muted')}; }}
QLabel[role="hint"] {{ color: {c('text_muted')}; font-size: 13px; }}
QLabel[role="field"] {{ color: {c('text_muted')}; font-size: 13px; }}
QLabel[role="value"] {{ color: {c('text_strong')}; }}
QLabel[role="mono"] {{ color: {c('text_strong')}; font-family: "{MONO}"; font-size: 12px; }}
QLabel[tone="ok"] {{ color: {c('green')}; }}
QLabel[tone="warn"] {{ color: {c('amber')}; }}
QLabel[tone="error"], QLabel[role="error"] {{ color: {c('red')}; }}
QLabel[tone="muted"] {{ color: {c('text_muted')}; }}

/* panels */
QFrame[role="panel"] {{ background: {c('surface')}; border: 1px solid {c('line', 0.8)}; border-radius: 10px; }}
QFrame[role="panel"] QLabel, QFrame[role="panel"] QCheckBox, QFrame[role="panel"] QRadioButton {{ background: transparent; }}
QFrame[role="divider"] {{ background: {c('line', 0.8)}; border: none; }}
QFrame[role="notice"] {{ background: {c('amber', 0.10)}; border: 1px solid {c('amber', 0.30)}; border-radius: 6px; }}
QFrame[role="notice"][tone="info"] {{ background: {c('eagle', 0.08)}; border: 1px solid {c('eagle', 0.30)}; }}
QFrame[role="notice"] QLabel {{ background: transparent; color: {c('text')}; }}
QWidget#footer {{ background: {c('sunken')}; border-top: 1px solid {c('line', 0.8)}; }}
QScrollArea {{ background: transparent; border: none; }}

/* buttons */
QPushButton {{ background: {c('surface')}; color: {c('text_secondary')}; border: 1px solid {c('line')};
               border-radius: 6px; padding: 7px 14px; font-weight: 500; }}
QPushButton:hover {{ color: {c('text_strong')}; border-color: {c('line_strong')}; }}
QPushButton:pressed {{ padding-top: 8px; padding-bottom: 6px; }}
QPushButton:focus {{ border: 2px solid {c('eagle_bright')}; padding: 6px 13px; }}
QPushButton:disabled {{ color: {c('text_faint')}; border-color: {c('line', 0.6)}; background: {c('surface', 0.6)}; }}
QPushButton[role="primary"] {{ background: {c('eagle_deep')}; border-color: {c('eagle_deep')}; color: {c('on_brand')}; }}
QPushButton[role="primary"]:hover {{ background: {c('eagle')}; border-color: {c('eagle')}; }}
QPushButton[role="primary"]:focus {{ border: 2px solid {c('text_strong')}; padding: 6px 13px; }}
QPushButton[role="primary"]:disabled {{ background: {c('eagle_deep', 0.25 if p.name == 'dark' else 0.45)}; border-color: transparent;
    color: {c('on_brand', 0.45 if p.name == 'dark' else 0.7)}; }}
QPushButton[role="ghost"] {{ background: transparent; border-color: transparent; color: {c('text_muted')}; }}
QPushButton[role="ghost"]:hover {{ background: {c('line', 0.4)}; color: {c('text_strong')}; }}
QPushButton[role="ghost"]:focus {{ border: 2px solid {c('eagle_bright')}; padding: 6px 13px; }}
QPushButton[role="danger"] {{ background: {c('red', 0.10)}; border-color: {c('red', 0.30)}; color: {c('red')}; }}
QPushButton[role="danger"]:hover {{ background: {c('red', 0.20)}; }}
QDialogButtonBox QPushButton {{ min-width: 72px; }}

/* fields */
QLineEdit, QComboBox, QSpinBox, QTimeEdit, QPlainTextEdit, QTextBrowser {{
    background: {c('sunken')}; color: {c('text')}; border: 1px solid {c('line')}; border-radius: 6px;
    selection-background-color: {c('eagle', 0.32)}; selection-color: {c('text_strong')};
    placeholder-text-color: {c('text_faint')}; }}
QLineEdit, QComboBox, QSpinBox, QTimeEdit {{ padding: 6px 10px; min-height: 20px; }}
QPlainTextEdit, QTextBrowser {{ padding: 8px 10px; }}
QLineEdit:hover, QComboBox:hover, QSpinBox:hover, QTimeEdit:hover, QPlainTextEdit:hover {{ border-color: {c('line_strong')}; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QTimeEdit:focus, QPlainTextEdit:focus, QTextBrowser:focus {{ border-color: {c('eagle')}; }}
QLineEdit:disabled, QComboBox:disabled, QSpinBox:disabled, QTimeEdit:disabled, QPlainTextEdit:disabled {{
    color: {c('text_faint')}; background: {c('sunken', 0.6)}; border-color: {c('line', 0.6)}; }}
QAbstractSpinBox, QAbstractSpinBox QLineEdit {{ font-family: "{BODY}"; font-size: 14px; }}
QAbstractSpinBox QLineEdit {{ background: transparent; border: none; padding: 0; margin: 0; }}
QComboBox QLineEdit {{ background: transparent; border: none; padding: 0; margin: 0; }}
QLineEdit[mono="true"], QComboBox[mono="true"], QPlainTextEdit[mono="true"] {{ font-family: "{MONO}"; font-size: 12px; }}
QComboBox {{ padding-right: 28px; }}
QComboBox::drop-down {{ subcontrol-origin: padding; subcontrol-position: center right; width: 26px; border: none; }}
QComboBox::down-arrow {{ image: url("{img['chevron-down']}"); width: 14px; height: 14px; }}
QComboBox::down-arrow:hover {{ image: url("{img['chevron-down-hover']}"); }}
QComboBox::down-arrow:disabled {{ image: url("{img['chevron-down-disabled']}"); }}
QComboBox QAbstractItemView {{ background: {c('surface')}; color: {c('text')}; border: 1px solid {c('line')};
    selection-background-color: {c('eagle', 0.14)}; selection-color: {c('text_strong')}; outline: 0; padding: 4px; }}
QSpinBox, QTimeEdit {{ padding: 6px 24px 6px 0; }}
QSpinBox::up-button, QTimeEdit::up-button {{ subcontrol-origin: border; subcontrol-position: top right; width: 22px;
    border: none; border-left: 1px solid {c('line', 0.8)}; border-top-right-radius: 6px; }}
QSpinBox::down-button, QTimeEdit::down-button {{ subcontrol-origin: border; subcontrol-position: bottom right; width: 22px;
    border: none; border-left: 1px solid {c('line', 0.8)}; border-bottom-right-radius: 6px; }}
QSpinBox::up-button:hover, QSpinBox::down-button:hover, QTimeEdit::up-button:hover, QTimeEdit::down-button:hover {{ background: {c('line', 0.5)}; }}
QSpinBox::up-arrow, QTimeEdit::up-arrow {{ image: url("{img['chevron-up']}"); width: 11px; height: 11px; }}
QSpinBox::down-arrow, QTimeEdit::down-arrow {{ image: url("{img['chevron-down']}"); width: 11px; height: 11px; }}
QSpinBox::up-arrow:disabled, QTimeEdit::up-arrow:disabled {{ image: url("{img['chevron-up-disabled']}"); }}
QSpinBox::down-arrow:disabled, QTimeEdit::down-arrow:disabled {{ image: url("{img['chevron-down-disabled']}"); }}

QCheckBox, QRadioButton {{ spacing: 10px; color: {c('text')}; }}
QCheckBox:disabled, QRadioButton:disabled {{ color: {c('text_faint')}; }}
QCheckBox::indicator {{ width: 16px; height: 16px; border: 1px solid {c('line_strong')}; border-radius: 4px; background: {c('sunken')}; }}
QCheckBox::indicator:hover {{ border-color: {c('eagle')}; }}
QCheckBox::indicator:focus {{ border: 2px solid {c('eagle_bright')}; }}
QCheckBox::indicator:checked {{ background: {c('eagle_deep')}; border-color: {c('eagle_deep')}; image: url("{img['check']}"); }}
QCheckBox::indicator:disabled {{ border-color: {c('line')}; background: {c('sunken', 0.6)}; }}
QCheckBox::indicator:checked:disabled {{ background: {c('eagle_deep', 0.45)}; border-color: transparent; }}
QCheckBox::indicator:checked:focus {{ border: 2px solid {c('text_strong')}; }}
QRadioButton::indicator {{ width: 16px; height: 16px; border: 1px solid {c('line_strong')}; border-radius: 9px; background: {c('sunken')}; }}
QRadioButton::indicator:hover {{ border-color: {c('eagle')}; }}
QRadioButton::indicator:focus {{ border: 2px solid {c('eagle_bright')}; }}
QRadioButton::indicator:checked {{ border: 5px solid {c('eagle_deep')}; background: {c('on_brand')}; width: 8px; height: 8px; }}
QRadioButton::indicator:checked:focus {{ border: 5px solid {c('eagle_bright') if p.name == 'dark' else c('text_strong')}; background: {c('on_brand')}; }}

/* tables */
QTableWidget {{ background: {c('surface')}; color: {c('text')}; border: 1px solid transparent; gridline-color: transparent;
    selection-background-color: {c('eagle', 0.12)}; selection-color: {c('text_strong')}; }}
QTableWidget::item {{ padding: 0 12px; border-bottom: 1px solid {c('line', 0.6)}; }}
QTableWidget::item:selected {{ background: {c('eagle', 0.12)}; color: {c('text_strong')}; }}
QTableWidget:focus {{ border: 1px solid {c('eagle_bright')}; }}
QHeaderView {{ background: {c('sunken')}; border: none; }}
QHeaderView::section {{ background: {c('sunken')}; color: {c('text_muted')}; border: none;
    border-bottom: 1px solid {c('line', 0.8)}; padding: 8px 15px;
    font-family: "{BODY}"; font-size: 11px; font-weight: 500; }}
QTableCornerButton::section {{ background: {c('sunken')}; border: none; }}

/* scrollbars */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle {{ background: {c('line_strong', 0.7)}; border-radius: 3px; }}
QScrollBar::handle:hover {{ background: {c('line_strong')}; }}
QScrollBar::handle:vertical {{ min-height: 32px; }}
QScrollBar::handle:horizontal {{ min-width: 32px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}

QProgressBar {{ background: {c('sunken')}; border: none; border-radius: 2px; max-height: 4px; min-height: 4px; }}
QProgressBar::chunk {{ background: {c('eagle')}; border-radius: 2px; }}

QMenu {{ background: {c('surface')}; color: {c('text')}; border: 1px solid {c('line')}; border-radius: 8px; padding: 4px; }}
QMenu::item {{ padding: 6px 16px; border-radius: 4px; }}
QMenu::item:selected {{ background: {c('eagle', 0.14)}; color: {c('text_strong')}; }}
QMenu::item:disabled {{ color: {c('text_faint')}; }}
QMenu::separator {{ height: 1px; background: {c('line')}; margin: 4px 6px; }}
"""


def qpalette(p: Palette) -> QPalette:
    pal = QPalette()
    R = QPalette.ColorRole
    for group in (QPalette.ColorGroup.Active, QPalette.ColorGroup.Inactive, QPalette.ColorGroup.Disabled):
        dim = group == QPalette.ColorGroup.Disabled
        pal.setColor(group, R.Window, p.q("ground"))
        pal.setColor(group, R.WindowText, p.q("text_faint" if dim else "text"))
        pal.setColor(group, R.Base, p.q("sunken"))
        pal.setColor(group, R.AlternateBase, p.q("surface"))
        pal.setColor(group, R.Text, p.q("text_faint" if dim else "text"))
        pal.setColor(group, R.Button, p.q("surface"))
        pal.setColor(group, R.ButtonText, p.q("text_faint" if dim else "text_secondary"))
        pal.setColor(group, R.BrightText, p.q("text_strong"))
        pal.setColor(group, R.Highlight, p.q("eagle", 0.32))
        pal.setColor(group, R.HighlightedText, p.q("text_strong"))
        pal.setColor(group, R.PlaceholderText, p.q("text_faint"))
        pal.setColor(group, R.ToolTipBase, p.q("surface"))
        pal.setColor(group, R.ToolTipText, p.q("text"))
        pal.setColor(group, R.Link, p.q("eagle_bright"))
        pal.setColor(group, R.LinkVisited, p.q("eagle_bright"))
        pal.setColor(group, R.Light, p.q("line_strong"))
        pal.setColor(group, R.Midlight, p.q("line"))
        pal.setColor(group, R.Mid, p.q("line"))
        pal.setColor(group, R.Dark, p.q("sunken"))
        pal.setColor(group, R.Shadow, p.q("shadow"))
        pal.setColor(group, R.Accent, p.q("eagle"))
    return pal


def document_css(p: Palette) -> str:
    """For rich text in QTextBrowser (the data-collection notice)."""
    return (f"body {{ color: {p.hex('text')}; font-family: '{BODY}'; font-size: 14px; }}"
            f"h3 {{ color: {p.hex('text_strong')}; font-family: '{DISPLAY}'; font-size: 15px; font-weight: 600; "
            f"margin-top: 14px; margin-bottom: 4px; }}"
            f"p, li {{ line-height: 140%; }} b {{ color: {p.hex('text_strong')}; }}"
            f"a {{ color: {p.hex('eagle_bright')}; }}")


# ── Theme manager ─────────────────────────────────────────────────────────
class ThemeManager(QObject):
    """Owns the mode (dark, light, system), applies it and tells painted widgets to repaint."""

    changed = Signal(str)          # the resolved theme: "dark" or "light"

    def __init__(self, app: QApplication, settings: Optional[QSettings] = None) -> None:
        super().__init__(app)
        self.app = app
        self.settings = settings if settings is not None else QSettings("UMEagleEye", "EagleEye Agent")
        mode = str(self.settings.value("theme", "system"))
        self.mode = mode if mode in MODES else "system"
        hints = QGuiApplication.styleHints()
        hints.colorSchemeChanged.connect(self._system_changed)

    def resolved(self) -> str:
        if self.mode != "system":
            return self.mode
        scheme = QGuiApplication.styleHints().colorScheme()
        return "light" if scheme == Qt.ColorScheme.Light else "dark"

    def set_mode(self, mode: str) -> None:
        if mode not in MODES or mode == self.mode:
            return
        self.mode = mode
        self.settings.setValue("theme", mode)
        self.apply()

    def _system_changed(self, _scheme: Qt.ColorScheme) -> None:
        if self.mode == "system":
            self.apply(follow_system=False)

    def apply(self, follow_system: bool = True) -> None:
        global _current
        hints = QGuiApplication.styleHints()
        if follow_system and hasattr(hints, "setColorScheme"):
            # Also themes the Windows title bar. Unknown hands it back to the system.
            hints.setColorScheme({"dark": Qt.ColorScheme.Dark, "light": Qt.ColorScheme.Light}.get(
                self.mode, Qt.ColorScheme.Unknown))
        name = self.resolved()
        _current = PALETTES[name]
        self.app.setPalette(qpalette(_current))
        self.app.setStyleSheet(stylesheet(_current))
        self.changed.emit(name)


def setup(app: QApplication) -> ThemeManager:
    """Fonts, the Fusion style (it honours the palette everywhere), the base font and the theme."""
    load_fonts()
    app.setStyle("Fusion")
    base = font("body")
    app.setFont(base)
    manager = ThemeManager(app)
    manager.apply()
    app.theme = manager  # type: ignore[attr-defined]
    return manager


def manager() -> Optional[ThemeManager]:
    app = QApplication.instance()
    return getattr(app, "theme", None)


def tabular(f: QFont) -> QFont:
    """Tabular numerals (DESIGN: figures line up in tables)."""
    f.setFeature(QFont.Tag("tnum"), 1)
    return f


def inset(spin: QAbstractSpinBox) -> QAbstractSpinBox:
    """QSS padding does not reach the text inside a spin box; give it the fields' inset."""
    edit = spin.findChild(QLineEdit)
    if edit is not None:
        edit.setTextMargins(9, 0, 0, 0)
    return spin


def icon_size(px: int = 16) -> QSize:
    return QSize(px, px)
