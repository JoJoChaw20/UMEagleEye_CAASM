"""EagleEye pipeline agent for the UMEagleEye CAASM platform."""

VERSION = "0.1.0"

# The build stamp, written into _build.py by the packaging scripts (packaging/buildstamp.py):
# 0.1.0+<UTC build time>.<commit>. The dashboard compares it with the newest published package to
# offer an update; a copy run from the source tree is "dev" and is never offered one.
try:
    from ._build import BUILD
except ImportError:
    BUILD = "dev"
