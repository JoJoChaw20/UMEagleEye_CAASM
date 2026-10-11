"""Desktop app (PySide6) around the agent service: setup, consent, status, schedules,
privacy settings, dependency installation and the log. Start it with
`python -m eagleeye gui` or the packaged EagleEyeAgent.exe."""

from .app import main

__all__ = ["main"]
