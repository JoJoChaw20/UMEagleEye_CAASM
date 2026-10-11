from __future__ import annotations

from datetime import datetime, timedelta

from eagleeye.schedule import Schedule, ScheduleState

T = datetime(2026, 10, 11, 10, 0)


def test_daily_runs_once_after_its_time():
    s = Schedule(subnet="192.168.1.0/24", mode="daily", time="02:00")
    last = datetime(2026, 10, 10, 2, 0)                      # yesterday's run
    assert s.is_due(last, T)                                  # today's 02:00 has passed
    assert not s.is_due(datetime(2026, 10, 11, 2, 0), T)      # already ran today
    assert not s.is_due(datetime(2026, 10, 11, 1, 0), datetime(2026, 10, 11, 1, 59))


def test_daily_missed_runs_collapse_into_one():
    s = Schedule(subnet="10.0.0.0/24", time="02:00")
    last = T - timedelta(days=5)                              # machine was off for days
    assert s.is_due(last, T)
    assert not s.is_due(T, T + timedelta(hours=1))            # after that run, nothing until tomorrow
    assert s.next_run(T, T + timedelta(hours=1)) == datetime(2026, 10, 12, 2, 0)


def test_interval():
    s = Schedule(subnet="10.0.0.0/24", mode="interval", hours=6)
    assert not s.is_due(T, T + timedelta(hours=5, minutes=59))
    assert s.is_due(T, T + timedelta(hours=6))
    assert s.next_run(T, T + timedelta(hours=1)) == T + timedelta(hours=6)


def test_disabled_or_invalid_never_due():
    assert not Schedule(subnet="10.0.0.0/24", enabled=False).is_due(T - timedelta(days=2), T)
    bad = Schedule(subnet="10.0.0.0/8")
    assert bad.problems() and not bad.is_due(T - timedelta(days=2), T)
    assert "HH:MM" in Schedule(subnet="10.0.0.0/24", time="25:00").problems()[0]
    assert Schedule(subnet="10.0.0.0/24", mode="interval", hours=0).problems()
    assert Schedule(subnet="10.0.0.0/24; calc").problems()


def test_from_dict_tolerates_junk():
    s = Schedule.from_dict({"subnet": "10.0.0.0/24", "hours": "x", "extra": 1})
    assert s.hours == 0 and s.problems() == []                # daily mode ignores hours
    assert Schedule.from_dict(Schedule(subnet="10.0.0.0/24", mode="interval", hours=3).to_dict()).hours == 3


def test_state_starts_the_clock_on_first_sight_and_persists(tmp_path):
    path = tmp_path / "state.json"
    state = ScheduleState(path)
    assert state.last_run("a", T) == T                        # new schedule: no immediate run
    state.mark("a", T + timedelta(hours=1))
    reloaded = ScheduleState(path)
    assert reloaded.last_runs["a"] == T + timedelta(hours=1)
    reloaded.last_run("b", T)
    reloaded.forget_except({"b"})
    assert set(ScheduleState(path).last_runs) == {"b"}


def test_corrupt_state_file_is_ignored(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("{nope")
    assert ScheduleState(path).last_runs == {}
