"""Tests for the packaging (ticket #50): installer/homesoc.spec, installer/homesoc.iss, README.

Runs on any OS without PyInstaller or Inno Setup:
- the .spec is Python: it is executed with stub ``Analysis/PYZ/EXE/COLLECT`` globals and a stub
  ``PyInstaller.utils.hooks`` module, and the recorded arguments are checked;
- the .iss is parsed as INI-like sections of ``Key: value; Key: "value"`` entries.
The fourth acceptance criterion (green tray shield after installing on a fresh VM snapshot) is a
manual check, documented in README.md ("Manual check on a fresh VM") and CLAUDE.md §12.
"""

from __future__ import annotations

import re
import runpy
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from agent import config

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC = REPO_ROOT / "installer" / "homesoc.spec"
ISS = REPO_ROOT / "installer" / "homesoc.iss"
README = REPO_ROOT / "README.md"

REQUIRED_DATAS = {
    "config.yaml": ".",
    "data/allowlist.txt": "data",
    "models/dga.joblib": "models",
    "models/flow.joblib": "models",
}
EXACT_FIREWALL_CLEANUP = {
    "Remove-NetFirewallRule -Group 'HomeSOC'",
    'Remove-NetFirewallRule -Group "HomeSOC"',
}
# Anything that changes firewall/Defender state beyond removing the HomeSOC group.
FORBIDDEN_COMMANDS = re.compile(
    r"netsh|Set-NetFirewallProfile|Set-NetFirewallRule|Disable-NetFirewallRule|"
    r"New-NetFirewallRule|Enable-NetFirewallRule|Set-MpPreference|Add-MpPreference|"
    r"Remove-MpPreference|DisableRealtimeMonitoring|MpCmdRun|sc(\.exe)?\s+(stop|config)\s+"
    r"(mpssvc|windefend)",
    re.IGNORECASE,
)


# --- the .spec, executed with stubs --------------------------------------------------------


@dataclass
class _Analysis:
    scripts_in: list[str]
    kwargs: dict[str, Any]
    pure: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    binaries: list = field(default_factory=list)
    datas: list = field(default_factory=list)


@dataclass
class SpecRun:
    analyses: list[_Analysis]
    exes: list[dict[str, Any]]
    collects: list[tuple[tuple, dict[str, Any]]]
    namespace: dict[str, Any]


def run_spec(monkeypatch: pytest.MonkeyPatch, spec: Path = SPEC,
             specpath: Path | None = None) -> SpecRun:
    """Execute the spec like PyInstaller would, recording every build object it creates."""
    analyses: list[_Analysis] = []
    exes: list[dict[str, Any]] = []
    collects: list[tuple[tuple, dict[str, Any]]] = []

    def analysis(scripts: list[str], **kwargs: Any) -> _Analysis:
        a = _Analysis(scripts, kwargs, datas=list(kwargs.get("datas", [])),
                      binaries=list(kwargs.get("binaries", [])))
        analyses.append(a)
        return a

    def exe(*args: Any, **kwargs: Any) -> dict[str, Any]:
        exes.append(kwargs)
        return kwargs

    def collect(*args: Any, **kwargs: Any) -> None:
        collects.append((args, kwargs))

    hooks = types.ModuleType("PyInstaller.utils.hooks")
    hooks.collect_all = lambda name: ([], [], [f"{name}.stub"])  # type: ignore[attr-defined]
    hooks.collect_submodules = lambda name, filter=None: [f"{name}.stub"]  # type: ignore[attr-defined]
    for mod in ("PyInstaller", "PyInstaller.utils"):
        monkeypatch.setitem(sys.modules, mod, types.ModuleType(mod))
    monkeypatch.setitem(sys.modules, "PyInstaller.utils.hooks", hooks)

    namespace: dict[str, Any] = {
        "__name__": "__main__",
        "SPECPATH": str(specpath or spec.parent),
        "Analysis": analysis,
        "PYZ": lambda pure, *a, **k: ("PYZ", id(pure)),
        "EXE": exe,
        "COLLECT": collect,
    }
    exec(compile(spec.read_text(encoding="utf-8"), str(spec), "exec"), namespace)
    return SpecRun(analyses, exes, collects, namespace)


def _rel(source: str) -> str:
    return Path(source).resolve().relative_to(REPO_ROOT).as_posix()


def bundled_files(datas: list[tuple[str, str]]) -> list[str]:
    """Every repo-relative file a ``datas`` list ships (directories are expanded)."""
    files: list[str] = []
    for source, _dest in datas:
        path = Path(source)
        if path.is_dir():
            files += [_rel(str(p)) for p in sorted(path.rglob("*")) if p.is_file()]
        else:
            files.append(_rel(source))
    return files


def forbidden_bundled(files: list[str]) -> list[str]:
    """Files that must never ship: lab/, tests/, any .py source, DGA generator code (§7, §9)."""
    bad = []
    for rel in files:
        low = rel.casefold()
        if (low.startswith(("lab/", "tests/")) or low.endswith((".py", ".pyc"))
                or "baderj" in low or "domain_generation_algorithms" in low
                or "dga_gen" in low or "/dgas/" in low):
            bad.append(rel)
    return bad


@pytest.fixture
def spec_run(monkeypatch: pytest.MonkeyPatch) -> SpecRun:
    return run_spec(monkeypatch)


def _by_name(run: SpecRun, name: str) -> dict[str, Any]:
    matches = [e for e in run.exes if e.get("name") == name]
    assert len(matches) == 1, f"expected one EXE named {name!r}, got {run.exes}"
    return matches[0]


def _agent_analysis(run: SpecRun) -> _Analysis:
    [a] = [a for a in run.analyses if a.scripts_in[0].endswith("agent_entry.py")]
    return a


def _app_analysis(run: SpecRun) -> _Analysis:
    [a] = [a for a in run.analyses if a.scripts_in[0].endswith("app_entry.py")]
    return a


def test_spec_bundles_models_config_and_allowlist_for_the_agent(spec_run: SpecRun) -> None:
    datas = {_rel(src): dest for src, dest in _agent_analysis(spec_run).datas}
    for rel, dest in REQUIRED_DATAS.items():
        assert datas.get(rel) == dest, f"{rel} must be bundled into {dest!r}, datas={datas}"


def test_spec_bundles_every_file_the_agent_seeds_into_the_data_root(spec_run: SpecRun) -> None:
    datas = {_rel(src): dest for src, dest in _agent_analysis(spec_run).datas}
    for rel in config.SEED_IF_MISSING + config.SEED_REFRESH:
        assert rel in datas, f"agent/config.py seeds {rel} but the spec does not bundle it"
        assert datas[rel] == Path(rel).parent.as_posix(), f"{rel} lands in the wrong folder"


def test_spec_bundles_the_app_ui_and_config(spec_run: SpecRun) -> None:
    app = _app_analysis(spec_run)
    datas = {_rel(src): dest for src, dest in app.datas}
    assert datas.get("app/ui") == "app/ui"
    assert datas.get("config.yaml") == "."
    shipped = bundled_files(app.datas)
    for name in ("index.html", "app.js", "styles.css"):
        assert f"app/ui/{name}" in shipped


def test_spec_never_bundles_lab_tests_training_or_dga_generator_code(spec_run: SpecRun) -> None:
    for a in spec_run.analyses:
        assert forbidden_bundled(bundled_files(a.datas)) == []
        # Code: only the two entry scripts, no lab/tests/training modules, and those excluded.
        assert [_rel(s) for s in a.scripts_in] in (["installer/agent_entry.py"],
                                                   ["installer/app_entry.py"])
        hidden = a.kwargs.get("hiddenimports", [])
        assert not [h for h in hidden if h.split(".")[0] in ("lab", "tests", "models")]
        for module in ("lab", "tests", "models"):
            assert module in a.kwargs.get("excludes", []), f"{module} must be excluded"
        assert [_rel(p) for p in a.kwargs.get("pathex", [])] == ["."]


def test_forbidden_check_catches_lab_and_generator_files() -> None:
    # The check above is only as good as this helper: make sure it actually flags bad files.
    assert forbidden_bundled([
        "lab/fake_malware/freegamecheats.py",
        "lab/dnsmasq.conf",
        "tests/test_smoke.py",
        "models/train_dga.py",
        "data/cache/domain_generation_algorithms/dgas/necurs/dga.py",
        "config.yaml",
        "models/dga.joblib",
    ]) == [
        "lab/fake_malware/freegamecheats.py",
        "lab/dnsmasq.conf",
        "tests/test_smoke.py",
        "models/train_dga.py",
        "data/cache/domain_generation_algorithms/dgas/necurs/dga.py",
    ]


def test_spec_with_a_lab_file_added_is_caught(tmp_path: Path,
                                              monkeypatch: pytest.MonkeyPatch) -> None:
    # Mutation check: a spec that sneaks lab/ in must fail the same checks.
    bad = tmp_path / "homesoc.spec"
    text = SPEC.read_text(encoding="utf-8").replace(
        '(str(ROOT / "models" / "flow.joblib"), "models"),',
        '(str(ROOT / "models" / "flow.joblib"), "models"),\n    (str(ROOT / "lab"), "lab"),',
    )
    bad.write_text(text, encoding="utf-8")
    assert text != SPEC.read_text(encoding="utf-8")
    run = run_spec(monkeypatch, bad, specpath=SPEC.parent)
    assert forbidden_bundled(bundled_files(_agent_analysis(run).datas))


def test_spec_builds_an_elevated_agent_and_a_normal_user_app(spec_run: SpecRun) -> None:
    agent = _by_name(spec_run, "HomeSOC-Agent")
    app = _by_name(spec_run, "HomeSOC")
    assert agent.get("uac_admin") is True
    assert not app.get("uac_admin")
    [(args, kwargs)] = spec_run.collects
    assert kwargs["name"] == "HomeSOC"  # dist\HomeSOC\, which homesoc.iss packs
    assert agent in args and app in args


@pytest.mark.parametrize(("entry", "target"), [
    ("installer/agent_entry.py", "agent.main"),
    ("installer/app_entry.py", "app.main"),
])
def test_entry_scripts_run_the_real_main(entry: str, target: str,
                                         monkeypatch: pytest.MonkeyPatch) -> None:
    module = __import__(target, fromlist=["main"])
    calls: list[str] = []
    monkeypatch.setattr(module, "main", lambda: calls.append(target))
    runpy.run_path(str(REPO_ROOT / entry), run_name="__main__")
    assert calls == [target]


def test_entry_script_gives_a_windowed_exe_stdio(monkeypatch: pytest.MonkeyPatch) -> None:
    namespace = runpy.run_path(str(REPO_ROOT / "installer" / "agent_entry.py"), run_name="entry")
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    namespace["_ensure_stdio"]()
    try:
        assert sys.stdout is not None and sys.stderr is not None
        sys.stdout.write("x")  # uvicorn's logging writes here; must not raise
    finally:
        sys.stdout.close()
        sys.stderr.close()


# --- the .iss -------------------------------------------------------------------------------


def _split_entry(line: str) -> dict[str, str]:
    """``Key: value; Key: "a ""b"" c"`` -> {"Key": ..., ...} (Inno doubles quotes in strings)."""
    parts, current, in_quote = [], "", False
    for ch in line:
        if ch == '"':
            in_quote = not in_quote
        if ch == ";" and not in_quote:
            parts.append(current)
            current = ""
        else:
            current += ch
    parts.append(current)
    entry: dict[str, str] = {}
    for part in parts:
        if not part.strip():
            continue
        key, _, value = part.partition(":")
        value = value.strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1].replace('""', '"')
        entry[key.strip()] = value
    return entry


def parse_iss(text: str) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Section name -> raw lines (comments dropped, ``{#Name}`` defines expanded)."""
    defines = dict(re.findall(r'^#define\s+(\w+)\s+"([^"]*)"', text, re.MULTILINE))
    sections: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        for name, value in defines.items():
            line = line.replace("{#" + name + "}", value)
        if not line or line.startswith(";") or line.startswith("#"):
            continue
        header = re.fullmatch(r"\[(\w+)\]", line)
        if header:
            current = header.group(1)
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return sections, defines


def entries(section: str, text: str | None = None) -> list[dict[str, str]]:
    sections, _ = parse_iss(ISS.read_text(encoding="utf-8") if text is None else text)
    return [_split_entry(line) for line in sections.get(section, [])]


def _command(entry: dict[str, str]) -> str:
    """The text an entry runs: Filename + Parameters, with PowerShell's -Command unwrapped."""
    params = entry.get("Parameters", "")
    m = re.search(r'-Command\s+"(.*)"\s*$', params)
    return m.group(1) if m else f"{entry.get('Filename', '')} {params}"


def firewall_entries(run_entries: list[dict[str, str]]) -> list[dict[str, str]]:
    return [e for e in run_entries
            if re.search(r"firewall|netsh|mpssvc", _command(e) + e.get("Filename", ""), re.I)]


def uninstall_problems(text: str) -> list[str]:
    """Why an .iss's uninstall step is not exactly "remove the HomeSOC group" (empty = fine)."""
    problems = []
    run = entries("UninstallRun", text)
    fw = firewall_entries(run)
    if len(fw) != 1:
        problems.append(f"expected exactly one firewall command in [UninstallRun], got {len(fw)}")
    for e in fw:
        if "powershell" not in e.get("Filename", "").casefold():
            problems.append(f"firewall cleanup must run PowerShell: {e}")
        if _command(e).strip() not in EXACT_FIREWALL_CLEANUP:
            problems.append(f"firewall cleanup is not exactly the HomeSOC group: {_command(e)!r}")
    # Nowhere else ([Run], [Code], ...) may remove firewall rules.
    if text.count("Remove-NetFirewallRule") != 1:
        problems.append("Remove-NetFirewallRule must appear exactly once (the uninstall cleanup)")
    if FORBIDDEN_COMMANDS.search(text):
        problems.append(f"forbidden command: {FORBIDDEN_COMMANDS.search(text).group(0)!r}")
    return problems


def test_uninstall_removes_only_the_homesoc_firewall_group() -> None:
    fw = firewall_entries(entries("UninstallRun"))
    assert len(fw) == 1
    assert fw[0]["Filename"].endswith("powershell.exe")
    assert _command(fw[0]) in EXACT_FIREWALL_CLEANUP
    assert "waituntilterminated" in fw[0]["Flags"]
    assert uninstall_problems(ISS.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize("broader", [
    "Remove-NetFirewallRule",                          # every rule on the PC
    "Remove-NetFirewallRule -Group 'HomeSOC*'",        # wildcard
    "Remove-NetFirewallRule -DisplayName 'HomeSOC*'",  # not the group
    "Remove-NetFirewallRule -Group 'HomeSOC'; netsh advfirewall reset",
    "Remove-NetFirewallRule -Group 'HomeSOC'; Set-NetFirewallProfile -Enabled False",
    "Remove-NetFirewallRule -Group 'HomeSOC'; Set-MpPreference -DisableRealtimeMonitoring $true",
])
def test_uninstall_check_rejects_broader_commands(broader: str) -> None:
    text = ISS.read_text(encoding="utf-8").replace(
        "Remove-NetFirewallRule -Group 'HomeSOC'", broader.replace('"', '""'))
    assert uninstall_problems(text) != []


def test_uninstall_check_rejects_a_second_firewall_command() -> None:
    text = ISS.read_text(encoding="utf-8") + (
        '\n[UninstallRun]\nFilename: "{sys}\\netsh.exe"; Parameters: "advfirewall reset"\n')
    assert uninstall_problems(text) != []


def test_uninstall_stops_the_agent_before_removing_rules() -> None:
    # A running agent could add a rule back after the cleanup.
    run = entries("UninstallRun")
    commands = [_command(e) for e in run]
    stop_agent = next(i for i, c in enumerate(commands) if "/IM HomeSOC-Agent.exe" in c)
    delete_task = next(i for i, c in enumerate(commands) if "Unregister-ScheduledTask" in c)
    cleanup = next(i for i, c in enumerate(commands) if "Remove-NetFirewallRule" in c)
    assert delete_task < stop_agent < cleanup
    assert all(e.get("RunOnceId") for e in run)


def test_installer_installs_the_agent_elevated_and_the_app_as_the_user() -> None:
    sections, _ = parse_iss(ISS.read_text(encoding="utf-8"))
    setup = dict(line.split("=", 1) for line in sections["Setup"])
    assert setup["PrivilegesRequired"] == "admin"
    assert setup["OutputBaseFilename"] == "HomeSOC-Setup"
    [files] = entries("Files")
    assert files["Source"] == "..\\dist\\HomeSOC\\*"  # the spec's COLLECT(name="HomeSOC")

    run = entries("Run")
    [agent] = [e for e in run if "HomeSOC-Agent.exe" in _command(e)]
    cmd = _command(agent)
    assert "-UserId 'SYSTEM'" in cmd and "-RunLevel Highest" in cmd
    assert "Register-ScheduledTask" in cmd and "Start-ScheduledTask" in cmd
    assert "-ExecutionTimeLimit ([TimeSpan]::Zero)" in cmd  # schtasks' default kills it at 72 h
    [app] = [e for e in run if e.get("Filename") == "{app}\\HomeSOC.exe"]
    assert "runasoriginaluser" in app["Flags"].split()
    assert "postinstall" in app["Flags"].split()


def test_iss_parser_unquotes_inno_strings() -> None:
    entry = _split_entry('Filename: "a.exe"; Parameters: "-Command ""x; y"""; Flags: runhidden')
    assert entry == {"Filename": "a.exe", "Parameters": '-Command "x; y"', "Flags": "runhidden"}


# --- README ---------------------------------------------------------------------------------


def _readme_section(heading_word: str) -> str:
    """The README section whose heading names ``heading_word`` (code blocks included)."""
    lines, in_fence, found = [], False, False
    for line in README.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
        is_heading = not in_fence and line.startswith("#")
        if is_heading and found:
            break
        if is_heading and heading_word in line:
            found = True
        if found:
            lines.append(line)
    assert found, f"README has no section about {heading_word}"
    return "\n".join(lines)


def test_readme_documents_the_build() -> None:
    build = _readme_section("installer")
    assert "pyinstaller --noconfirm installer\\homesoc.spec" in build
    assert "ISCC.exe\" installer\\homesoc.iss" in build
    assert "HomeSOC-Setup.exe" in build
    assert "%PROGRAMDATA%\\HomeSOC" in build  # where the writable data goes


def test_readme_says_the_defender_exclusion_is_test_vm_only() -> None:
    section = _readme_section("Defender")
    assert "test VM only" in section
    assert "Add-MpPreference -ExclusionPath" in section
    assert "Remove-MpPreference -ExclusionPath" in section
    assert "Never" in section and "real" in section
    # Only the build folder, never a whole drive or the install folder.
    for path in re.findall(r"-ExclusionPath\s+(\S+)", section):
        assert path.strip('"').endswith("\\dist"), path


def test_readme_documents_the_manual_fresh_vm_check() -> None:
    section = _readme_section("Manual check")
    assert "HomeSOC-Setup.exe" in section and "green" in section
