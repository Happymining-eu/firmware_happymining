"""Which files of a source are candidates, and how one is opened."""

from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest
from hm_vectorizer import walker
from hm_vectorizer.walker import (
    NotRegularFile,
    extension_of,
    is_excluded,
    open_regular_file,
    open_source_root,
    walk_source,
)
from vz_support import Site


def walk(site: Site, **changes: object) -> walker.SourceWalk:
    cfg = site.save(**changes) if changes else site.load()
    return walk_source(cfg, cfg.sources[0])


def paths(result: walker.SourceWalk) -> list[str]:
    return [f.rel_path for f in result.files]


def test_only_wanted_extensions_whatever_their_case(site: Site) -> None:
    site.write("report.PDF", b"x")
    site.write("notes.md", "x")
    site.write("archive.tar.gz", b"x")
    site.write("photo.jpg", b"x")
    site.write("README", "x")
    site.write(".hidden", "x")
    site.write("trailing.", "x")
    result = walk(site)
    assert paths(result) == ["notes.md", "report.PDF"]
    assert [f.ext for f in result.files] == ["md", "pdf"]
    assert result.ignored["other_extension"] == 5
    assert sum(result.skipped.values()) == 0


def test_extension_of() -> None:
    assert extension_of("a.TXT") == "txt"
    assert extension_of("a.tar.gz") == "gz"
    assert extension_of("noext") == ""
    assert extension_of(".bashrc") == ""
    assert extension_of("dot.") == ""


def test_order_is_stable_sorted_by_name_depth_first(site: Site) -> None:
    for name in ["b.txt", "a/z.txt", "a/b/c.txt", "c/a.txt", "a.txt", "B.txt"]:
        site.write(name, "x")
    first = paths(walk(site))
    assert first == ["B.txt", "a/b/c.txt", "a/z.txt", "a.txt", "b.txt", "c/a.txt"]
    assert paths(walk(site)) == first


def test_entry_carries_size_and_modification_time(site: Site) -> None:
    path = site.write("a.txt", "12345")
    (entry,) = walk(site).files
    assert (entry.source_id, entry.size, entry.mtime_ns) == ("docs", 5, path.stat().st_mtime_ns)


def test_excluded_directory_name_matches_at_any_depth_and_is_not_entered(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    site.write("keep.txt", "x")
    site.write("#recycle/old.txt", "x")
    site.write("projects/#recycle/deep/older.txt", "x")
    site.write("projects/recycle/kept.txt", "x")

    listed: list[int] = []
    real = walker._list_dir

    def spy(fd: int) -> list[os.DirEntry[str]]:
        listed.append(fd)
        return real(fd)

    monkeypatch.setattr(walker, "_list_dir", spy)
    result = walk(site)
    assert paths(result) == ["keep.txt", "projects/recycle/kept.txt"]
    assert result.ignored["excluded"] == 2
    # the root, projects and projects/recycle: neither #recycle directory was listed
    assert len(listed) == 3


def test_excluded_path_is_a_run_of_whole_segments(site: Site) -> None:
    site.write("private/hr/salaries.txt", "x")
    site.write("teams/private/hr/review.txt", "x")
    site.write("private/hr-archive/ok.txt", "x")
    site.write("private/notes/hr/ok.txt", "x")
    site.write("hr/private/ok.txt", "x")
    site.write("xprivate/hr/ok.txt", "x")
    assert paths(walk(site)) == [
        "hr/private/ok.txt",
        "private/hr-archive/ok.txt",
        "private/notes/hr/ok.txt",
        "xprivate/hr/ok.txt",
    ]


def test_exclusion_ignores_case_and_unicode_composition(site: Site) -> None:
    site.write("Private/HR/a.txt", "x")
    site.write("#RECYCLE/b.txt", "x")
    site.write("résumés/c.txt", "x")  # decomposed accents on disk
    site.write("kept/d.txt", "x")
    assert paths(walk(site, exclude=["private/hr", "#recycle", "résumés"])) == ["kept/d.txt"]


def test_exclusion_can_name_a_file(site: Site) -> None:
    site.write("a/secret.txt", "x")
    site.write("a/public.txt", "x")
    assert paths(walk(site, exclude=["a/secret.txt"])) == ["a/public.txt"]


def test_is_excluded() -> None:
    patterns = (("private", "hr"), ("#recycle",))
    assert is_excluded(("a", "private", "hr", "f.txt"), patterns)
    assert is_excluded(("#recycle",), patterns)
    assert not is_excluded(("private", "x", "hr"), patterns)
    assert not is_excluded(("hr",), patterns)
    assert not is_excluded((), patterns)


def test_size_limit_and_empty_files(site: Site) -> None:
    site.write("exact.txt", b"a" * (1024 * 1024))
    site.write("over.txt", b"a" * (1024 * 1024 + 1))
    site.write("empty.txt", b"")
    result = walk(site)
    assert paths(result) == ["exact.txt"]
    assert result.skipped == {"too_large": 1, "empty": 1}


def test_symbolic_links_are_never_followed(site: Site, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "passwords.txt").write_text("root:hunter2")
    site.write("real/inner.txt", "x")
    docs = site.source_dir()
    os.symlink(outside / "passwords.txt", docs / "link-to-outside-file.txt")
    os.symlink(outside, docs / "link-to-outside-dir")
    os.symlink(docs / "real" / "inner.txt", docs / "link-to-inside-file.txt")
    os.symlink(docs / "real", docs / "link-to-inside-dir")
    os.symlink(docs / "nowhere.txt", docs / "dangling.txt")
    os.symlink("..", docs / "real" / "up")
    result = walk(site)
    assert paths(result) == ["real/inner.txt"]
    assert result.skipped == {"symlink": 6}


def test_special_files_are_skipped(site: Site) -> None:
    site.write("a.txt", "x")
    os.mkfifo(site.source_dir() / "pipe.txt")
    sock = socket.socket(socket.AF_UNIX)
    try:
        sock.bind(str(site.source_dir() / "sock.txt"))
        result = walk(site)
    finally:
        sock.close()
    assert paths(result) == ["a.txt"]
    assert result.skipped == {"special": 2}


def test_office_and_macos_leftovers_are_skipped(site: Site) -> None:
    site.write("report.docx", b"x")
    site.write("~$report.docx", b"x")
    site.write("._report.docx", b"x")
    site.write(".~lock.report.docx", b"x")
    result = walk(site)
    assert paths(result) == ["report.docx"]
    assert result.skipped == {"temp_file": 3}


def test_name_that_is_not_text_is_skipped(site: Site) -> None:
    site.write("ok.txt", "x")
    with open(os.fsencode(site.source_dir()) + b"/bad-\xff.txt", "wb") as handle:
        handle.write(b"x")
    result = walk(site)
    assert paths(result) == ["ok.txt"]
    assert result.skipped == {"bad_name": 1}


def test_depth_is_limited(site: Site, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(walker, "MAX_DEPTH", 3)
    site.write("a/b/ok.txt", "x")
    site.write("a/b/c/too-deep.txt", "x")
    result = walk(site)
    assert paths(result) == ["a/b/ok.txt"]
    assert result.skipped == {"too_deep": 1}


# -- sources that cannot be read ---------------------------------------------------


def test_missing_source_is_unavailable(site: Site) -> None:
    site.source_dir().rmdir()
    result = walk(site)
    assert not result.available and result.files == []
    assert result.is_unknown("anything.txt")


def test_empty_source_is_unavailable_not_emptied(site: Site) -> None:
    """An unmounted NAS is an empty directory."""
    result = walk(site)
    assert not result.available
    assert result.is_unknown("anything.txt")


def test_source_whose_subpath_is_a_link_is_unavailable(site: Site, tmp_path: Path) -> None:
    secret = tmp_path / "container-config"
    secret.mkdir()
    (secret / "token.txt").write_text("the token")
    os.symlink(secret, site.source_dir() / "sub")
    cfg = site.save(source_paths={"docs": f"{site.nas_root}/docs/sub"})
    with pytest.raises(OSError):
        open_source_root(cfg.sources[0])
    result = walk_source(cfg, cfg.sources[0])
    assert not result.available and result.files == []


def test_unreadable_directory_makes_what_is_below_unknown(
    site: Site, monkeypatch: pytest.MonkeyPatch
) -> None:
    site.write("ok/a.txt", "x")
    site.write("flaky/b.txt", "x")
    site.write("flaky/deep/c.txt", "x")
    real = walker._list_dir
    flaky = os.stat(site.source_dir() / "flaky").st_ino

    def failing(fd: int) -> list[os.DirEntry[str]]:
        if os.fstat(fd).st_ino == flaky:
            raise OSError(5, "Input/output error")
        return real(fd)

    monkeypatch.setattr(walker, "_list_dir", failing)
    result = walk(site)
    assert result.available
    assert paths(result) == ["ok/a.txt"]
    assert result.unknown_prefixes == ["flaky"]
    assert result.is_unknown("flaky/b.txt") and result.is_unknown("flaky/deep/c.txt")
    assert not result.is_unknown("flaky-other/x.txt") and not result.is_unknown("ok/a.txt")


# -- opening ------------------------------------------------------------------


def test_open_regular_file_reads_through_the_root_descriptor(site: Site) -> None:
    site.write("a/b/c.txt", "content")
    cfg = site.load()
    root = open_source_root(cfg.sources[0])
    try:
        fd = open_regular_file(root, "a/b/c.txt")
        with os.fdopen(fd, "rb") as handle:
            assert handle.read() == b"content"
    finally:
        os.close(root)


def test_open_refuses_a_link_as_file_or_as_directory(site: Site, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    site.write("real/a.txt", "x")
    docs = site.source_dir()
    os.symlink(outside / "secret.txt", docs / "real" / "link.txt")
    os.symlink(outside, docs / "linkdir")
    cfg = site.load()
    root = open_source_root(cfg.sources[0])
    try:
        with pytest.raises(NotRegularFile):
            open_regular_file(root, "real/link.txt")
        with pytest.raises(OSError):
            open_regular_file(root, "linkdir/secret.txt")
    finally:
        os.close(root)


@pytest.mark.parametrize("rel_path", ["../outside.txt", "a/../../x.txt", "/etc/passwd", "a//b.txt", ".", ""])
def test_open_refuses_paths_that_are_not_plain_relative_paths(site: Site, rel_path: str) -> None:
    site.write("a/b.txt", "x")
    cfg = site.load()
    root = open_source_root(cfg.sources[0])
    try:
        with pytest.raises(NotRegularFile):
            open_regular_file(root, rel_path)
    finally:
        os.close(root)


def test_open_refuses_a_fifo_without_blocking(site: Site) -> None:
    site.write("a.txt", "x")
    os.mkfifo(site.source_dir() / "pipe.txt")
    cfg = site.load()
    root = open_source_root(cfg.sources[0])
    try:
        with pytest.raises(NotRegularFile):
            open_regular_file(root, "pipe.txt")
    finally:
        os.close(root)


def test_walk_leaves_no_descriptor_open(site: Site) -> None:
    for i in range(30):
        site.write(f"d{i}/sub/f.txt", "x")
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(5):
        walk(site)
    assert len(os.listdir("/proc/self/fd")) == before
