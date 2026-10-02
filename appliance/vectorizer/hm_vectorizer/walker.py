"""Enumerating the files of a source, and opening one of them, without ever
following a symbolic link.

Rules (docs/appliance.md 4.4, and the safest reading where it is silent):

- only files whose extension is wanted are candidates;
- a file is left out when a sequence of its path segments matches an
  `exclude` pattern; an excluded directory is not entered at all;
- files over the size limit and empty files are skipped;
- symbolic links are never followed, to a file or to a directory, inside or
  outside the source: a link can point out of the share, and a link inside it
  can point into an excluded directory. What a link points to inside the
  share is reached by its real path anyway;
- sockets, FIFOs and devices are skipped;
- directories are opened one component at a time with O_NOFOLLOW, starting
  at the mount point, so a component replaced by a link between listing and
  opening is refused by the kernel;
- the order is stable: entries sorted by name, depth first.

A directory that cannot be listed makes everything below it *unknown*: the
caller must not conclude that the files it indexed there have disappeared.
"""

from __future__ import annotations

import os
import stat
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field

from .config import Config, SourceConfig, normalize_segment

MAX_DEPTH = 64
MAX_REL_PATH_CHARS = 4096

# Left by office suites and by macOS on network shares; they carry the
# extension of a document and are not one.
_TEMP_PREFIXES = ("~$", "._", ".~lock.")

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(frozen=True)
class FileEntry:
    source_id: str
    rel_path: str  # POSIX path relative to the root of the source
    size: int
    mtime_ns: int
    ext: str


@dataclass
class SourceWalk:
    source_id: str
    available: bool = True
    files: list[FileEntry] = field(default_factory=list)
    skipped: Counter[str] = field(default_factory=Counter)  # wanted files left out, by reason
    ignored: Counter[str] = field(default_factory=Counter)  # other_extension, excluded
    unknown_prefixes: list[str] = field(default_factory=list)  # directories that could not be listed

    def is_unknown(self, rel_path: str) -> bool:
        """True when the walk cannot tell whether this path still exists."""
        if not self.available:
            return True
        return any(rel_path == p or rel_path.startswith(p + "/") for p in self.unknown_prefixes)


class NotRegularFile(OSError):
    """The path is not, or is no longer, a regular file reachable without a link."""


def extension_of(name: str) -> str:
    """Lower-cased text after the last dot; "" when there is none."""
    dot = name.rfind(".")
    if dot <= 0 or dot == len(name) - 1:
        return ""
    return name[dot + 1 :].lower()


def is_excluded(segments: Sequence[str], patterns: Sequence[Sequence[str]]) -> bool:
    """True when a pattern equals a run of consecutive segments of the path.

    `segments` and `patterns` are normalised with `normalize_segment`.
    """
    for pattern in patterns:
        width = len(pattern)
        if width == 0 or width > len(segments):
            continue
        for start in range(len(segments) - width + 1):
            if tuple(segments[start : start + width]) == tuple(pattern):
                return True
    return False


def open_source_root(source: SourceConfig) -> int:
    """Open the root directory of a source and return its descriptor.

    The mount point is opened first, then each segment of the subpath with
    O_NOFOLLOW: a link placed in the share where the subpath should be cannot
    lead the service into its own container file system.
    """
    fd = os.open(source.mount, _DIR_FLAGS)
    try:
        for segment in source.subpath:
            child = os.open(segment, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


def open_regular_file(root_fd: int, rel_path: str) -> int:
    """Open a file of the source for reading, refusing any link on the way.

    Returns a descriptor on a regular file. Raises NotRegularFile or OSError.
    """
    segments = rel_path.split("/")
    if not segments or any(s in ("", ".", "..") for s in segments):
        raise NotRegularFile("unusable relative path")
    dir_fd = os.dup(root_fd)
    try:
        for segment in segments[:-1]:
            child = os.open(segment, _DIR_FLAGS, dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = child
        try:
            fd = os.open(segments[-1], _FILE_FLAGS, dir_fd=dir_fd)
        except OSError as exc:
            raise NotRegularFile("cannot be opened without following a link") from exc
    finally:
        os.close(dir_fd)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise NotRegularFile("not a regular file")
        os.set_blocking(fd, True)
    except BaseException:
        os.close(fd)
        raise
    return fd


def walk_source(cfg: Config, source: SourceConfig) -> SourceWalk:
    """List the candidate files of one source."""
    result = SourceWalk(source_id=source.source_id)
    try:
        root_fd = open_source_root(source)
    except OSError:
        result.available = False
        return result
    try:
        try:
            top = _list_dir(root_fd)
        except OSError:
            result.available = False
            return result
        if not top:
            # An unmounted NAS shows up as an empty directory. Reading that as
            # "every file was deleted" would empty the index.
            result.available = False
            return result
        _walk_dir(cfg, result, root_fd, top, (), ())
    finally:
        os.close(root_fd)
    return result


def _list_dir(fd: int) -> list[os.DirEntry[str]]:
    # scandir() works on its own duplicate of the descriptor and leaves this one open.
    with os.scandir(fd) as it:
        return sorted(it, key=lambda entry: entry.name)


def _walk_dir(
    cfg: Config,
    result: SourceWalk,
    dir_fd: int,
    entries: list[os.DirEntry[str]],
    segments: tuple[str, ...],
    normalized: tuple[str, ...],
) -> None:
    for entry in entries:
        name = entry.name
        rel_segments = (*segments, name)
        rel_path = "/".join(rel_segments)
        try:
            name.encode("utf-8")
        except UnicodeEncodeError:
            result.skipped["bad_name"] += 1
            continue
        rel_normalized = (*normalized, normalize_segment(name))
        try:
            is_link = entry.is_symlink()
            is_dir = not is_link and entry.is_dir(follow_symlinks=False)
            is_file = not is_link and not is_dir and entry.is_file(follow_symlinks=False)
        except OSError:
            result.unknown_prefixes.append(rel_path)
            continue

        if is_excluded(rel_normalized, cfg.exclude):
            result.ignored["excluded"] += 1
            continue
        if is_link:
            result.skipped["symlink"] += 1
            continue

        if is_dir:
            if len(rel_segments) >= MAX_DEPTH:
                result.skipped["too_deep"] += 1
                continue
            try:
                child_fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
            except OSError:
                result.unknown_prefixes.append(rel_path)
                continue
            try:
                try:
                    children = _list_dir(child_fd)
                except OSError:
                    result.unknown_prefixes.append(rel_path)
                    continue
                _walk_dir(cfg, result, child_fd, children, rel_segments, rel_normalized)
            finally:
                os.close(child_fd)
            continue

        if not is_file:
            result.skipped["special"] += 1
            continue

        ext = extension_of(name)
        if ext not in cfg.extensions:
            result.ignored["other_extension"] += 1
            continue
        if name.startswith(_TEMP_PREFIXES):
            result.skipped["temp_file"] += 1
            continue
        if len(rel_path) > MAX_REL_PATH_CHARS:
            result.skipped["bad_name"] += 1
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            result.unknown_prefixes.append(rel_path)
            continue
        if not stat.S_ISREG(info.st_mode):
            result.skipped["special"] += 1
            continue
        if info.st_size == 0:
            result.skipped["empty"] += 1
            continue
        if info.st_size > cfg.max_file_bytes:
            result.skipped["too_large"] += 1
            continue
        result.files.append(
            FileEntry(
                source_id=result.source_id,
                rel_path=rel_path,
                size=info.st_size,
                mtime_ns=info.st_mtime_ns,
                ext=ext,
            )
        )
