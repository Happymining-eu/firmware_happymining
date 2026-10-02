"""Request bodies of the appliance and release routes (docs/appliance.md, sections 9 and 12).

These models fix the *shape* of a request: which keys exist, of which JSON
type, within which size. Unknown keys are refused, and nothing is coerced: a
string is not accepted where a number is expected, and text is not trimmed.
The *rules* of the document (patterns, cross references, what a kind of entry
may carry) are checked in one place, ``services/appliance.validate_document``,
on the whole document the change would produce.

A secret never has a field of its own for clear text. It arrives sealed for
the machine (``sealed_secret`` / ``sealed_secrets``) next to the object that
uses it, and the caller never chooses the name it is stored under.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

Text = Annotated[str, StringConstraints(max_length=600)]
ShortText = Annotated[str, StringConstraints(max_length=200)]
# A sealed value of the largest secret (4096 bytes) is about 5.6 KiB of base64url.
Sealed = Annotated[str, StringConstraints(max_length=6000)]


class Exact(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ModeIn(Exact):
    mode: ShortText


class PluginIn(Exact):
    enabled: bool
    settings: dict[ShortText, Any] = Field(default_factory=dict, max_length=32)
    # Catalog secret key -> sealed value. null removes a stored, optional secret.
    sealed_secrets: dict[ShortText, Sealed | None] | None = Field(default=None, max_length=32)


class NasIn(Exact):
    kind: ShortText
    host: Text
    access: ShortText
    subpath: Text | None = None
    # smb
    share: ShortText | None = None
    username: ShortText | None = None
    domain: ShortText | None = None
    sealed_secret: Sealed | None = None
    # nfs
    export: Text | None = None


class AnswerIn(Exact):
    provider: ShortText
    model: ShortText | None = None
    base_url: Text | None = None
    sealed_secret: Sealed | None = None


class VectorizerIn(Exact):
    sources: Annotated[list[ShortText], Field(max_length=64)]
    extensions: Annotated[list[ShortText], Field(max_length=64)]
    exclude: Annotated[list[Text], Field(max_length=64)]
    max_file_mib: int
    embedding_model: ShortText
    ocr: bool
    answer: AnswerIn


class DestinationIn(Exact):
    kind: ShortText
    # nas
    nas_id: ShortText | None = None
    subpath: Text | None = None
    # s3
    endpoint: Text | None = None
    region: ShortText | None = None
    bucket: ShortText | None = None
    prefix: Text | None = None
    access_key_id: ShortText | None = None
    sealed_secret: Sealed | None = None


class BackupIn(Exact):
    enabled: bool
    destination: DestinationIn
    include_models: bool
    keep: int


class ScheduleIn(Exact):
    job: ShortText
    every: ShortText
    minute: int
    enabled: bool
    hour: int | None = None
    weekday: int | None = None
    plugin: ShortText | None = None


class WindowIn(Exact):
    start_hour: int
    end_hour: int


class UpdateIn(Exact):
    channel: ShortText
    policy: ShortText
    window: WindowIn | None = None


class JobIn(Exact):
    job: ShortText
    plugin: ShortText | None = None


class InstallUpdateIn(Exact):
    version: Annotated[str, StringConstraints(max_length=24)]


# --- releases --------------------------------------------------------------


class ReleaseIn(Exact):
    # The manifest file, byte for byte, in base64 (at most 16 KiB before encoding).
    manifest_b64: Annotated[str, StringConstraints(min_length=1, max_length=24000)]
    signature_b64: Annotated[str, StringConstraints(min_length=1, max_length=128)]


class ChannelsIn(Exact):
    channels: Annotated[list[ShortText], Field(max_length=8)]


class WithdrawIn(Exact):
    reason: Annotated[str, StringConstraints(min_length=1, max_length=300)]
