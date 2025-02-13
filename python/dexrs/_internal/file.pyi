from .container import InMemoryDexContainer, FileDexContainer
from .structs import Header

class VerifyPreset:
    ALL: VerifyPreset
    NONE: VerifyPreset
    CHECKSUM_ONLY: VerifyPreset

class DexFile:
    @staticmethod
    def from_file(data: FileDexContainer, preset: VerifyPreset = ...) -> DexFile: ...
    @staticmethod
    def from_bytes(
        data: InMemoryDexContainer, preset: VerifyPreset = ...
    ) -> DexFile: ...

    # instance methods
    def get_header(self) -> Header: ...
