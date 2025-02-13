import pathlib
import dexrs

assets_base_dir = pathlib.Path(__file__).parent.parent.parent / "tests"


def get_asset(asset_name: str) -> pathlib.Path:
    return assets_base_dir / asset_name


PRIME_DEX = dexrs.DexFile.from_file(
    dexrs.FileDexContainer(str(get_asset("prime/prime.dex")))
)