import pathlib

assets_base_dir = pathlib.Path(__file__).parent.parent.parent / "tests"


def get_asset(asset_name: str) -> pathlib.Path:
    return assets_base_dir / asset_name