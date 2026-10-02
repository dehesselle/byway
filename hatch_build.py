import tempfile
from pathlib import Path

from hatchling.builders.hooks.plugin.interface import BuildHookInterface
from hatchling.builders.sdist import SdistBuilder

# Where a copy of usernet's package sources lives inside our own sdist, so the
# wheel-from-sdist build phase has something to pull from once the sibling
# checkout below is no longer around (sdists must be self-contained). Placed
# next to src/pyac, matching this project's own src layout.
_USERNET_IN_SDIST = "src/usernet"


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        # The "editable" version is what `uv sync` installs for local dev; it
        # must resolve usernet via the sibling checkout's own editable install
        # (see [tool.uv.sources] in pyproject.toml), not a vendored snapshot
        # baked in here. Force-including source only makes sense for a real
        # distributable wheel/sdist, so skip it for editable builds.
        if version == "editable":
            return

        sibling_usernet = Path(self.root).parent / "usernet"
        usernet_in_sdist = Path(self.root) / _USERNET_IN_SDIST

        if sibling_usernet.is_dir():
            _regenerate_version(sibling_usernet)
            source = sibling_usernet / "src" / "usernet"
        elif usernet_in_sdist.is_dir():
            source = usernet_in_sdist
        else:
            return

        # The wheel installs packages flat, same as src/pyac -> pyac.
        target = _USERNET_IN_SDIST if self.target_name == "sdist" else "usernet"
        build_data.setdefault("force_include", {})[str(source)] = target


def _regenerate_version(usernet: Path) -> None:
    # Runs only usernet's own build hooks (in particular hatch-vcs's version-file
    # hook) instead of a full `uv build`, so this neither writes an unused
    # wheel into usernet's dist/ nor depends on `uv` being on PATH.
    with tempfile.TemporaryDirectory() as scratch:
        list(
            SdistBuilder(str(usernet)).build(
                directory=scratch, versions=["standard"], hooks_only=True
            )
        )
