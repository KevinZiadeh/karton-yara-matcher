"""Karton YARA Service."""

import pathlib
import re
from typing import ClassVar, cast

import yara
from karton.core import Karton, RemoteResource, Task

from .__version__ import __version__


class YaraMatcher(Karton):
    """
    Perform YARA on sample and add corresponding tags.

    **Consumes:**
    ```
    {"type": "sample", "stage": "recognized"}
    ```

    **Produces:**
    ```
    {
        "headers": {"type": "sample", "stage": "analyzed"},
        "payload": {
            "sample": sample,
            "tags": <YARA tags>,
        }
    }
    ```
    """

    identity = "karton.yara-matcher"
    filters: ClassVar = [
        {"type": "sample", "stage": "recognized"},
    ]
    version = __version__
    RULES_PATH = "/app/rules"
    _compiled_rules = None

    def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003, D107
        super().__init__(*args, **kwargs)
        self.log.info("Initializing YaraScanner...")

        yara_dir = pathlib.Path(self.RULES_PATH)
        if not yara_dir.exists() or not yara_dir.is_dir():
            raise FileNotFoundError(f"Yara directory not found: {yara_dir}")

        yara_files = list(yara_dir.rglob("*.yar*"))
        if not yara_files:
            raise FileNotFoundError(f"No Yara rules found in directory: {yara_dir}")

        rule_paths = [f.resolve().as_posix() for f in yara_files if f.is_file()]

        compiled_rules = {}
        self.log.info(f"Compiling {len(rule_paths)} YARA rules...")
        for i, path in enumerate(rule_paths):
            try:
                # Check if rule compiles
                yara.compile(filepath=path)
                compiled_rules[str(i)] = path
            except yara.SyntaxError as e:
                self.log.warning(f"Skipped {path} (SyntaxError: {e})")
            except Exception as e:  # noqa: BLE001
                self.log.warning(f"Skipped {path} (Other error: {e})")

        self.yara_handler: yara.Rules = yara.compile(filepaths=compiled_rules)

    @staticmethod
    def normalize_rule_name(match: str) -> str:
        """Normalize a YARA rule name."""
        parts = match.replace(" ","-").split("_")
        for ignore_pattern in ["g\\d+", "w\\d+", "a\\d+", "auto"]:
            if re.match(ignore_pattern, parts[-1]):
                return "_".join(parts[:-1])
        return match

    def process(self, task: Task) -> None:
        """
        Entry point of this service.

        Takes a sample and perform YARA on it. Add tags to the sample.

        Args:
            task (Task): Karton task

        """
        sample_resource = cast("RemoteResource", task.get_resource("sample"))
        tags = None
        with sample_resource.download_temporary_file() as f:
            matches = self.yara_handler.match(f.name)
            tags = sorted({
                f"yara:{YaraMatcher.normalize_rule_name(match.rule)}"
                for match in matches
            })

        if not tags:
            return

        self.send_task(
            Task(
                headers={"type": "sample", "stage": "analyzed"},
                payload={
                    "sample": sample_resource,
                    "tags": tags,
                },
            ),
        )
        self.log.info(f"Successfully pushed YATA tags for {sample_resource.sha256}")
