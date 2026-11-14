"""Streaming chunk parser and format sniffer for multi-source ingestion (Issue #46)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple, Union

import pandas as pd

from network_anomaly.ingestion.adapters import (
    AWSVPCFlowAdapter,
    BaseSourceAdapter,
    NetFlowV3Adapter,
    NetFlowV5Adapter,
    SuricataEveAdapter,
    UnsupportedSourceAdapter,
    ZeekConnAdapter,
)
from network_anomaly.ingestion.exceptions import (
    FormatInvalidError,
    IngestionError,
    SourceUnsupportedError,
)
from network_anomaly.ingestion.registry import SourceDefinition, SourceRegistry
from network_anomaly.ingestion.schemas import CanonicalNetworkEvent

MAX_DEFAULT_FILE_SIZE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB safety cap


class FormatSniffer:
    """Sniffs physical format, delimiter, and infers source schema."""

    def __init__(self, registry: Optional[SourceRegistry] = None) -> None:
        self.registry = registry or SourceRegistry()

    def inspect_file(
        self,
        file_path: Union[str, Path],
        max_bytes: int = MAX_DEFAULT_FILE_SIZE_BYTES,
    ) -> Tuple[str, str, Optional[SourceDefinition]]:
        """Inspect file format, delimiter, and matching SourceDefinition.

        Returns
        -------
        file_type : str
            'csv', 'tsv', 'jsonl', 'json'
        delimiter : str
            ',', '\t', ' '
        source_def : Optional[SourceDefinition]
            Matching source from registry, or None if unknown.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Input file not found: {path}")

        file_size = path.stat().st_size
        if file_size > max_bytes:
            raise IngestionError(
                f"File size {file_size:,} bytes exceeds maximum allowed limit {max_bytes:,} bytes."
            )

        suffix = path.suffix.lower()

        # Check JSON / JSONL
        if suffix in [".json", ".jsonl"]:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                first_line = f.readline().strip()
                try:
                    record = json.loads(first_line)
                    cols = list(record.keys()) if isinstance(record, dict) else []
                    matched = self.registry.detect_source(cols)
                    return ("jsonl" if suffix == ".jsonl" else "json"), "", matched
                except Exception:
                    raise FormatInvalidError(f"Malformed JSON in first line of {path}")

        # Check Delimited (CSV / TSV / space)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            first_line = f.readline().strip()
            if not first_line:
                raise FormatInvalidError(f"Input file {path} is empty")

            # Check if Zeek TSV header (#fields)
            if first_line.startswith("#fields"):
                cols = first_line.split("\t")[1:]
                matched = self.registry.get_source("source:zeek-conn")
                return "tsv", "\t", matched

            # Sniff delimiter
            if "\t" in first_line:
                delimiter = "\t"
                file_type = "tsv"
            elif "," in first_line:
                delimiter = ","
                file_type = "csv"
            elif " " in first_line:
                delimiter = " "
                file_type = "space-delimited"
            else:
                delimiter = ","
                file_type = "csv"

            cols = [c.strip() for c in first_line.split(delimiter) if c.strip()]
            matched = self.registry.detect_source(cols)
            return file_type, delimiter, matched


class StreamingChunkParser:
    """Streams large network files in bounded memory chunks and applies appropriate adapter."""

    def __init__(
        self,
        registry: Optional[SourceRegistry] = None,
        chunk_size: int = 10000,
        fail_on_malformed: bool = False,
    ) -> None:
        self.registry = registry or SourceRegistry()
        self.sniffer = FormatSniffer(self.registry)
        self.chunk_size = chunk_size
        self.fail_on_malformed = fail_on_malformed

    def get_adapter(self, source_def: SourceDefinition) -> BaseSourceAdapter:
        """Instantiate corresponding adapter for a source definition."""
        adapter_name = source_def.adapter_name
        if adapter_name == "NetFlowV3Adapter":
            return NetFlowV3Adapter(
                source_id=source_def.source_id, schema_version=source_def.schema_version
            )
        elif adapter_name == "ZeekConnAdapter":
            return ZeekConnAdapter(
                source_id=source_def.source_id, schema_version=source_def.schema_version
            )
        elif adapter_name == "NetFlowV5Adapter":
            return NetFlowV5Adapter(
                source_id=source_def.source_id, schema_version=source_def.schema_version
            )
        elif adapter_name == "AWSVPCFlowAdapter":
            return AWSVPCFlowAdapter(
                source_id=source_def.source_id, schema_version=source_def.schema_version
            )
        elif adapter_name == "SuricataEveAdapter":
            return SuricataEveAdapter(
                source_id=source_def.source_id, schema_version=source_def.schema_version
            )
        else:
            return UnsupportedSourceAdapter(
                source_id=source_def.source_id, schema_version=source_def.schema_version
            )

    def parse_file_chunks(
        self,
        file_path: Union[str, Path],
        explicit_source_id: Optional[str] = None,
    ) -> Generator[List[CanonicalNetworkEvent], None, None]:
        """Yield chunks of CanonicalNetworkEvents from a file using streaming I/O."""
        path = Path(file_path)
        file_type, delimiter, detected_source = self.sniffer.inspect_file(path)

        if explicit_source_id:
            source_def = self.registry.get_source(explicit_source_id)
        elif detected_source:
            source_def = detected_source
        else:
            raise SourceUnsupportedError(
                f"Could not automatically identify source format for {path}. Please specify explicit_source_id."
            )

        adapter = self.get_adapter(source_def)

        # JSONL stream
        if file_type == "jsonl":
            chunk_records: List[Dict[str, Any]] = []
            record_idx = 0
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        if isinstance(record, dict):
                            chunk_records.append(record)
                            record_idx += 1
                    except json.JSONDecodeError as err:
                        if self.fail_on_malformed:
                            raise FormatInvalidError(
                                f"Malformed JSONL at line {record_idx+1}: {err}"
                            )
                    if len(chunk_records) >= self.chunk_size:
                        yield [
                            adapter.adapt_record(r, record_idx=i)
                            for i, r in enumerate(chunk_records)
                        ]
                        chunk_records = []
            if chunk_records:
                yield [adapter.adapt_record(r, record_idx=i) for i, r in enumerate(chunk_records)]
            return

        # Zeek TSV stream (handles #fields header and comment lines)
        if source_def.source_id == "source:zeek-conn" or (file_type == "tsv" and delimiter == "\t"):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                first_few = [f.readline() for _ in range(15)]
            fields_line = next(
                (line_item for line_item in first_few if line_item.startswith("#fields")), None
            )
            if fields_line:
                cols = fields_line.strip().split("\t")[1:]
                chunk_records = []
                record_counter = 0
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("#") or not line.strip():
                            continue
                        parts = line.strip().split("\t")
                        if len(parts) == len(cols):
                            chunk_records.append(dict(zip(cols, parts)))
                            record_counter += 1
                        if len(chunk_records) >= self.chunk_size:
                            yield [
                                adapter.adapt_record(r, record_idx=i)
                                for i, r in enumerate(chunk_records)
                            ]
                            chunk_records = []
                if chunk_records:
                    yield [
                        adapter.adapt_record(r, record_idx=i) for i, r in enumerate(chunk_records)
                    ]
                return

        # Delimited table stream via pandas chunks
        try:
            reader = pd.read_csv(
                path,
                sep=delimiter,
                chunksize=self.chunk_size,
                low_memory=True,
                comment="#",
                on_bad_lines="error" if self.fail_on_malformed else "skip",
            )
            for chunk_df in reader:
                events = adapter.adapt_dataframe(chunk_df)
                yield events
        except Exception as err:
            raise FormatInvalidError(f"Failed to parse delimited stream from {path}: {err}")
