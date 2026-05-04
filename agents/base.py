"""
agents/base.py
Classe de base abstraite pour AnalystAgent et CriticAgent.
"""
from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod

from schemas.finding import Finding


class BaseAgent(ABC):
    """Common base class for AnalystAgent and CriticAgent.

    Subclasses must implement `run(findings) -> list[Finding]` and call
    `_parse_findings()` on the LLM response text.
    """

    def __init__(self, model: str, temperature: float = 1.0):
        self.model = model
        self.temperature = temperature

    @abstractmethod
    def run(self, findings: list[Finding]) -> list[Finding]:
        ...

    @staticmethod
    def _strip_code_fence(raw: str) -> str:
        """Strip a ```...``` markdown fence if the model wrapped its JSON."""
        raw = raw.strip()
        if raw.startswith("```"):
            # Drop the opening fence (with optional language tag) and closing fence.
            lines = raw.splitlines()
            if lines:
                lines = lines[1:]
                if lines and lines[-1].strip().startswith("```"):
                    lines = lines[:-1]
            raw = "\n".join(lines).strip()
        return raw

    def _parse_findings(self, raw: str) -> list[Finding]:
        """Parse a JSON response into Finding objects.

        Resilient against:
        - empty / whitespace-only responses (raises ValueError)
        - markdown code fences (strip)
        - LLM truncation (max_tokens hit) — try to recover the longest
          prefix that parses as a JSON object/array, otherwise raise a
          ValueError that names the failure mode (so the caller can decide
          whether to retry with a smaller batch).
        """
        cleaned = self._strip_code_fence(raw)
        if not cleaned.strip():
            raise ValueError("LLM returned empty content (likely max_tokens=0 or upstream filter)")

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            recovered = self._recover_truncated_json(cleaned)
            if recovered is None:
                raise ValueError(
                    f"LLM response is not valid JSON and no salvageable prefix found "
                    f"(error: {exc.msg} at pos {exc.pos}). Likely truncated — "
                    f"reduce max_tokens consumer or batch size."
                ) from exc
            data = recovered

        if isinstance(data, dict):
            data = data.get("findings", [data])
        return [Finding(**item) for item in data]

    @staticmethod
    def _recover_truncated_json(text: str) -> object | None:
        """Best-effort recovery of a truncated JSON value.

        Strategy:
        - Walk char-by-char tracking object/array depth, ignoring brackets
          and commas inside strings (with backslash escape handling).
        - Record each position where the *outermost* container closes
          cleanly (full parse) AND each top-level comma within an array
          (potential truncation cut point).
        - Try the cleanest cut first (full close), fall back to cutting at
          the last top-level comma and appending `]` to recover the prefix
          elements of a truncated array.

        Returns the parsed object or None if nothing salvageable.
        """
        if not text or text[:1] not in "[{":
            return None
        outer = text[0]
        in_str = False
        esc = False
        depth_obj = depth_arr = 0
        last_complete_end = None      # index AFTER the outer container closed
        top_level_commas: list[int] = []  # positions of commas at outer-array depth 1
        for i, ch in enumerate(text):
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == "{":
                depth_obj += 1
            elif ch == "}":
                depth_obj -= 1
            elif ch == "[":
                depth_arr += 1
            elif ch == "]":
                depth_arr -= 1
            elif ch == ",":
                # Top-level comma inside the outer array (not nested in an obj/sub-array).
                if outer == "[" and depth_arr == 1 and depth_obj == 0:
                    top_level_commas.append(i)
            if depth_obj == 0 and depth_arr == 0:
                last_complete_end = i + 1

        if last_complete_end is not None:
            try:
                return json.loads(text[:last_complete_end])
            except json.JSONDecodeError:
                pass

        # Truncated mid-element: cut at last top-level comma, close the array.
        if outer == "[" and top_level_commas:
            cut = top_level_commas[-1]
            candidate = text[:cut] + "]"
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                return None
        return None

    def _parse_updates(self, raw: str) -> list[dict]:
        """Parse a JSON response into a list of partial-update dicts.
        Used by the Analyst, which only returns id/analyst_conclusion/cvss_score."""
        cleaned = self._strip_code_fence(raw)
        data = json.loads(cleaned)
        if isinstance(data, dict):
            data = data.get("findings", [data])
        return list(data)
