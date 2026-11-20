"""Base de conocimiento local: MITRE ATT&CK, actores (con pais segun MISP) y paises.

Se carga una sola vez desde archivos versionados en el repo (ver build.py), sin red.
"""
import json
import pathlib
from functools import cached_property

from app.knowledge.build import norm

DATA = pathlib.Path(__file__).parent / "data"
# Nombres cortos para los paises que la norma ISO nombra de forma larga.
SHORT_NAMES = {"KP": "Corea del Norte", "KR": "Corea del Sur", "RU": "Rusia", "IR": "Irán", "SY": "Siria",
               "VN": "Vietnam", "TW": "Taiwán", "BO": "Bolivia", "VE": "Venezuela", "GB": "Reino Unido",
               "US": "Estados Unidos", "CN": "China", "MD": "Moldavia", "TZ": "Tanzania", "LA": "Laos"}
# Nombres que usan los sitios de filtracion y no coinciden con ATT&CK.
ALIASES = {"lockbit3": "LockBit 3.0", "lockbit": "LockBit 3.0", "lockbit5": "LockBit 3.0", "alphv": "BlackCat",
           "blackcat": "BlackCat", "blackbasta": "Black Basta", "cl0p": "Cl0p", "clop": "Cl0p", "playnews": "Play",
           "ransomhub": "RansomHub", "akira": "Akira", "qilin": "Qilin", "agenda": "Qilin", "medusa": "Medusa",
           "medusalocker": "MedusaLocker", "lumma": "Lumma Stealer", "lummac2": "Lumma Stealer",
           "cobaltstrike": "Cobalt Strike", "qbot": "QakBot", "mozi": "Mirai"}
LATAM = {"AR", "BO", "BR", "CL", "CO", "CR", "CU", "DO", "EC", "GT", "HN", "MX", "NI", "PA", "PE", "PR", "PY",
         "SV", "UY", "VE"}


class KnowledgeBase:
    def __init__(self, data_dir: pathlib.Path = DATA):
        self.attack = json.loads((data_dir / "attack_index.json").read_text(encoding="utf-8"))
        raw = json.loads((data_dir / "countries.json").read_text(encoding="utf-8"))
        self.countries = {cc: {**v, "name": SHORT_NAMES.get(cc, v["name"])} for cc, v in raw.items()}
        self.groups: dict = self.attack["groups"]
        self.software: dict = self.attack["software"]
        self.techniques: dict = self.attack["techniques"]
        self.tactics: list = self.attack["tactics"]

    @cached_property
    def _software_index(self) -> dict[str, str]:
        idx: dict[str, str] = {}
        for sid, s in self.software.items():
            for n in [s["name"], *s["aliases"]]:
                idx.setdefault(norm(n), sid)
        return idx

    @cached_property
    def _group_index(self) -> dict[str, str]:
        idx: dict[str, str] = {}
        for gid, g in self.groups.items():
            for n in [g["name"], *g["aliases"]]:
                idx.setdefault(norm(n), gid)
        return idx

    def _lookup(self, name: str, index: dict[str, str]) -> str | None:
        key = norm(name)
        if not key:
            return None
        return index.get(key) or index.get(norm(ALIASES.get(key, "")))

    def match_software(self, name: str) -> str | None:
        return self._lookup(name, self._software_index)

    def match_group(self, name: str) -> str | None:
        return self._lookup(name, self._group_index)

    def country(self, cc: str | None) -> dict | None:
        return self.countries.get((cc or "").upper())

    def actor_summary(self, gid: str) -> dict:
        g = self.groups[gid]
        c = self.country(g["country"])
        return {"id": gid, "name": g["name"], "aliases": g["aliases"][:6], "country": g["country"],
                "country_name": c["name"] if c else None, "sponsor": g["sponsor"],
                "url": f"https://attack.mitre.org/groups/{gid}/"}

    def technique_parent(self, tid: str) -> str:
        return tid.split(".")[0]
