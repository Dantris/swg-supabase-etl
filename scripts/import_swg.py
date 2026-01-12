import os, re, json, hashlib, subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Iterable, Optional

import psycopg2
import psycopg2.extras

TAB_INCLUDE_RE = os.environ.get("TAB_INCLUDE_RE", "")
TAB_EXCLUDE_RE = os.environ.get("TAB_EXCLUDE_RE", "")
IMPORT_STF = os.environ.get("IMPORT_STF", "0") == "1"

include_pat = re.compile(TAB_INCLUDE_RE, re.IGNORECASE) if TAB_INCLUDE_RE else None
exclude_pat = re.compile(TAB_EXCLUDE_RE, re.IGNORECASE) if TAB_EXCLUDE_RE else None

TAB_SPLIT = re.compile(r"\t")


def sh(cmd: List[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True, capture_output=True, text=True)
    return p.stdout.strip()


def sha1_file(p: Path) -> str:
    h = hashlib.sha1()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_tab_rows(tab_path: Path) -> Tuple[List[str], List[str], Iterable[Dict[str, object]]]:
    # First pass: read header + types
    with tab_path.open("r", encoding="utf-8-sig", errors="replace") as f:
        def next_data_line():
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                if line.lstrip().startswith("#"):
                    continue
                return line
            return None

        header = next_data_line()
        if header is None:
            raise ValueError(f"Empty tab: {tab_path}")

        types = next_data_line()
        if types is None:
            raise ValueError(f"Missing type row: {tab_path}")

    columns = TAB_SPLIT.split(header)
    type_codes = TAB_SPLIT.split(types)

    if len(type_codes) < len(columns):
        type_codes += ["s"] * (len(columns) - len(type_codes))
    if len(columns) < len(type_codes):
        columns += [f"col_{i}" for i in range(len(columns), len(type_codes))]

    def cast(t: str, v: str) -> object:
        v = v.strip()
        if v == "":
            return None
        t = (t or "s").strip()
        try:
            if t in ("i", "e"):
                return int(v)
            if t == "f":
                return float(v)
            if t == "b":
                if v.lower() in ("true", "t", "yes", "y"):
                    return True
                if v.lower() in ("false", "f", "no", "n"):
                    return False
                return bool(int(v))
        except Exception:
            return v
        return v

    # Second pass: generator re-opens file and skips first 2 data lines
    def row_iter():
        with tab_path.open("r", encoding="utf-8-sig", errors="replace") as f2:
            skipped = 0
            for line in f2:
                line = line.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                skipped += 1
                if skipped <= 2:
                    continue  # skip header + type row

                parts = TAB_SPLIT.split(line)
                n = len(columns)
                if len(parts) < n:
                    parts += [""] * (n - len(parts))
                data = {columns[i]: cast(type_codes[i], parts[i]) for i in range(n)}
                yield data

    return columns, type_codes, row_iter()


def read_u32_le(buf: bytes, off: int):
    return int.from_bytes(buf[off:off + 4], "little", signed=False), off + 4


def read_u8(buf: bytes, off: int):
    return buf[off], off + 1


def read_u16_le(buf: bytes, off: int):
    return int.from_bytes(buf[off:off + 2], "little", signed=False), off + 2


def parse_stf(stf_path: Path) -> Dict[str, str]:
    buf = stf_path.read_bytes()
    off = 0

    magic, off = read_u32_le(buf, off)
    if magic not in (0x0000ABCD, 0xDEADBEEF):
        raise ValueError(f"Unexpected STF magic {hex(magic)} in {stf_path}")

    _flag, off = read_u8(buf, off)
    _next_index, off = read_u32_le(buf, off)
    count, off = read_u32_le(buf, off)

    values: Dict[int, str] = {}
    for _ in range(count):
        sid, off = read_u32_le(buf, off)
        _unknown, off = read_u32_le(buf, off)
        runes, off = read_u32_le(buf, off)
        u16s = []
        for _r in range(runes):
            ch, off = read_u16_le(buf, off)
            u16s.append(ch)
        raw = b"".join((c.to_bytes(2, "little") for c in u16s))
        values[sid] = raw.decode("utf-16le", errors="replace")

    names: Dict[int, str] = {}
    for _ in range(count):
        sid, off = read_u32_le(buf, off)
        runes, off = read_u32_le(buf, off)
        raw = buf[off:off + runes]
        off += runes
        names[sid] = raw.decode("utf-8", errors="replace")

    return {names[sid]: values[sid] for sid in names if sid in values}


def upsert_datatable(cur, source_repo, source_ref, path, sha1, row_count, col_count) -> int:
    cur.execute(
        """
        insert into public.new_datatables (source_repo, source_ref, path, sha1, row_count, column_count)
        values (%s,%s,%s,%s,%s,%s)
        on conflict (source_repo, source_ref, path)
        do update set sha1=excluded.sha1, row_count=excluded.row_count, column_count=excluded.column_count
        returning id
        """,
        (source_repo, source_ref, path, sha1, row_count, col_count),
    )
    return cur.fetchone()[0]


def replace_columns(cur, datatable_id: int, columns: List[str], types: List[str]) -> None:
    cur.execute("delete from public.new_datatable_columns where datatable_id=%s", (datatable_id,))
    psycopg2.extras.execute_values(
        cur,
        """
        insert into public.new_datatable_columns (datatable_id, ordinal, name, type_code)
        values %s
        """,
        [(datatable_id, i, columns[i], types[i]) for i in range(len(columns))],
        page_size=1000,
    )


def replace_rows(cur, datatable_id: int, rows: Iterable[Dict[str, object]], batch_size: int = 1000) -> int:
    cur.execute("delete from public.new_datatable_rows where datatable_id=%s", (datatable_id,))
    total, batch, idx = 0, [], 0
    for row in rows:
        batch.append((datatable_id, idx, json.dumps(row)))
        idx += 1
        if len(batch) >= batch_size:
            psycopg2.extras.execute_values(
                cur,
                "insert into public.new_datatable_rows (datatable_id, row_index, data) values %s",
                batch,
                template="(%s,%s,%s::jsonb)",
                page_size=batch_size,
            )
            total += len(batch)
            batch.clear()
    if batch:
        psycopg2.extras.execute_values(
            cur,
            "insert into public.new_datatable_rows (datatable_id, row_index, data) values %s",
            batch,
            template="(%s,%s,%s::jsonb)",
            page_size=len(batch),
        )
        total += len(batch)
    return total


def upsert_stf_file(cur, source_repo, source_ref, path, sha1, entry_count) -> int:
    cur.execute(
        """
        insert into public.new_stf_files (source_repo, source_ref, path, sha1, entry_count)
        values (%s,%s,%s,%s,%s)
        on conflict (source_repo, source_ref, path)
        do update set sha1=excluded.sha1, entry_count=excluded.entry_count
        returning id
        """,
        (source_repo, source_ref, path, sha1, entry_count),
    )
    return cur.fetchone()[0]


def replace_stf_entries(cur, stf_file_id: int, entries: Dict[str, str], batch_size: int = 2000) -> None:
    cur.execute("delete from public.new_stf_entries where stf_file_id=%s", (stf_file_id,))
    items = list(entries.items())
    for i in range(0, len(items), batch_size):
        chunk = items[i:i + batch_size]
        psycopg2.extras.execute_values(
            cur,
            "insert into public.new_stf_entries (stf_file_id, key, text) values %s",
            [(stf_file_id, k, v) for (k, v) in chunk],
            page_size=batch_size,
        )


def main():
    db_url = os.environ["SUPABASE_DB_URL"]
    workdir = Path(os.environ.get("WORKDIR", "_work")).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    dsrc_repo = os.environ.get("DSRC_REPO", "https://github.com/SWG-Source/dsrc.git")
    dsrc_ref = os.environ.get("DSRC_REF", "master")
    client_repo = os.environ.get("CLIENT_REPO", "https://github.com/SWG-Source/client-assets.git")
    client_ref = os.environ.get("CLIENT_REF", "master")

    dsrc_dir = workdir / "dsrc"
    client_dir = workdir / "client-assets"

    if not dsrc_dir.exists():
        sh(["git", "clone", "--depth", "1", "--branch", dsrc_ref, dsrc_repo, str(dsrc_dir)])
    if not client_dir.exists():
        sh(["git", "clone", "--depth", "1", "--branch", client_ref, client_repo, str(client_dir)])

    conn = psycopg2.connect(db_url)
    conn.autocommit = False

    with conn.cursor() as cur:
        cur.execute(
            "insert into public.new_import_runs(source,status,details) values (%s,%s,%s) returning id",
            ("github-actions", "running", json.dumps({"dsrc": dsrc_repo, "client": client_repo})),
        )
        run_id = cur.fetchone()[0]
        conn.commit()

    try:
        with conn.cursor() as cur:
            tab_files = list(dsrc_dir.rglob("*.tab"))

            kept = 0
            for p in tab_files:
                rel = p.relative_to(dsrc_dir).as_posix()

                if include_pat and not include_pat.search(rel):
                    continue
                if exclude_pat and exclude_pat.search(rel):
                    continue

                kept += 1
                print(f"[TAB] {rel}")

                columns, types, rows_iter = iter_tab_rows(p)

                dt_id = upsert_datatable(cur, dsrc_repo, dsrc_ref, rel, sha1_file(p), 0, len(columns))
                replace_columns(cur, dt_id, columns, types)
                row_count = replace_rows(cur, dt_id, rows_iter, batch_size=1000)
                cur.execute("update public.new_datatables set row_count=%s where id=%s", (row_count, dt_id))
                conn.commit()

            print(f"Kept {kept} / {len(tab_files)} tab files")

            if IMPORT_STF:
                stf_files = list(client_dir.rglob("*.stf"))
                for p in stf_files:
                    rel = p.relative_to(client_dir).as_posix()
                    try:
                        entries = parse_stf(p)
                    except Exception as e:
                        print(f"[WARN] skipping stf {rel}: {e}")
                        conn.commit()
                        continue

                    stf_id = upsert_stf_file(cur, client_repo, client_ref, rel, sha1_file(p), len(entries))
                    replace_stf_entries(cur, stf_id, entries)
                    conn.commit()

            cur.execute(
                "update public.new_import_runs set status='ok', details=details||%s::jsonb where id=%s",
                (json.dumps({"tabs_total": len(tab_files), "tabs_kept": kept, "stf": IMPORT_STF}), run_id),
            )
            conn.commit()

    except Exception as e:
        conn.rollback()
        with conn.cursor() as cur:
            cur.execute(
                "update public.new_import_runs set status='error', details=details||%s::jsonb where id=%s",
                (json.dumps({"error": str(e)}), run_id),
            )
            conn.commit()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    main()
