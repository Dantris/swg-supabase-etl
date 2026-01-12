import os, re, json, hashlib, subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Iterable, Optional

import psycopg2
import psycopg2.extras

TAB_SPLIT = re.compile(r"\t")

TAB_INCLUDE_RE = os.environ.get("TAB_INCLUDE_RE", "")
TAB_EXCLUDE_RE = os.environ.get("TAB_EXCLUDE_RE", "")

IMPORT_STF = os.environ.get("IMPORT_STF", "0") == "1"
MAX_TAB_FILES = int(os.environ.get("MAX_TAB_FILES", "40"))
MAX_STF_FILES = int(os.environ.get("MAX_STF_FILES", "0"))

include_pat = re.compile(TAB_INCLUDE_RE, re.IGNORECASE) if TAB_INCLUDE_RE else None
exclude_pat = re.compile(TAB_EXCLUDE_RE, re.IGNORECASE) if TAB_EXCLUDE_RE else None


def sh(cmd: List[str], cwd: Optional[Path] = None) -> str:
    p = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
    )
    return p.stdout.strip()


def sha1_file(p: Path) -> str:
    h = hashlib.sha1()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_tab_rows(tab_path: Path) -> Tuple[List[str], List[str], Iterable[Dict[str, object]]]:
    # First pass: header + types
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

    # Re-open file so generator doesn't depend on closed handle
    def row_iter():
        with tab_path.open("r", encoding="utf-8-sig", errors="replace") as f2:
            skipped = 0
            for line in f2:
                line = line.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                skipped += 1
                if skipped <= 2:
                    continue
                parts = TAB_SPLIT.split(line)
                n = len(columns)
                if len(parts) < n:
                    parts += [""] * (n - len(parts))
                yield {columns[i]: cast(type_codes[i], parts[i]) for i in range(n)}

    return columns, type_codes, row_iter()


# STF parsing (kept, disabled by default)
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


def upsert_inventory(cur, source_repo, source_ref, kind, path, sha1, status):
    # status is either 'ok' (already imported) or 'pending' (needs import)
    cur.execute(
        """
        insert into public.new_ingest_files
          (source_repo, source_ref, kind, path, sha1, status, updated_at)
        values
          (%s,%s,%s,%s,%s,%s,now())
        on conflict (source_repo, source_ref, kind, path)
        do update set
          -- keep sha1 if we already have a real one and incoming is empty
          sha1 = case
                  when excluded.sha1 is not null and excluded.sha1 <> '' then excluded.sha1
                  else public.new_ingest_files.sha1
                end,
          status = case
                    when excluded.status = 'ok' then 'ok'
                    when public.new_ingest_files.status = 'ok' then 'ok'
                    else public.new_ingest_files.status
                  end,
          updated_at = now()
        """,
        (source_repo, source_ref, kind, path, sha1 or "", status),
    )


def mark_status(cur, source_repo, source_ref, kind, path, status, last_error=None, sha1: Optional[str] = None):
    cur.execute(
        """
        update public.new_ingest_files
        set
          status=%s,
          last_error=%s,
          sha1 = coalesce(%s, sha1),
          updated_at=now()
        where source_repo=%s and source_ref=%s and kind=%s and path=%s
        """,
        (status, last_error, sha1, source_repo, source_ref, kind, path),
    )


def next_pending(cur, source_repo, source_ref, kind, limit_n):
    cur.execute(
        """
        select path
        from public.new_ingest_files
        where source_repo=%s and source_ref=%s and kind=%s
          and status in ('pending','error')
        order by path
        limit %s
        """,
        (source_repo, source_ref, kind, limit_n),
    )
    return [r[0] for r in cur.fetchall()]


def datatable_existing(cur, source_repo, source_ref, path) -> Optional[Tuple[int, str]]:
    cur.execute(
        """
        select id, sha1
        from public.new_datatables
        where source_repo=%s and source_ref=%s and path=%s
        """,
        (source_repo, source_ref, path),
    )
    row = cur.fetchone()
    if not row:
        return None
    return int(row[0]), (row[1] or "")


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
    # Only called when we truly need to import/refresh this file.
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


def main():
    print("=== SWG IMPORTER (inventory/resume + skip already imported) ===", flush=True)

    db_url = os.environ["SUPABASE_DB_URL"]
    workdir = Path(os.environ.get("WORKDIR", "_work")).resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    dsrc_repo = os.environ.get("DSRC_REPO", "https://github.com/SWG-Source/dsrc.git")
    dsrc_ref = os.environ.get("DSRC_REF", "master")
    client_repo = os.environ.get("CLIENT_REPO", "https://github.com/SWG-Source/client-assets.git")
    client_ref = os.environ.get("CLIENT_REF", "master")

    print(f"Filters:", flush=True)
    print(f"  TAB_INCLUDE_RE={TAB_INCLUDE_RE!r}", flush=True)
    print(f"  TAB_EXCLUDE_RE={TAB_EXCLUDE_RE!r}", flush=True)
    print(f"Chunking:", flush=True)
    print(f"  MAX_TAB_FILES={MAX_TAB_FILES}", flush=True)
    print(f"  IMPORT_STF={IMPORT_STF} MAX_STF_FILES={MAX_STF_FILES}", flush=True)

    dsrc_dir = workdir / "dsrc"
    client_dir = workdir / "client-assets"

    if not dsrc_dir.exists():
        print(f"Cloning dsrc into {dsrc_dir} ...", flush=True)
        sh(["git", "clone", "--depth", "1", "--branch", dsrc_ref, dsrc_repo, str(dsrc_dir)])
        print("dsrc clone done.", flush=True)

    if IMPORT_STF and MAX_STF_FILES > 0 and not client_dir.exists():
        print(f"Cloning client-assets into {client_dir} ...", flush=True)
        sh(["git", "clone", "--depth", "1", "--branch", client_ref, client_repo, str(client_dir)])
        print("client-assets clone done.", flush=True)

    conn = psycopg2.connect(db_url)
    conn.autocommit = False

    try:
        with conn.cursor() as cur:
            # Load already-imported file list so we DON'T redo your 120k+ rows.
            cur.execute(
                """
                select path, sha1
                from public.new_datatables
                where source_repo=%s and source_ref=%s
                """,
                (dsrc_repo, dsrc_ref),
            )
            already = {path: (sha1 or "") for (path, sha1) in cur.fetchall()}
            print(f"Found {len(already)} existing datatables in DB for this repo/ref.", flush=True)

            # ===== Inventory pass (TAB) =====
            tab_paths = list(dsrc_dir.rglob("*.tab"))
            print(f"Filesystem scan: {len(tab_paths)} .tab files found under dsrc.", flush=True)

            considered = 0
            marked_ok = 0
            marked_pending = 0

            for p in tab_paths:
                rel = p.relative_to(dsrc_dir).as_posix()

                if include_pat and not include_pat.search(rel):
                    continue
                if exclude_pat and exclude_pat.search(rel):
                    continue

                considered += 1

                # If it already exists in new_datatables, mark OK immediately (skip re-import).
                if rel in already:
                    upsert_inventory(cur, dsrc_repo, dsrc_ref, "tab", rel, already[rel], "ok")
                    marked_ok += 1
                else:
                    upsert_inventory(cur, dsrc_repo, dsrc_ref, "tab", rel, "", "pending")
                    marked_pending += 1

            conn.commit()
            print(
                f"Inventory complete: considered={considered} ok={marked_ok} pending={marked_pending}",
                flush=True,
            )

            # ===== Work pass (TAB) =====
            todo = next_pending(cur, dsrc_repo, dsrc_ref, "tab", MAX_TAB_FILES)
            conn.commit()
            print(f"Pending TAB files this run: {len(todo)} (limit {MAX_TAB_FILES})", flush=True)

            processed = 0
            for rel in todo:
                p = dsrc_dir / rel
                if not p.exists():
                    mark_status(cur, dsrc_repo, dsrc_ref, "tab", rel, "error", "file missing on disk", None)
                    conn.commit()
                    print(f"[ERR] {rel} :: file missing on disk", flush=True)
                    continue

                try:
                    mark_status(cur, dsrc_repo, dsrc_ref, "tab", rel, "running", None, None)
                    conn.commit()

                    file_sha1 = sha1_file(p)

                    # If datatable exists and sha1 matches, skip re-import
                    existing = datatable_existing(cur, dsrc_repo, dsrc_ref, rel)
                    if existing and existing[1] == file_sha1:
                        mark_status(cur, dsrc_repo, dsrc_ref, "tab", rel, "ok", None, file_sha1)
                        conn.commit()
                        processed += 1
                        print(f"[SKIP] {rel} (already imported, sha1 match)", flush=True)
                        continue

                    columns, types, rows_iter = iter_tab_rows(p)

                    dt_id = upsert_datatable(cur, dsrc_repo, dsrc_ref, rel, file_sha1, 0, len(columns))
                    replace_columns(cur, dt_id, columns, types)
                    row_count = replace_rows(cur, dt_id, rows_iter, batch_size=1000)

                    cur.execute("update public.new_datatables set row_count=%s where id=%s", (row_count, dt_id))

                    mark_status(cur, dsrc_repo, dsrc_ref, "tab", rel, "ok", None, file_sha1)
                    conn.commit()

                    processed += 1
                    print(f"[OK] {rel} rows={row_count}", flush=True)

                except Exception as e:
                    conn.rollback()
                    with conn.cursor() as cur2:
                        mark_status(cur2, dsrc_repo, dsrc_ref, "tab", rel, "error", str(e), None)
                        conn.commit()
                    print(f"[ERR] {rel} :: {e}", flush=True)

            print(f"Processed TAB files this run: {processed}", flush=True)

            # ===== Optional STF import (later) =====
            if IMPORT_STF and MAX_STF_FILES > 0:
                print("STF import enabled (limited).", flush=True)
                stf_paths = list(client_dir.rglob("*.stf"))
                for sp in stf_paths:
                    rel = sp.relative_to(client_dir).as_posix()
                    # inventory stfs as pending; (you can add the same "already imported" logic later)
                    upsert_inventory(cur, client_repo, client_ref, "stf", rel, "", "pending")
                conn.commit()

                todo_stf = next_pending(cur, client_repo, client_ref, "stf", MAX_STF_FILES)
                conn.commit()
                print(f"Pending STF files this run: {len(todo_stf)} (limit {MAX_STF_FILES})", flush=True)

                for rel in todo_stf:
                    sp = client_dir / rel
                    try:
                        mark_status(cur, client_repo, client_ref, "stf", rel, "running", None, None)
                        conn.commit()

                        try:
                            entries = parse_stf(sp)
                        except Exception as e:
                            mark_status(cur, client_repo, client_ref, "stf", rel, "error", f"parse failed: {e}", None)
                            conn.commit()
                            print(f"[WARN] STF parse failed {rel}: {e}", flush=True)
                            continue

                        # You can store STF entries later (not needed for quests/items/mobs core)
                        mark_status(cur, client_repo, client_ref, "stf", rel, "ok", None, None)
                        conn.commit()
                        print(f"[OK] STF {rel} entries={len(entries)}", flush=True)

                    except Exception as e:
                        conn.rollback()
                        with conn.cursor() as cur2:
                            mark_status(cur2, client_repo, client_ref, "stf", rel, "error", str(e), None)
                            conn.commit()
                        print(f"[ERR] STF {rel} :: {e}", flush=True)

    finally:
        conn.close()


if __name__ == "__main__":
    main()
