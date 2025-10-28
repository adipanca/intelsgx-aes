#!/usr/bin/env bash
# Versi ringan: ambil CPU% dan Mem dari `docker stats` setiap interval.
# Berhenti otomatis setelah DURATION detik (atau pakai MAX_SAMPLES).
# Kolom DB/TABLE/FS diisi 0 agar header tetap kompatibel dengan analyzer.

set -u

CTR_NAME="${CTR_NAME:-mysql}"
OUTPUT_CSV="${OUTPUT_CSV:-monitor_report.csv}"

# Kontrol durasi
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"   # detik
DURATION="${DURATION:-60}"                # total jalan (detik); kosongkan untuk tanpa batas
MAX_SAMPLES="${MAX_SAMPLES:-}"            # alternatif: batasi jumlah sampel

MODE_TAG="${MODE_TAG:-probe}"             # label bebas ke CSV

# ==== helper: konversi satuan ke bytes ====
toB() {
  local x="$1"
  x="$(echo -n "$x" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr , .)"
  local n u
  n="$(echo -n "$x" | sed -E 's/[^0-9.]*([0-9.]+)[^0-9.]*$/\1/')"
  u="$(echo -n "$x" | grep -oE '(B|[KMGTP]i?B)$' | tr '[:upper:]' '[:lower:]')"
  if [[ -z "$u" ]]; then
    [[ "$x" =~ [Kk][Ii]?[Bb]$ ]] && u="kib"
    [[ "$x" =~ [Mm][Ii]?[Bb]$ ]] && u="mib"
    [[ "$x" =~ [Gg][Ii]?[Bb]$ ]] && u="gib"
    [[ "$x" =~ [Tt][Ii]?[Bb]$ ]] && u="tib"
    [[ "$x" =~ [Kk][Bb]$     ]] && u="kb"
    [[ "$x" =~ [Mm][Bb]$     ]] && u="mb"
    [[ "$x" =~ [Gg][Bb]$     ]] && u="gb"
    [[ "$x" =~ [Tt][Bb]$     ]] && u="tb"
    [[ "$x" =~ [Bb]$         ]] && u="b"
  fi
  case "$u" in
    b|"")  awk -v n="$n" 'BEGIN{printf "%.0f", n+0}';;
    kb)    awk -v n="$n" 'BEGIN{printf "%.0f", n*1000}';;
    kib)   awk -v n="$n" 'BEGIN{printf "%.0f", n*1024}';;
    mb)    awk -v n="$n" 'BEGIN{printf "%.0f", n*1000*1000}';;
    mib)   awk -v n="$n" 'BEGIN{printf "%.0f", n*1024*1024}';;
    gb)    awk -v n="$n" 'BEGIN{printf "%.0f", n*1000*1000*1000}';;
    gib)   awk -v n="$n" 'BEGIN{printf "%.0f", n*1024*1024*1024}';;
    tb)    awk -v n="$n" 'BEGIN{printf "%.0f", n*1000*1000*1000*1000}';;
    tib)   awk -v n="$n" 'BEGIN{printf "%.0f", n*1024*1024*1024*1024}';;
    *)     awk -v n="$n" 'BEGIN{printf "%.0f", n+0}';;
  esac
}

# ==== header CSV (kompatibel dengan versi lengkap) ====
# Validasi: OUTPUT_CSV bukan direktori dan bisa ditulis
if [[ -d "$OUTPUT_CSV" ]]; then
  echo "ERROR: OUTPUT_CSV='$OUTPUT_CSV' adalah direktori" >&2
  exit 1
fi
touch "$OUTPUT_CSV" 2>/dev/null || { echo "ERROR: tidak bisa menulis ke '$OUTPUT_CSV'" >&2; exit 1; }

if [[ ! -s "$OUTPUT_CSV" ]]; then
  echo "timestamp_iso,mode_tag,cpu_pct,mem_used_bytes,mem_limit_bytes,mem_pct,db_bytes,table_enc_bytes,table_plain_bytes,delta_db_bytes,delta_table_enc_bytes,delta_table_plain_bytes,container_fs_bytes,delta_container_fs_bytes" > "$OUTPUT_CSV"
fi

# ==== eksekusi dengan durasi ====
start_ts=$(date +%s)
samples=0

while :; do
  # stop kondisi durasi/sampel
  now=$(date +%s)
  if [[ -n "${DURATION}" ]] && (( now - start_ts >= DURATION )); then
    break
  fi
  if [[ -n "${MAX_SAMPLES}" ]] && (( samples >= MAX_SAMPLES )); then
    break
  fi

  raw="$(docker stats --no-stream --format "{{.CPUPerc}},{{.MemUsage}}" "$CTR_NAME" 2>/dev/null || echo "0.0%,0B/0B")"
  cpu="$(echo "$raw" | cut -d, -f1 | sed 's/%//')"
  mem="$(echo "$raw" | cut -d, -f2)"
  used="$(echo "$mem" | awk -F'/' '{gsub(/ /,"",$1); print $1}')"
  lim="$( echo "$mem" | awk -F'/' '{gsub(/ /,"",$2); print $2}')"

  used_b="$(toB "$used")"
  lim_b="$(toB "$lim")"

  if [[ -z "$lim_b" || "$lim_b" = "0" ]]; then
    mem_pct="0.000"
  else
    mem_pct=$(awk -v u="$used_b" -v l="$lim_b" 'BEGIN{printf "%.3f", (u*100.0)/l}')
  fi

  ts=$(date -Iseconds)
  # kolom DB/TABLE/FS = 0 (sengaja), supaya format konsisten dengan analyzer
  echo "${ts},${MODE_TAG},${cpu},${used_b},${lim_b},${mem_pct},0,0,0,0,0,0,0,0" >> "$OUTPUT_CSV"

  samples=$((samples+1))
  sleep "$SAMPLE_INTERVAL"
done

echo "OK: CSV -> $OUTPUT_CSV"
