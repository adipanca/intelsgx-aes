#!/usr/bin/env bash
set -u
CTR_NAME="${CTR_NAME:-mysql}"
OUTPUT_CSV="${OUTPUT_CSV:-monitor_report.csv}"

toB() {
  # Convert "417.7MiB", "15.62GiB", "512kB", "1024 B" → integer bytes
  local x="$1"
  # Normalisasi: buang spasi di tepi, ganti koma→titik
  x="$(echo -n "$x" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | tr , .)"

  # Ambil angka desimal dan unit yang valid di akhir string
  local n u
  n="$(echo -n "$x" | sed -E 's/[^0-9.]*([0-9.]+)[^0-9.]*$/\1/')"
  u="$(echo -n "$x" | grep -oE '(B|[KMGTP]i?B)$' | tr '[:upper:]' '[:lower:]')"

  # Kalau unit tidak ketemu, coba deteksi pola manual (docker kadang buang 'B')
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
    b|"")    awk -v n="$n" 'BEGIN{printf "%.0f", n+0}';;
    kb)      awk -v n="$n" 'BEGIN{printf "%.0f", n*1000}';;
    kib)     awk -v n="$n" 'BEGIN{printf "%.0f", n*1024}';;
    mb)      awk -v n="$n" 'BEGIN{printf "%.0f", n*1000*1000}';;
    mib)     awk -v n="$n" 'BEGIN{printf "%.0f", n*1024*1024}';;
    gb)      awk -v n="$n" 'BEGIN{printf "%.0f", n*1000*1000*1000}';;
    gib)     awk -v n="$n" 'BEGIN{printf "%.0f", n*1024*1024*1024}';;
    tb)      awk -v n="$n" 'BEGIN{printf "%.0f", n*1000*1000*1000*1000}';;
    tib)     awk -v n="$n" 'BEGIN{printf "%.0f", n*1024*1024*1024*1024}';;
    *)       awk -v n="$n" 'BEGIN{printf "%.0f", n+0}';;
  esac
}


# header
if [[ ! -s "$OUTPUT_CSV" ]]; then
  echo "timestamp_iso,mode_tag,cpu_pct,mem_used_bytes,mem_limit_bytes,mem_pct,db_bytes,table_enc_bytes,table_plain_bytes,delta_db_bytes,delta_table_enc_bytes,delta_table_plain_bytes,container_fs_bytes,delta_container_fs_bytes" > "$OUTPUT_CSV"
fi

for i in 1 2 3; do
  raw="$(docker stats --no-stream --format "{{.CPUPerc}},{{.MemUsage}}" "$CTR_NAME" 2>/dev/null || echo "0.0%,0B/0B")"
  cpu="$(echo "$raw" | cut -d, -f1 | sed 's/%//')"
  mem="$(echo "$raw" | cut -d, -f2)"
  used="$(echo "$mem" | awk -F'/' '{gsub(/ /,"",$1); print $1}')"
  lim="$( echo "$mem" | awk -F'/' '{gsub(/ /,"",$2); print $2}')"

  used_b="$(toB "$used")"
  lim_b="$(toB "$lim")"

  # hindari bagi 0
  if [[ -z "$lim_b" || "$lim_b" = "0" ]]; then
    mem_pct="0.000"
  else
    mem_pct=$(awk -v u="$used_b" -v l="$lim_b" 'BEGIN{printf "%.3f", (u*100.0)/l}')
  fi

  ts=$(date -Iseconds)
  echo "${ts},probe,${cpu},${used_b},${lim_b},${mem_pct},0,0,0,0,0,0,0,0" >> "$OUTPUT_CSV"
  echo "wrote sample $i"
  sleep 1
done
