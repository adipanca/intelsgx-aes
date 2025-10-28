#!/usr/bin/env bash
set -euo pipefail

# =========[ Konfigurasi (bisa di-override via env) ]=========
CTR_NAME="${CTR_NAME:-mysql}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASS="${MYSQL_PASS:-}"             # atau gunakan MYSQL_PWD=...
MYSQL_DB="${MYSQL_DB:-bench}"

# MODE pilih: plain | dec
MODE="${MODE:-plain}"

# Tabel default berdasar MODE
if [[ "${MODE}" == "dec" ]]; then
  TABLE="${TABLE:-sub_aead}"
else
  TABLE="${TABLE:-sub_plain}"
fi

# Format penyimpanan ciphertext di DB (untuk MODE=dec)
# - hex    : kolom enc* & supi disimpan HEX
# - base64 : kolom enc* & supi disimpan Base64
ENC_FMT="${ENC_FMT:-hex}"

# Batas & filter
LIMIT_ROWS="${LIMIT_ROWS:-${COUNT:-}}"
UEID_PREFIX_FILTER="${UEID_PREFIX_FILTER:-}"

# AAD prefix (harus sama dengan saat encrypt)
AAD_PREFIX="${AAD_PREFIX:-aad}"

# Eksekusi
HOST_PORT="${HOST_PORT:-3306}"
DEBUG="${DEBUG:-0}"
CLIENT_IMAGE="${CLIENT_IMAGE:-mysql:8.4}"

# Output/monitoring
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"   # detik; 0=off
OUTDIR="${OUTDIR:-./monitor_out}"
TS_FILE="$(date +%Y%m%d_%H%M%S)"
CSV_DOCKER="${OUTDIR}/docker_stats_${CTR_NAME}_${TS_FILE}.csv"
CSV_SUMMARY="${OUTDIR}/query_times_${TS_FILE}.csv"
CSV_ITER="${OUTDIR}/iter_times_${TS_FILE}.csv"

# Kontrol tampilan
PRINT_RESULT="${PRINT_RESULT:-1}"         # 1 cetak hasil tiap baris, 0 tidak
SLEEP_BETWEEN_MS="${SLEEP_BETWEEN_MS:-0}" # tidur antar baris (ms), 0=tanpa jeda

mkdir -p "${OUTDIR}"

# =========[ Helpers ]=========
die(){ echo "ERROR: $*" >&2; exit 1; }
need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "command '$1' tidak ditemukan"; }
sql_quote(){ printf "%s" "$1" | sed "s/'/''/g"; }
now_ns(){ date +%s%N; }
ns_to_ms(){ awk -v ns="$1" 'BEGIN{ printf "%.0f\n", ns/1000000 }'; }
sleep_ms(){ perl -e "select(undef,undef,undef,${1}/1000)" 2>/dev/null || true; }

echo "Container : $CTR_NAME"
echo "Database  : $MYSQL_DB"
echo "Table     : $TABLE"
echo "Mode      : $MODE  (enc fmt: $ENC_FMT)"
[[ -n "${LIMIT_ROWS}" ]] && echo "Limit     : ${LIMIT_ROWS}"
[[ -n "${UEID_PREFIX_FILTER}" ]] && echo "UEID like : ${UEID_PREFIX_FILTER}%"
echo "Sampling  : ${SAMPLE_INTERVAL}s (0=off)"
echo "CSV summary: ${CSV_SUMMARY}"
echo "CSV per-row: ${CSV_ITER}"
echo "CSV docker : ${CSV_DOCKER}"
echo "=============================================="

need_cmd docker
docker ps --format '{{.Names}}' | grep -qx "$CTR_NAME" || die "container '$CTR_NAME' tidak berjalan"

# Tentukan runner mysql client
RUNNER=""
PASS_ARG=()
[[ -n "$MYSQL_PASS" ]] && PASS_ARG=(-p"$MYSQL_PASS")

if docker exec -i "$CTR_NAME" sh -c "command -v mysql >/dev/null 2>&1"; then
  RUNNER="docker-exec-mysql"
elif docker exec -i "$CTR_NAME" sh -c "command -v mariadb >/dev/null 2>&1"; then
  RUNNER="docker-exec-mariadb"
elif docker run --rm --network "container:${CTR_NAME}" "$CLIENT_IMAGE" sh -c "command -v mysql >/dev/null 2>&1"; then
  RUNNER="sidecar-mysql"
elif command -v mysql >/dev/null 2>&1; then
  RUNNER="host-mysql"
fi
[[ -z "$RUNNER" ]] && die "mysql client tidak ditemukan (di container/sidecar/host)."

run_sql () {
  local sql="$1"
  case "$RUNNER" in
    docker-exec-mysql)
      docker exec -i "$CTR_NAME" mysql -u"$MYSQL_USER" -D "$MYSQL_DB" -N -B --raw "${PASS_ARG[@]}" -e "$sql"
      ;;
    docker-exec-mariadb)
      docker exec -i "$CTR_NAME" mariadb -u"$MYSQL_USER" -D "$MYSQL_DB" -N -B --raw "${PASS_ARG[@]}" -e "$sql"
      ;;
    sidecar-mysql)
      docker run --rm --network "container:${CTR_NAME}" "$CLIENT_IMAGE" \
        mysql -u"$MYSQL_USER" -D "$MYSQL_DB" -N -B --raw "${PASS_ARG[@]}" -e "$sql"
      ;;
    host-mysql)
      mysql -h 127.0.0.1 -P "$HOST_PORT" -u"$MYSQL_USER" -D "$MYSQL_DB" -N -B --raw "${PASS_ARG[@]}" -e "$sql"
      ;;
  esac
}

# Uji koneksi
run_sql "SELECT 1;" >/dev/null || die "gagal konek ke MySQL (runner=$RUNNER)"
[[ "$DEBUG" == "1" ]] && set -x

# WHERE dasar
WHERE_CLAUSE="1"
if [[ -n "$UEID_PREFIX_FILTER" ]]; then
  WHERE_CLAUSE="ueid LIKE '$(sql_quote "${UEID_PREFIX_FILTER}")%'"
fi
LIMIT_CLAUSE=""
if [[ -n "$LIMIT_ROWS" ]]; then
  LIMIT_CLAUSE="LIMIT ${LIMIT_ROWS}"
fi

# Fungsi sumber ciphertext (MODE=dec)
case "$ENC_FMT" in
  hex)
    DEC_PK="UNHEX(encPermanentKey)"
    DEC_OPC="UNHEX(encOpcKey)"
    DEC_TOPC="UNHEX(encTopcKey)"
    DEC_SUPI="UNHEX(supi)"
    LEN_PK="CHAR_LENGTH(encPermanentKey)"
    LEN_OPC="CHAR_LENGTH(encOpcKey)"
    LEN_TOPC="CHAR_LENGTH(encTopcKey)"
    LEN_SUPI="CHAR_LENGTH(supi)"
    ;;
  base64)
    DEC_PK="FROM_BASE64(encPermanentKey)"
    DEC_OPC="FROM_BASE64(encOpcKey)"
    DEC_TOPC="FROM_BASE64(encTopcKey)"
    DEC_SUPI="FROM_BASE64(supi)"
    LEN_PK="CHAR_LENGTH(encPermanentKey)"
    LEN_OPC="CHAR_LENGTH(encOpcKey)"
    LEN_TOPC="CHAR_LENGTH(encTopcKey)"
    LEN_SUPI="CHAR_LENGTH(supi)"
    ;;
  *)
    die "ENC_FMT tidak dikenal: $ENC_FMT (hex|base64)"
    ;;
esac

# AAD index default dari UEID (empat digit kanan numerik)
AAD_EXPR_DEFAULT="(RIGHT(ueid,4)+0)"
AAD_EXPR="${AAD_EXPR:-$AAD_EXPR_DEFAULT}"

# =========[ Ambil daftar UEID yang akan di-loop ]=========
LIST_SQL=$(cat <<SQL
SELECT ueid
FROM \`${TABLE}\`
WHERE ${WHERE_CLAUSE}
ORDER BY CAST(RIGHT(ueid,4) AS UNSIGNED)
${LIMIT_CLAUSE};
SQL
)
mapfile -t UEIDS < <(run_sql "$LIST_SQL")

if (( ${#UEIDS[@]} == 0 )); then
  echo "Tidak ada baris yang cocok filter/limit."
  exit 0
fi

# =========[ Sampler docker stats ]=========
sampler_pid=""
docker_header="timestamp,container,cpu_percent,mem_usage,mem_limit,mem_percent,net_io,block_io,pids"

snapshot_stats_once() {
  if [[ ! -f "${CSV_DOCKER}" ]]; then
    echo "${docker_header}" > "${CSV_DOCKER}"
  fi
  docker stats --no-stream --format \
'{{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}' "$CTR_NAME" \
  | awk -v ts="$(date +%Y-%m-%dT%H:%M:%S)" -F',' '{
      split($3, a, " / ");
      print ts "," $1 "," $2 "," a[1] "," a[2] "," $4 "," $5 "," $6 "," $7
    }' >> "${CSV_DOCKER}" 2>/dev/null || true
}

start_sampler(){
  [[ "${SAMPLE_INTERVAL}" == "0" ]] && return 0
  [[ -f "${CSV_DOCKER}" ]] || echo "${docker_header}" > "${CSV_DOCKER}"
  {
    while :; do
      docker stats --no-stream --format \
'{{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}' "$CTR_NAME" \
      | awk -v ts="$(date +%Y-%m-%dT%H:%M:%S)" -F',' '{
          split($3, a, " / ");
          print ts "," $1 "," $2 "," a[1] "," a[2] "," $4 "," $5 "," $6 "," $7
        }' >> "${CSV_DOCKER}" 2>/dev/null || true
      sleep "${SAMPLE_INTERVAL}"
    done
  } &
  sampler_pid=$!
}

stop_sampler(){ [[ -n "${sampler_pid}" ]] && kill "${sampler_pid}" 2>/dev/null || true; }

# =========[ Eksekusi + timing per baris ]=========
echo "phase,elapsed_ms,rows" > "${CSV_SUMMARY}"
echo "iter,ueid,elapsed_ms,rows" > "${CSV_ITER}"

overall_start_ns="$(now_ns)"
snapshot_stats_once
start_sampler

# Header tampilan manusia
if [[ "${MODE}" == "plain" ]]; then
  echo -e "ueid\tsqn\tkid\tperm_plain\topc_plain\ttopc_plain\tsupi_plain"
else
  echo -e "ueid\tsqn\tkid\tenc_pk_len\tenc_opc_len\tenc_topc_len\tenc_supi_len\tperm_plain\topc_plain\ttopc_plain\tsupi_plain"
fi

total_rows=0
iter=0

for u in "${UEIDS[@]}"; do
  iter=$((iter+1))
  # SQL per baris
  if [[ "${MODE}" == "plain" ]]; then
    Q=$(cat <<SQL
SET @aad_prefix = _binary'${AAD_PREFIX}';
SELECT
  ueid,
  JSON_UNQUOTE(JSON_EXTRACT(sequenceNumber,'$.sqn')) AS sqn,
  CAST(SUBSTRING_INDEX(protectionParameterId,'-',-1) AS UNSIGNED) AS kid,
  encPermanentKey AS perm_plain,
  encOpcKey       AS opc_plain,
  encTopcKey      AS topc_plain,
  supi            AS supi_plain
FROM \`${TABLE}\`
WHERE ueid='$(sql_quote "$u")';
SQL
)
  else
    Q=$(cat <<SQL
SET @aad_prefix = _binary'${AAD_PREFIX}';
SELECT
  ueid,
  JSON_UNQUOTE(JSON_EXTRACT(sequenceNumber,'$.sqn')) AS sqn,
  CAST(SUBSTRING_INDEX(protectionParameterId,'-',-1) AS UNSIGNED) AS kid,
  ${LEN_PK}   AS enc_pk_len,
  ${LEN_OPC}  AS enc_opc_len,
  ${LEN_TOPC} AS enc_topc_len,
  ${LEN_SUPI} AS enc_supi_len,
  AEAD_DECRYPT_DEFAULT(${DEC_PK},
      CONCAT(@aad_prefix, (${AAD_EXPR})),
      CAST(SUBSTRING_INDEX(protectionParameterId,'-',-1) AS UNSIGNED)) AS perm_plain,
  AEAD_DECRYPT_DEFAULT(${DEC_OPC},
      CONCAT(@aad_prefix, (${AAD_EXPR})),
      CAST(SUBSTRING_INDEX(protectionParameterId,'-',-1) AS UNSIGNED)) AS opc_plain,
  AEAD_DECRYPT_DEFAULT(${DEC_TOPC},
      CONCAT(@aad_prefix, (${AAD_EXPR})),
      CAST(SUBSTRING_INDEX(protectionParameterId,'-',-1) AS UNSIGNED)) AS topc_plain,
  AEAD_DECRYPT_DEFAULT(${DEC_SUPI},
      CONCAT(@aad_prefix, (${AAD_EXPR})),
      CAST(SUBSTRING_INDEX(protectionParameterId,'-',-1) AS UNSIGNED)) AS supi_plain
FROM \`${TABLE}\`
WHERE ueid='$(sql_quote "$u")';
SQL
)
  fi

  t0="$(now_ns)"
  out="$(run_sql "$Q" || true)"
  elapsed_ms="$(ns_to_ms $(( $(now_ns) - t0 )))"

  # hitung rows (biasanya 0 atau 1)
  rc=$(printf "%s\n" "$out" | sed '/^$/d' | wc -l | awk '{print $1}')
  total_rows=$(( total_rows + rc ))

  echo "${iter},${u},${elapsed_ms},${rc}" >> "${CSV_ITER}"

  # tampilkan hasil
  if [[ "${PRINT_RESULT}" == "1" && -n "$out" ]]; then
    echo "$out"
  fi

  # jeda antar baris jika diminta
  if (( SLEEP_BETWEEN_MS > 0 )); then
    sleep_ms "${SLEEP_BETWEEN_MS}"
  fi
done

stop_sampler
snapshot_stats_once

overall_elapsed_ms="$(ns_to_ms $(( $(now_ns) - overall_start_ns )))"
echo "query_loop,${overall_elapsed_ms},${total_rows}" >> "${CSV_SUMMARY}"
echo
echo "================== RINGKASAN =================="
echo "Loop time (ms): ${overall_elapsed_ms}"
echo "Rows returned : ${total_rows}"

# Ringkasan docker stats (portable awk)
if [[ -s "${CSV_DOCKER}" ]]; then
  echo
  echo "Ringkasan docker stats (${CTR_NAME}):"
  awk -F',' 'NR>1{
    gsub(/%/,"",$3); cpu=$3+0;
    gsub(/%/,"",$6); memp=$6+0;

    mu=$4; split(mu, b, " ")
    val=b[1]; unit=b[2]
    if(unit ~ /KiB/i){ mib=val/1024 }
    else if(unit ~ /MiB/i){ mib=val }
    else if(unit ~ /GiB/i){ mib=val*1024 }
    else if(unit ~ /B/i){ mib=val/1048576 }
    else { mib=val }

    cpu_sum+=cpu; if(cpu>cpu_max)cpu_max=cpu
    memp_sum+=memp; if(memp>memp_max)memp_max=memp
    mem_sum+=mib; if(mib>mem_max)mem_max=mib
    n++
  } END{
    if(n>0){
      printf "CPU avg / max (%%)  : %.2f / %.2f\n", cpu_sum/n, cpu_max
      printf "Mem avg / max (MiB): %.2f / %.2f\n", mem_sum/n, mem_max
      printf "Mem%% avg/max (%%)   : %.2f / %.2f\n", memp_sum/n, memp_max
    } else {
      print "tidak ada sampel docker stats"
    }
  }' "${CSV_DOCKER}"
fi

echo
echo "Artefak:"
echo "- Summary times : ${CSV_SUMMARY}"
echo "- Per-row times : ${CSV_ITER}"
echo "- Docker stats  : ${CSV_DOCKER}"
echo "================================================"
