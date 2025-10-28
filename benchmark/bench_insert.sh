#!/usr/bin/env bash
set -euo pipefail

# =======================
# Konfigurasi (override via env)
# =======================
CTR_NAME="${CTR_NAME:-mysql}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASS="${MYSQL_PASS:-}"
MYSQL_DB="${MYSQL_DB:-bench}"

MODE="${MODE:-both}"
TABLE_ENC="${TABLE_ENC:-sub_aead}"
TABLE_PLAIN="${TABLE_PLAIN:-sub_plain}"

COUNT="${COUNT:-10}"
UEID_PREFIX="${UEID_PREFIX:-UE}"
SUPI_PREFIX="${SUPI_PREFIX:-imsi-00101}"
AUTH_METHOD="${AUTH_METHOD:-EAP-AKA_PRIME}"
N5GC_AUTH="${N5GC_AUTH:-EAP-AKA_PRIME}"
AMF_VAL="${AMF_VAL:-8000}"
ALG_ID="${ALG_ID:-milenage}"
VGI="${VGI:-0}"
RGI="${RGI:-0}"

PLAINTEXT_BASE="${PLAINTEXT_BASE:-hello}"
OPC_BASE="${OPC_BASE:-opc}"
TOPC_BASE="${TOPC_BASE:-topc}"

AAD_PREFIX="${AAD_PREFIX:-aad}"
KID="${KID:-1}"

DEBUG="${DEBUG:-0}"
CLIENT_IMAGE="${CLIENT_IMAGE:-mysql:8.4}"
HOST_PORT="${HOST_PORT:-3306}"

# ====== Monitoring ======
# Sampling docker stats (detik). 0 = disable sampling.
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"
# CSV output
OUTDIR="${OUTDIR:-./monitor_out}"
TS_FILE="$(date +%Y%m%d_%H%M%S)"
CSV_FILE="${OUTDIR}/docker_stats_${CTR_NAME}_${TS_FILE}.csv"
ITER_CSV="${OUTDIR}/iter_times_${TS_FILE}.csv"

mkdir -p "${OUTDIR}"

# =======================
# Helper
# =======================
die(){ echo "ERROR: $*" >&2; exit 1; }
need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "command '$1' tidak ditemukan"; }

echo "Container     : $CTR_NAME"
echo "Database      : $MYSQL_DB"
echo "Mode          : $MODE"
echo "Table (enc)   : $TABLE_ENC"
echo "Table (plain) : $TABLE_PLAIN"
echo "COUNT         : $COUNT"
echo "KID           : $KID"
echo "Sampling (s)  : ${SAMPLE_INTERVAL} (0=off)"
echo "CSV (docker)  : ${CSV_FILE}"
echo "CSV (iter)    : ${ITER_CSV}"
echo "================================================"

case "$MODE" in
  enc|plain|both) ;;
  *) die "MODE harus salah satu: enc | plain | both" ;;
esac

need_cmd docker
docker ps --format '{{.Names}}' | grep -qx "$CTR_NAME" || die "container '$CTR_NAME' tidak berjalan"

# Pilih runner mysql client
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

# =======================
# Time helper (ns -> ms)
# =======================
now_ns(){ date +%s%N; }
ns_to_ms(){
  # prints integer ms
  awk -v ns="$1" 'BEGIN{ printf "%.0f\n", ns/1000000 }'
}

# =======================
# Builder SQL (asli punyamu)
# =======================
build_sql_enc() {
  local UEID="$1" SUPI="$2" P_VAL="$3" OPC_VAL="$4" TOPC_VAL="$5" AAD_VAL="$6" SQN="$7"
  cat <<SQL
INSERT INTO \`${TABLE_ENC}\` (
  ueid, authenticationMethod, encPermanentKey, protectionParameterId, sequenceNumber,
  authenticationManagementField, algorithmId, encOpcKey, encTopcKey,
  vectorGenerationInHss, n5gcAuthMethod, rgAuthenticationInd, supi
) VALUES (
  '${UEID}',
  '${AUTH_METHOD}',
  HEX(AEAD_ENCRYPT_DEFAULT(_binary'${P_VAL}', _binary'${AAD_VAL}', ${KID})),
  'kid-${KID}',
  JSON_OBJECT('sqn','${SQN}'),
  '${AMF_VAL}',
  '${ALG_ID}',
  HEX(AEAD_ENCRYPT_DEFAULT(_binary'${OPC_VAL}', _binary'${AAD_VAL}', ${KID})),
  HEX(AEAD_ENCRYPT_DEFAULT(_binary'${TOPC_VAL}', _binary'${AAD_VAL}', ${KID})),
  ${VGI},
  '${N5GC_AUTH}',
  ${RGI},
  HEX(AEAD_ENCRYPT_DEFAULT(_binary'${SUPI}', _binary'${AAD_VAL}', ${KID}))
)
ON DUPLICATE KEY UPDATE
  authenticationMethod=VALUES(authenticationMethod),
  encPermanentKey=VALUES(encPermanentKey),
  protectionParameterId=VALUES(protectionParameterId),
  sequenceNumber=VALUES(sequenceNumber),
  authenticationManagementField=VALUES(authenticationManagementField),
  algorithmId=VALUES(algorithmId),
  encOpcKey=VALUES(encOpcKey),
  encTopcKey=VALUES(encTopcKey),
  vectorGenerationInHss=VALUES(vectorGenerationInHss),
  n5gcAuthMethod=VALUES(n5gcAuthMethod),
  rgAuthenticationInd=VALUES(rgAuthenticationInd),
  supi=VALUES(supi)
;
SELECT '${UEID}' AS ueid,
       LENGTH(encPermanentKey) AS enc_pk_len_hex,
       JSON_EXTRACT(sequenceNumber, '$.sqn') AS sqn,
       CHAR_LENGTH(supi) AS enc_supi_hex_len
FROM \`${TABLE_ENC}\` WHERE ueid='${UEID}';
SQL
}


build_sql_plain() {
  local UEID="$1" SUPI="$2" P_VAL="$3" OPC_VAL="$4" TOPC_VAL="$5" SQN="$6"
  cat <<SQL
INSERT INTO \`${TABLE_PLAIN}\` (
  ueid, authenticationMethod, encPermanentKey, protectionParameterId, sequenceNumber,
  authenticationManagementField, algorithmId, encOpcKey, encTopcKey,
  vectorGenerationInHss, n5gcAuthMethod, rgAuthenticationInd, supi
) VALUES (
  '${UEID}',
  '${AUTH_METHOD}',
  '${P_VAL}',
  'plain',
  JSON_OBJECT('sqn','${SQN}'),
  '${AMF_VAL}',
  '${ALG_ID}',
  '${OPC_VAL}',
  '${TOPC_VAL}',
  ${VGI},
  '${N5GC_AUTH}',
  ${RGI},
  '${SUPI}'
)
ON DUPLICATE KEY UPDATE
  authenticationMethod=VALUES(authenticationMethod),
  encPermanentKey=VALUES(encPermanentKey),
  protectionParameterId=VALUES(protectionParameterId),
  sequenceNumber=VALUES(sequenceNumber),
  authenticationManagementField=VALUES(authenticationManagementField),
  algorithmId=VALUES(algorithmId),
  encOpcKey=VALUES(encOpcKey),
  encTopcKey=VALUES(encTopcKey),
  vectorGenerationInHss=VALUES(vectorGenerationInHss),
  n5gcAuthMethod=VALUES(n5gcAuthMethod),
  rgAuthenticationInd=VALUES(rgAuthenticationInd),
  supi=VALUES(supi)
;
SELECT '${UEID}' AS ueid,
       CHAR_LENGTH(encPermanentKey) AS pk_len,
       JSON_EXTRACT(sequenceNumber, '$.sqn') AS sqn,
       supi
FROM \`${TABLE_PLAIN}\` WHERE ueid='${UEID}';
SQL
}

# =======================
# Sampler docker stats (background)
# =======================
sampler_pid=""
start_sampler(){
  [[ "${SAMPLE_INTERVAL}" == "0" ]] && return 0
  {
    echo "timestamp,container,cpu_percent,mem_usage,mem_limit,mem_percent,net_io,block_io,pids"
    while :; do
      # --no-stream agar satu snapshot per loop
      docker stats --no-stream --format \
'{{.Container}},{{.CPUPerc}},{{.MemUsage}},{{.MemPerc}},{{.NetIO}},{{.BlockIO}},{{.PIDs}}' "$CTR_NAME" \
      | awk -v ts="$(date +%Y-%m-%dT%H:%M:%S)" -F',' '{
          # .MemUsage like "123.4MiB / 2GiB"
          split($3, a, " / ");
          print ts "," $1 "," $2 "," a[1] "," a[2] "," $4 "," $5 "," $6 "," $7
        }' >> "${CSV_FILE}" 2>/dev/null || true
      sleep "${SAMPLE_INTERVAL}"
    done
  } &
  sampler_pid=$!
}
stop_sampler(){
  [[ -n "${sampler_pid}" ]] && kill "${sampler_pid}" 2>/dev/null || true
}

# =======================
# Eksekusi + timing
# =======================
echo "iter,ueid,mode,elapsed_ms" > "${ITER_CSV}"

overall_start_ns="$(now_ns)"
start_sampler

for i in $(seq 1 "$COUNT"); do
  iter_start_ns="$(now_ns)"

  UEID=$(printf "%s%04d" "$UEID_PREFIX" "$i")
  SUPI="${SUPI_PREFIX}$(printf '%05d' "$i")"
  P_VAL="${PLAINTEXT_BASE}${i}"
  OPC_VAL="${OPC_BASE}${i}"
  TOPC_VAL="${TOPC_BASE}${i}"
  AAD_VAL="${AAD_PREFIX}${i}"
  SQN=$(printf "%012d" "$i")

  case "$MODE" in
    enc)
      SQL=$(build_sql_enc "$UEID" "$SUPI" "$P_VAL" "$OPC_VAL" "$TOPC_VAL" "$AAD_VAL" "$SQN")
      echo "--- INSERT ENC ${UEID} ---"
      [[ "$DEBUG" == "1" ]] && { echo "[SQL ENC]"; echo "$SQL"; }
      run_sql "$SQL"
      ;;
    plain)
      SQL=$(build_sql_plain "$UEID" "$SUPI" "$P_VAL" "$OPC_VAL" "$TOPC_VAL" "$SQN")
      echo "--- INSERT PLAIN ${UEID} ---"
      [[ "$DEBUG" == "1" ]] && { echo "[SQL PLAIN]"; echo "$SQL"; }
      run_sql "$SQL"
      ;;
    both)
      SQL=$(build_sql_enc "$UEID" "$SUPI" "$P_VAL" "$OPC_VAL" "$TOPC_VAL" "$AAD_VAL" "$SQN")
      echo "--- INSERT ENC ${UEID} ---"
      [[ "$DEBUG" == "1" ]] && { echo "[SQL ENC]"; echo "$SQL"; }
      run_sql "$SQL"

      SQL=$(build_sql_plain "$UEID" "$SUPI" "$P_VAL" "$OPC_VAL" "$TOPC_VAL" "$SQN")
      echo "--- INSERT PLAIN ${UEID} ---"
      [[ "$DEBUG" == "1" ]] && { echo "[SQL PLAIN]"; echo "$SQL"; }
      run_sql "$SQL"
      ;;
  esac

  iter_elapsed_ms=$(ns_to_ms $(( $(now_ns) - iter_start_ns )))
  echo "$i,$UEID,$MODE,$iter_elapsed_ms" >> "${ITER_CSV}"
  echo ">>> Iter-$i ${UEID}: ${iter_elapsed_ms} ms"
done

stop_sampler
overall_elapsed_ms=$(ns_to_ms $(( $(now_ns) - overall_start_ns )))

echo
echo "================== RINGKASAN =================="
echo "Total waktu eksekusi : ${overall_elapsed_ms} ms"

# ---------- Ringkasan iterasi: avg, p95, max (tanpa asort) ----------
if [[ -s "${ITER_CSV}" ]]; then
  # baris data = total baris - header
  n=$(($(wc -l < "${ITER_CSV}") - 1))
  if (( n > 0 )); then
    avg=$(awk -F',' 'NR>1{s+=$4}END{if(NR>1)printf "%.2f", s/(NR-1)}' "${ITER_CSV}")
    # indeks p95 (ceil(0.95*n)), minimal 1
    p95_idx=$(( (95*n + 99)/100 ))
    (( p95_idx < 1 )) && p95_idx=1

    # ambil kolom elapsed_ms, sort numerik, ambil baris ke-p95_idx
    p95=$(awk -F',' 'NR>1{print $4}' "${ITER_CSV}" | sort -n | sed -n "${p95_idx}p")

    # max
    maxv=$(awk -F',' 'NR>1{if($4>m)m=$4}END{print (m=="")?0:m}' "${ITER_CSV}")

    echo "Iter avg (ms)      : ${avg}"
    echo "Iter p95 (ms)      : ${p95}"
    echo "Iter max (ms)      : ${maxv}"

    # TPS sederhana (opsional)
    tps=$(awk -v cnt="$n" -v ms="$overall_elapsed_ms" 'BEGIN{ if(ms>0) printf "%.2f", (cnt*1000.0)/ms; else print "0.00" }')
    echo "Throughput approx   : ${tps} ops/sec"
  else
    echo "Tidak ada data iterasi."
  fi
fi

# ---------- Ringkasan docker stats (kalau ada sampel) ----------
if [[ -s "${CSV_FILE}" ]]; then
  echo
  echo "Ringkasan docker stats (${CTR_NAME}):"
  awk -F',' 'NR>1{
    # kolom: ts,container,cpu%,mem_usage,mem_limit,mem%,net_io,block_io,pids
    gsub(/%/,"",$3); cpu=$3+0;
    gsub(/%/,"",$6); memp=$6+0;

    # konversi mem_usage -> MiB (support KiB/MiB/GiB/B)
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
  }' "${CSV_FILE}"
fi

echo
echo "Artefak:"
echo "- Iteration times : ${ITER_CSV}"
echo "- Docker stats    : ${CSV_FILE}"
echo "================================================"

