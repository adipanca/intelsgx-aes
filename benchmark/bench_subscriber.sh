#!/usr/bin/env bash
set -euo pipefail

# =======================
# Konfigurasi (override via env)
# =======================
CTR_NAME="${CTR_NAME:-mysql}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASS="${MYSQL_PASS:-}"
MYSQL_DB="${MYSQL_DB:-bench}"

# Mode penulisan: enc | plain | both
MODE="${MODE:-both}"

# Tabel target (bisa dioverride)
TABLE_ENC="${TABLE_ENC:-sub_aead}"
TABLE_PLAIN="${TABLE_PLAIN:-sub_plain}"

COUNT="${COUNT:-10}"                  # jumlah baris yang diinsert
UEID_PREFIX="${UEID_PREFIX:-UE}"      # UE0001..UE0010
SUPI_PREFIX="${SUPI_PREFIX:-imsi-00101}"  # total SUPI harus <= 20 char
AUTH_METHOD="${AUTH_METHOD:-EAP-AKA_PRIME}"
N5GC_AUTH="${N5GC_AUTH:-EAP-AKA_PRIME}"
AMF_VAL="${AMF_VAL:-8000}"
ALG_ID="${ALG_ID:-milenage}"
VGI="${VGI:-0}"                       # vectorGenerationInHss (0/1)
RGI="${RGI:-0}"                       # rgAuthenticationInd (0/1)

# Nilai-nilai data
PLAINTEXT_BASE="${PLAINTEXT_BASE:-hello}"  # utk encPermanentKey
OPC_BASE="${OPC_BASE:-opc}"                # utk encOpcKey
TOPC_BASE="${TOPC_BASE:-topc}"             # utk encTopcKey

# Parameter AEAD
AAD_PREFIX="${AAD_PREFIX:-aad}"
KID="${KID:-1}"

DEBUG="${DEBUG:-0}"
CLIENT_IMAGE="${CLIENT_IMAGE:-mysql:8.4}"
HOST_PORT="${HOST_PORT:-3306}"

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
echo "=============================================="

# Validasi MODE
case "$MODE" in
  enc|plain|both) ;;
  *) die "MODE harus salah satu: enc | plain | both" ;;
esac

need_cmd docker
docker ps --format '{{.Names}}' | grep -qx "$CTR_NAME" || die "container '$CTR_NAME' tidak berjalan"

# Tentukan runner (container mysql, sidecar, atau host)
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
# Builder SQL
# =======================
build_sql_enc() {
  # $1=ueid $2=supi $3=p_val $4=opc_val $5=topc_val $6=aad_val $7=sqn
  local UEID="$1" SUPI="$2" P_VAL="$3" OPC_VAL="$4" TOPC_VAL="$5" AAD_VAL="$6" SQN="$7"
  cat <<SQL
-- ENC: satu baris untuk ${UEID} -> ${TABLE_ENC}
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

-- verifikasi ringkas ENC
SELECT '${UEID}' AS ueid,
       LENGTH(encPermanentKey) AS enc_pk_len_hex,
       JSON_EXTRACT(sequenceNumber, '$.sqn') AS sqn,
       CHAR_LENGTH(supi) AS enc_supi_hex_len
FROM \`${TABLE_ENC}\` WHERE ueid='${UEID}';
SQL
}

build_sql_plain() {
  # $1=ueid $2=supi $3=p_val $4=opc_val $5=topc_val $6= sqn
  local UEID="$1" SUPI="$2" P_VAL="$3" OPC_VAL="$4" TOPC_VAL="$5" SQN="$6"
  cat <<SQL
-- PLAIN: satu baris untuk ${UEID} -> ${TABLE_PLAIN}
INSERT INTO \`${TABLE_PLAIN}\` (
  ueid, authenticationMethod, encPermanentKey, protectionParameterId, sequenceNumber,
  authenticationManagementField, algorithmId, encOpcKey, encTopcKey,
  vectorGenerationInHss, n5gcAuthMethod, rgAuthenticationInd, supi
) VALUES (
  '${UEID}',
  '${AUTH_METHOD}',
  '${P_VAL}',                 -- plaintext ke VARCHAR
  'plain',                    -- marker plain
  JSON_OBJECT('sqn','${SQN}'),
  '${AMF_VAL}',
  '${ALG_ID}',
  '${OPC_VAL}',               -- plaintext
  '${TOPC_VAL}',              -- plaintext
  ${VGI},
  '${N5GC_AUTH}',
  ${RGI},
  '${SUPI}'                   -- plaintext VARCHAR(20)
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

-- verifikasi ringkas PLAIN
SELECT '${UEID}' AS ueid,
       CHAR_LENGTH(encPermanentKey) AS pk_len,
       JSON_EXTRACT(sequenceNumber, '$.sqn') AS sqn,
       supi
FROM \`${TABLE_PLAIN}\` WHERE ueid='${UEID}';
SQL
}

# =======================
# Loop eksekusi
# =======================
for i in $(seq 1 "$COUNT"); do
  UEID=$(printf "%s%04d" "$UEID_PREFIX" "$i")
  SUPI="${SUPI_PREFIX}$(printf '%05d' "$i")"     # pastikan <= 20 char total
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
      # ENC terlebih dahulu, lalu PLAIN
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
done
