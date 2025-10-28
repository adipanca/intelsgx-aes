#!/usr/bin/env bash
set -euo pipefail

# =========[ Konfigurasi (bisa di-override via env) ]=========
CTR_NAME="${CTR_NAME:-mysql}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASS="${MYSQL_PASS:-}"
MYSQL_DB="${MYSQL_DB:-bench}"

# MODE pilih: plain | dec
MODE="${MODE:-plain}"

# Kalau TABLE tidak di-set, pilih default berdasar MODE
if [[ "${MODE}" == "dec" ]]; then
  TABLE="${TABLE:-sub_aead}"
else
  TABLE="${TABLE:-sub_plain}"
fi

# Format penyimpanan ciphertext di DB untuk kolom enc* dan supi pada tabel AEAD
# - hex    : kolom berisi HEX string => gunakan UNHEX() sebelum decrypt
# - base64 : kolom berisi Base64     => gunakan FROM_BASE64() sebelum decrypt
ENC_FMT="${ENC_FMT:-hex}"

# Batasi jumlah baris (COUNT juga didukung, alias ke LIMIT_ROWS)
LIMIT_ROWS="${LIMIT_ROWS:-${COUNT:-}}"

# Filter opsional berdasarkan prefix UEID (string LIKE 'prefix%')
UEID_PREFIX_FILTER="${UEID_PREFIX_FILTER:-}"

# AAD prefix (harus sama dengan saat proses ENCRYPT di data bench kamu)
AAD_PREFIX="${AAD_PREFIX:-aad}"

# Port host jika pakai client mysql dari host
HOST_PORT="${HOST_PORT:-3306}"

# Debug
DEBUG="${DEBUG:-0}"

# Client image jika pakai sidecar
CLIENT_IMAGE="${CLIENT_IMAGE:-mysql:8.4}"

# =========[ Helpers ]=========
die(){ echo "ERROR: $*" >&2; exit 1; }
need_cmd(){ command -v "$1" >/dev/null 2>&1 || die "command '$1' tidak ditemukan"; }

# Escape string untuk literal SQL (ganti ' -> '')
sql_quote(){ printf "%s" "$1" | sed "s/'/''/g"; }

echo "Container : $CTR_NAME"
echo "Database  : $MYSQL_DB"
echo "Table     : $TABLE"
echo "Mode      : $MODE  (enc fmt: $ENC_FMT)"
[[ -n "${LIMIT_ROWS}" ]] && echo "Limit     : ${LIMIT_ROWS}"
[[ -n "${UEID_PREFIX_FILTER}" ]] && echo "UEID like : ${UEID_PREFIX_FILTER}%"
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
      docker exec -i "$CTR_NAME" mysql -u"$MYSQL_USER" -D "$MYSQL_DB" -B --raw "${PASS_ARG[@]}" -e "$sql"
      ;;
    docker-exec-mariadb)
      docker exec -i "$CTR_NAME" mariadb -u"$MYSQL_USER" -D "$MYSQL_DB" -B --raw "${PASS_ARG[@]}" -e "$sql"
      ;;
    sidecar-mysql)
      docker run --rm --network "container:${CTR_NAME}" "$CLIENT_IMAGE" \
        mysql -u"$MYSQL_USER" -D "$MYSQL_DB" -B --raw "${PASS_ARG[@]}" -e "$sql"
      ;;
    host-mysql)
      mysql -h 127.0.0.1 -P "$HOST_PORT" -u"$MYSQL_USER" -D "$MYSQL_DB" -B --raw "${PASS_ARG[@]}" -e "$sql"
      ;;
  esac
}

# Uji koneksi
run_sql "SELECT 1;" >/dev/null || die "gagal konek ke MySQL (runner=$RUNNER)"
[[ "$DEBUG" == "1" ]] && set -x

# WHERE & LIMIT
WHERE_CLAUSE="1"
if [[ -n "$UEID_PREFIX_FILTER" ]]; then
  WHERE_CLAUSE="t.ueid LIKE '$(sql_quote "${UEID_PREFIX_FILTER}")%'"
fi
LIMIT_CLAUSE=""
if [[ -n "$LIMIT_ROWS" ]]; then
  LIMIT_CLAUSE="LIMIT ${LIMIT_ROWS}"
fi

# Fungsi pembungkus sumber ciphertext -> bytes sesuai ENC_FMT
case "$ENC_FMT" in
  hex)    DEC_SRC_PK="UNHEX(t.encPermanentKey)"
          DEC_SRC_OPC="UNHEX(t.encOpcKey)"
          DEC_SRC_TOPC="UNHEX(t.encTopcKey)"
          DEC_SRC_SUPI="UNHEX(t.supi)"
          LEN_PK="CHAR_LENGTH(t.encPermanentKey)"
          LEN_OPC="CHAR_LENGTH(t.encOpcKey)"
          LEN_TOPC="CHAR_LENGTH(t.encTopcKey)"
          LEN_SUPI="CHAR_LENGTH(t.supi)"
          ;;
  base64) DEC_SRC_PK="FROM_BASE64(t.encPermanentKey)"
          DEC_SRC_OPC="FROM_BASE64(t.encOpcKey)"
          DEC_SRC_TOPC="FROM_BASE64(t.encTopcKey)"
          DEC_SRC_SUPI="FROM_BASE64(t.supi)"
          LEN_PK="CHAR_LENGTH(t.encPermanentKey)"
          LEN_OPC="CHAR_LENGTH(t.encOpcKey)"
          LEN_TOPC="CHAR_LENGTH(t.encTopcKey)"
          LEN_SUPI="CHAR_LENGTH(t.supi)"
          ;;
  *) die "ENC_FMT tidak dikenal: $ENC_FMT (pakai 'hex' atau 'base64')"
     ;;
esac

# Ekspresi AAD index (default skema lama: ambil 4 digit kanan numeric dari UEID)
# Jika UEID kamu SHA1 hex dan kamu ingin ambil 4 hex terakhir -> desimal:
#   export AAD_EXPR="CAST(CONV(RIGHT(t.ueid,4),16,10) AS UNSIGNED)"
AAD_EXPR="${AAD_EXPR:-(RIGHT(t.ueid,4)+0)}"

# SQL per mode
if [[ "$MODE" == "plain" ]]; then
  # Asumsi tabel plain punya kolom 'permanentKey','opcKey','topcKey','supi' dalam teks biasa.
  SQL=$(cat <<SQL
SET @aad_prefix = _binary'${AAD_PREFIX}';
SELECT
  t.ueid AS ueid,
  JSON_UNQUOTE(JSON_EXTRACT(t.sequenceNumber,'$.sqn')) AS sqn,
  CAST(SUBSTRING_INDEX(t.protectionParameterId,'-',-1) AS UNSIGNED) AS kid,
  t.encPermanentKey AS perm_plain,
  t.encOpcKey       AS opc_plain,
  t.encTopcKey      AS topc_plain,
  t.supi         AS supi_plain
FROM \`${TABLE}\` t
WHERE ${WHERE_CLAUSE}
ORDER BY CAST(RIGHT(t.ueid,4) AS UNSIGNED)
${LIMIT_CLAUSE};
SQL
)
  echo -e "ueid\tsqn\tkid\tperm_plain\topc_plain\ttopc_plain\tsupi_plain"
  run_sql "$SQL" | awk 'NR>1 {print}'
elif [[ "$MODE" == "dec" ]]; then
  # Tabel AEAD: kolom encPermanentKey/encOpcKey/encTopcKey/supi berisi ciphertext.
  SQL=$(cat <<SQL
SET @aad_prefix = _binary'${AAD_PREFIX}';
SELECT
  t.ueid AS ueid,
  JSON_UNQUOTE(JSON_EXTRACT(t.sequenceNumber,'$.sqn')) AS sqn,
  CAST(SUBSTRING_INDEX(t.protectionParameterId,'-',-1) AS UNSIGNED) AS kid,
  ${LEN_PK}   AS enc_pk_len,
  ${LEN_OPC}  AS enc_opc_len,
  ${LEN_TOPC} AS enc_topc_len,
  ${LEN_SUPI} AS enc_supi_len,
  AEAD_DECRYPT_DEFAULT(${DEC_SRC_PK},
      CONCAT(@aad_prefix, (${AAD_EXPR})),
      CAST(SUBSTRING_INDEX(t.protectionParameterId,'-',-1) AS UNSIGNED)) AS perm_plain,
  AEAD_DECRYPT_DEFAULT(${DEC_SRC_OPC},
      CONCAT(@aad_prefix, (${AAD_EXPR})),
      CAST(SUBSTRING_INDEX(t.protectionParameterId,'-',-1) AS UNSIGNED)) AS opc_plain,
  AEAD_DECRYPT_DEFAULT(${DEC_SRC_TOPC},
      CONCAT(@aad_prefix, (${AAD_EXPR})),
      CAST(SUBSTRING_INDEX(t.protectionParameterId,'-',-1) AS UNSIGNED)) AS topc_plain,
  AEAD_DECRYPT_DEFAULT(${DEC_SRC_SUPI},
      CONCAT(@aad_prefix, (${AAD_EXPR})),
      CAST(SUBSTRING_INDEX(t.protectionParameterId,'-',-1) AS UNSIGNED)) AS supi_plain
FROM \`${TABLE}\` t
WHERE ${WHERE_CLAUSE}
ORDER BY CAST(RIGHT(t.ueid,4) AS UNSIGNED)
${LIMIT_CLAUSE};
SQL
)
  echo -e "ueid\tsqn\tkid\tenc_pk_len\tenc_opc_len\tenc_topc_len\tenc_supi_len\tperm_plain\topc_plain\ttopc_plain\tsupi_plain"
  run_sql "$SQL" | awk 'NR>1 {print}'
else
  die "MODE tidak dikenal: $MODE (pakai 'plain' atau 'dec')"
fi
