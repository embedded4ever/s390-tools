#!/usr/bin/env bash
set -euo pipefail

OUT_PREFIX=${1:-host}
SUBJ="/C=US/O=IBM/OU=Testing/CN=Qsafe HK"

if [ -f "${OUT_PREFIX}.hybrid.crt" ]; then
	echo "[*] Nothing to do... ${OUT_PREFIX}.hybrid.crt already exists"
	exit 0
fi

echo "[*] Generating ML-KEM-1024 keypair..."

if openssl list -kem-algorithms 2>/dev/null | grep -qi ML-KEM-1024; then
	echo "    -> OpenSSL OQS provider detected"

	if ! [ -f "${OUT_PREFIX}.mlkem.key" ]; then
		echo "[*] Generate ML-KEM key (target public key)"
		openssl genpkey -algorithm MLKEM1024 -out "${OUT_PREFIX}.mlkem.key"
		openssl pkey -in "${OUT_PREFIX}.mlkem.key" -pubout -out "${OUT_PREFIX}.mlkem.pub.pem"
	fi

	if ! [ -f "issuer.key" ] || ! [ -f "issuer.crt" ]; then
		echo "[*] Generate RSA issuer (signing key)"
		openssl req -x509 -newkey rsa:4096 -nodes \
			-keyout issuer.key \
			-out issuer.crt \
			-days 365 \
			-subj "${SUBJ}"
	fi

	if ! [ -f "${OUT_PREFIX}.mlkem.crt" ]; then
		echo "[*] Create certificate with injected ML-KEM public key"

		openssl req -new -newkey rsa:2048 -nodes \
			-keyout tmp.key \
			-subj "${SUBJ}" |
			openssl x509 -req \
				-CA issuer.crt \
				-CAkey issuer.key \
				-CAcreateserial \
				-days 365 \
				-set_serial 0x66A376DBB5502C74C6 \
				-force_pubkey "${OUT_PREFIX}.mlkem.pub.pem" \
				-extfile <(
					cat <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,keyAgreement
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:http://issuer.crl
EOF
				) \
				-out "${OUT_PREFIX}.mlkem.crt"
	fi
else
	echo "    -> No PQ support, using placeholder"
	exit 1
fi

echo "[*] Building hybrid PEM: ${OUT_PREFIX}.hybrid.pem"

{
	echo "-----BEGIN CERTIFICATE-----"

	sed '/-----/d' "${OUT_PREFIX}.pem.crt"

	echo "-----END CERTIFICATE-----"
	echo "-----BEGIN CERTIFICATE-----"
	sed '/-----/d' "${OUT_PREFIX}.mlkem.crt"

	echo "-----END CERTIFICATE-----"
} >"${OUT_PREFIX}.hybrid.crt"

echo "[✓] Done"
echo "    -> ${OUT_PREFIX}.hybrid.crt"
