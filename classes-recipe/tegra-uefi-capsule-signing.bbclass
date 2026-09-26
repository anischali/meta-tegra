inherit l4t_bsp python3native

DEPENDS += "edk2-basetools-tegra-native openssl-native"

PYTHON_BASETOOLS = "${RECIPE_SYSROOT_NATIVE}/usr/bin/edk2-BaseTools/Source/Python"

# Each certificate can be given as a PEM file or as a PKCS#11 URI. A
# certificate held on a token is exported to UEFI_CAPSULE_CERTS_DIR before
# signing, which requires OpenSSL to have a provider for PKCS#11 URIs, such
# as pkcs11-provider configured through OPENSSL_CONF.
UEFI_CAPSULE_SIGNER_PRIVATE_CERT ?= "${PYTHON_BASETOOLS}/Pkcs7Sign/TestCert.pem"
UEFI_CAPSULE_OTHER_PUBLIC_CERT ?= "${PYTHON_BASETOOLS}/Pkcs7Sign/TestSub.pub.pem"
UEFI_CAPSULE_TRUSTED_PUBLIC_CERT ?= "${@d.getVar('TEGRA_UEFI_CAPSULE_TRUSTED_CERT') or '${PYTHON_BASETOOLS}/Pkcs7Sign/TestRoot.pub.pem'}"
# Signer private key, as a PEM file or as a URI that OpenSSL resolves,
# such as a PKCS#11 URI. If empty, UEFI_CAPSULE_SIGNER_PRIVATE_CERT must
# hold the private key along with the certificate.
UEFI_CAPSULE_SIGNER_PRIVATE_KEY ?= ""
UEFI_CAPSULE_CERTS_DIR = "${B}/uefi-capsule-certs"

# Keep any PKCS#11 PIN out of task signatures
UEFI_CAPSULE_SIGNER_PRIVATE_CERT[vardepvalue] = "${@oe4t.pkcs11.redact(d.getVar('UEFI_CAPSULE_SIGNER_PRIVATE_CERT'))}"
UEFI_CAPSULE_OTHER_PUBLIC_CERT[vardepvalue] = "${@oe4t.pkcs11.redact(d.getVar('UEFI_CAPSULE_OTHER_PUBLIC_CERT'))}"
UEFI_CAPSULE_TRUSTED_PUBLIC_CERT[vardepvalue] = "${@oe4t.pkcs11.redact(d.getVar('UEFI_CAPSULE_TRUSTED_PUBLIC_CERT'))}"
UEFI_CAPSULE_SIGNER_PRIVATE_KEY[vardepvalue] = "${@oe4t.pkcs11.redact(d.getVar('UEFI_CAPSULE_SIGNER_PRIVATE_KEY'))}"

python () {
    # The values below are placed in single quotes in sign_uefi_capsules
    for var in ['UEFI_CAPSULE_SIGNER_PRIVATE_CERT', 'UEFI_CAPSULE_OTHER_PUBLIC_CERT',
                'UEFI_CAPSULE_TRUSTED_PUBLIC_CERT', 'UEFI_CAPSULE_SIGNER_PRIVATE_KEY']:
        if oe4t.pkcs11.is_uri(d.getVar(var)):
            oe4t.pkcs11.check_uri(d, var)
}

# Prints the name of a PEM file holding the certificate given as $1,
# which is either a file name, returned as is, or a PKCS#11 URI, in which
# case the certificate is exported from the token to a file named $2.pem.
tegra_uefi_capsule_cert() {
    case "$1" in
        pkcs11:*)
            ;;
        *)
            echo "$1"
            return 0
            ;;
    esac
    mkdir -p ${UEFI_CAPSULE_CERTS_DIR}
    if ! openssl storeutl -certs "$1" | openssl x509 -out ${UEFI_CAPSULE_CERTS_DIR}/$2.pem; then
        bbfatal "Failed to export the $2 certificate from its PKCS#11 token"
    fi
    echo "${UEFI_CAPSULE_CERTS_DIR}/$2.pem"
}

# Override this function to have a secure signing server
# perform the capsule signing.
sign_uefi_capsules() {
    export PYTHONPATH="${PYTHONPATH}:${PYTHON_BASETOOLS}"
    signer_cert=$(tegra_uefi_capsule_cert '${UEFI_CAPSULE_SIGNER_PRIVATE_CERT}' signer)
    other_cert=$(tegra_uefi_capsule_cert '${UEFI_CAPSULE_OTHER_PUBLIC_CERT}' other)
    trusted_cert=$(tegra_uefi_capsule_cert '${UEFI_CAPSULE_TRUSTED_PUBLIC_CERT}' trusted)
    set -- --signer-private-cert "$signer_cert" \
        --other-public-cert "$other_cert" \
        --trusted-public-cert "$trusted_cert"
    if [ -n '${UEFI_CAPSULE_SIGNER_PRIVATE_KEY}' ]; then
        set -- "$@" --signer-private-key '${UEFI_CAPSULE_SIGNER_PRIVATE_KEY}'
    fi
    if [ -e ${B}/${BUPFILENAME}.bl_only.bup-payload ]; then
        ${PYTHON} ${PYTHON_BASETOOLS}/Capsule/GenerateCapsule.py \
            -v --encode --monotonic-count 1 \
            --fw-version "${TEGRA_UEFI_FW_VERSION}" \
            --lsv "${TEGRA_UEFI_LOWEST_SUPPORTED_VERSION}" \
            --guid "${GUID}" \
            "$@" \
            -o ./tegra-bl.cap \
            ${B}/${BUPFILENAME}.bl_only.bup-payload
    fi
    if [ -e ${B}/${BUPFILENAME}.kernel_only.bup-payload ]; then
        ${PYTHON} ${PYTHON_BASETOOLS}/Capsule/GenerateCapsule.py \
            -v --encode --monotonic-count 1 \
            --fw-version "${TEGRA_UEFI_FW_VERSION}" \
            --lsv "${TEGRA_UEFI_LOWEST_SUPPORTED_VERSION}" \
            --guid "${GUID}" \
            "$@" \
            -o ./tegra-kernel.cap \
            ${B}/${BUPFILENAME}.kernel_only.bup-payload
    fi
}
