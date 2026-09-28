inherit l4t_bsp python3native

DEPENDS += "edk2-basetools-tegra-native openssl-native"

PYTHON_BASETOOLS = "${RECIPE_SYSROOT_NATIVE}/usr/bin/edk2-BaseTools/Source/Python"

# Each certificate can be given as a PEM file or as a PKCS#11 URI, which
# GenerateCapsule.py resolves through OpenSSL; that requires a provider for
# PKCS#11 URIs, such as pkcs11-provider configured through OPENSSL_CONF.
# For a URI, UEFI_CAPSULE_SIGNER_PRIVATE_CERT names the token object holding
# both the signer certificate and its private key, which stays on the token.
UEFI_CAPSULE_SIGNER_PRIVATE_CERT ?= "${PYTHON_BASETOOLS}/Pkcs7Sign/TestCert.pem"
UEFI_CAPSULE_OTHER_PUBLIC_CERT ?= "${PYTHON_BASETOOLS}/Pkcs7Sign/TestSub.pub.pem"
UEFI_CAPSULE_TRUSTED_PUBLIC_CERT ?= "${@d.getVar('TEGRA_UEFI_CAPSULE_TRUSTED_CERT') or '${PYTHON_BASETOOLS}/Pkcs7Sign/TestRoot.pub.pem'}"

# Override this function to have a secure signing server
# perform the capsule signing.
sign_uefi_capsules() {
    export PYTHONPATH="${PYTHONPATH}:${PYTHON_BASETOOLS}"
    if [ -e ${B}/${BUPFILENAME}.bl_only.bup-payload ]; then
        ${PYTHON} ${PYTHON_BASETOOLS}/Capsule/GenerateCapsule.py \
            -v --encode --monotonic-count 1 \
            --fw-version "${TEGRA_UEFI_FW_VERSION}" \
            --lsv "${TEGRA_UEFI_LOWEST_SUPPORTED_VERSION}" \
            --guid "${GUID}" \
            --signer-private-cert "${UEFI_CAPSULE_SIGNER_PRIVATE_CERT}" \
            --other-public-cert "${UEFI_CAPSULE_OTHER_PUBLIC_CERT}" \
            --trusted-public-cert "${UEFI_CAPSULE_TRUSTED_PUBLIC_CERT}" \
            -o ./tegra-bl.cap \
            ${B}/${BUPFILENAME}.bl_only.bup-payload
    fi
    if [ -e ${B}/${BUPFILENAME}.kernel_only.bup-payload ]; then
        ${PYTHON} ${PYTHON_BASETOOLS}/Capsule/GenerateCapsule.py \
            -v --encode --monotonic-count 1 \
            --fw-version "${TEGRA_UEFI_FW_VERSION}" \
            --lsv "${TEGRA_UEFI_LOWEST_SUPPORTED_VERSION}" \
            --guid "${GUID}" \
            --signer-private-cert "${UEFI_CAPSULE_SIGNER_PRIVATE_CERT}" \
            --other-public-cert "${UEFI_CAPSULE_OTHER_PUBLIC_CERT}" \
            --trusted-public-cert "${UEFI_CAPSULE_TRUSTED_PUBLIC_CERT}" \
            -o ./tegra-kernel.cap \
            ${B}/${BUPFILENAME}.kernel_only.bup-payload
    fi
}
