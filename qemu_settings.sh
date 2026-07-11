echo \
    -enable-kvm \
    -m 2G \
    -cpu host \
    -smp cpus=4,sockets=1,cores=2,threads=2 \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_VARS_4M.fd \
    -drive format=raw,file=fat:rw:esp \
    -serial file:output.log
