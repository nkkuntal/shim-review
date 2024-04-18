# Photon 5.0 base image
FROM photon:5.0-20240331

# Install build tools and setup
RUN tdnf install --repo=photon -q -y wget-1.21.3-4.ph5 \
                                     binutils-2.39-7.ph5 \
                                     dos2unix-7.4.3-2.ph5 \
                                     gcc-12.2.0-2.ph5 \
                                     make-4.3-2.ph5 \
                                     glibc-devel-2.36-10.ph5 \
                                     rpm-build-4.18.2-2.ph5 \
                                     linux-api-headers-6.1.79-1.ph5 \
                                     diffutils-3.8-2.ph5 \
                                     util-linux-2.38-4.ph5

COPY shimx64.efi /
COPY rpmmacros /root/.rpmmacros

# Get Photon-SHIM source RPM
RUN wget https://packages.vmware.com/photon/5.0/photon_srpms_5.0_x86_64/shim-15.8-1.ph5.src.rpm
RUN rpm -ivh shim-15.8-1.ph5.src.rpm

# Build shim RPM
RUN rpmbuild -bb /usr/src/photon/SPECS/shim.spec

# Unpack RPM and get EFI binary
RUN rpm2cpio /usr/src/photon/RPMS/x86_64/shim-15.8-1.ph5.x86_64.rpm | cpio -diu

# Result
RUN ls -l /shimx64.efi /usr/share/shim/shimx64.efi

RUN sha256sum /shimx64.efi /usr/share/shim/shimx64.efi

RUN objcopy --only-section .sbat -O binary /usr/share/shim/shimx64.efi /dev/stdout

RUN hexdump -Cv /shimx64.efi > orig && \
    hexdump -Cv /usr/share/shim/shimx64.efi > build && \
    diff -u orig build
