# Photon 5.0 base image
FROM photon:5.0-20240331

# Install build tools
RUN tdnf install -q -y coreutils wget tar bzip2 build-essential util-linux dos2unix rpm-build

COPY shimx64.efi /
COPY rpmmacros /root/.rpmmacros

# Get Photon-SHIM source rpm
RUN wget https://packages.vmware.com/photon/5.0/photon_srpms_5.0_x86_64/shim-15.8-1.ph5.src.rpm
RUN rpm -ivh shim-15.8-1.ph5.src.rpm

# Build shim efi
RUN rpmbuild -bb /usr/src/photon/SPECS/shim.spec

# Unpack built RPM
RUN rpm2cpio /usr/src/photon/RPMS/x86_64/shim-15.8-1.ph5.x86_64.rpm | cpio -diu

RUN ls -l /shimx64.efi /usr/share/shim/shimx64.efi

# result
RUN sha256sum /shimx64.efi /usr/share/shim/shimx64.efi

RUN objdump -sj .sbat /usr/share/shim/shimx64.efi

RUN hexdump -Cv /shimx64.efi > orig && \
    hexdump -Cv /usr/share/shim/shimx64.efi > build && \
    diff -u orig build
