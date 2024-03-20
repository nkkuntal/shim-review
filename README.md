This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Check the docs directory in this repo for guidance on submission and
getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
VMware, https://www.vmware.com/

*******************************************************************************
### What product or service is this for?
*******************************************************************************
Photon OS, https://vmware.github.io/photon/

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
Photon OS is a Linux distribution being used by VMware customers in clouds (vSphere, AWS, Azure, GCE) 
and on bare-metal. We use shim->grub2->Linux chain for Secure Boot support. It needs to be signed in 
order to boot the Photon OS on any device using UEFI CA certificate for Secure Boot.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
Photon OS is a customized operating system and optimized for VMware-specific appliances. We provide
custom grub2, various Linux-based kernel flavors (RT, Secure) and other components. It is crucial
that we support UEFI Secure Boot for our customers and hence require our own shim.
[DISCUSS]

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: Monty Ijzerman
- Position: Staff Program Manager, Security Response
- Email address: mijzerman@vmware.com
- PGP: http://pgp.mit.edu/pks/lookup?op=vindex&search=0xC61F6A1D
[NEED INFO]

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Edward Hawkins
- Position: Senior Security Program Manager
- Email address: ehawkins@vmware.com
- PGP: http://pgp.mit.edu/pks/lookup?op=vindex&search=0x405F7C6D
[NEED INFO]

(Key should be signed by the other security contacts, pushed to a keyserver
like keyserver.ubuntu.com, and preferably have signatures that are reasonably
well known in the Linux community.)

*******************************************************************************
### Were these binaries created from the 15.8 shim release tar?
Please create your shim binaries starting with the 15.8 shim release tar file: https://github.com/rhboot/shim/releases/download/15.8/shim-15.8.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.8 and contains the appropriate gnu-efi source.

*******************************************************************************
Yes.

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************
https://github.com/vmware/photon/tree/5.0/SPECS/shim

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
0001-Enforce-SBAT-presence-in-every-image.patch

0001-Add-provision-to-disable-netboot-and-httpboot-in-shi.patch

[NEED INFO]

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
NX bit is not set.

[NEED INFO]

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************
We use upstream grub2 (2.06~rc1) shim_lock verifier.

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of GRUB2 affected by any of the CVEs in the July 2020, the March 2021, the June 7th 2022, the November 15th 2022, or 3rd of October 2023 GRUB2 CVE list, have fixes for all these CVEs been applied?

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************
The current builds include the `grub,3` fixes.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
The entry should look similar to: `grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`
*******************************************************************************
No, SBAT generation for grub is 3.

`grub,3,Free Software Foundation,grub,2.06,https//www.gnu.org/software/grub/`

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
No and Yes

[NEED INFO]

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
All the above patches are applied to our kernel (6.1.79) and we frequently update to 
latest upstream Linux kernel v6.1.x.

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
Photon OS actively backports features and bugfixes from upstream Linux kernel. Majority of them
are distinguished in,
- Preempt RT kernel patches
- VMware appliance-specific performance and/or security patches

Our full patch list is here: https://github.com/vmware/photon/tree/5.0/SPECS/linux

[DISCUSS]

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
Yes, build time generated ephemeral key.

[DISCUSS; Module signing with photon_sb2020? Custom module loading with Secondary Keyring?]

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We don't use this.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
SBAT generation upgrade will handle revocation of older binaries. shim SBAT is upgraded
from 1 to 4 and grub2 SBAT is upgraded from 1 to 3.

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
`Dockerfile` is included to reproduce our build.

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
[NEED INFO]

*******************************************************************************
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..
*******************************************************************************
[NEED INFO]

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
[NEED INFO]

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************
[NEED INFO]

*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
No.

[NEED INFO; Is photon_sb2020 EV SSL cert?]

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, UKI(s), shim + all child shim binaries )?
### Please provide exact SBAT entries for all shim binaries as well as all SBAT binaries that shim will directly boot.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
If you are using a downstream implementation of GRUB2 or systemd-boot (e.g.
from Fedora or Debian), please preserve the SBAT entry from those distributions
and only append your own. More information on how SBAT works can be found
[here](https://github.com/rhboot/shim/blob/main/SBAT.md).
*******************************************************************************
shim
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.photon,1,VMware Photon OS,shim,15.8-1.ph5,https://github.com/vmware/photon
```

grub2
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,3,Free Software Foundation,grub,2.06,https//www.gnu.org/software/grub/
grub.photon,1,VMware Photon OS,grub2,2.06-16.ph5,https://github.com/vmware/photon
```

systemd-boot
```
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
systemd,1,The systemd Developers,systemd,253,https://systemd.io/
systemd.photon,1,VMware Photon OS,systemd,v253-3.ph5,https://github.com/vmware/photon/issues
```
[DISCUSS; Include revocations.efi?; systemd.photon URL?]

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
*******************************************************************************
[NEED INFO]

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
[NEED INFO]

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
grub-2.06 from https://www.gnu.org/software/grub/

*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
SHIM launches signed grub2, then launches kernel. To handle future vulnerabilities, we include
`revocations.efi`. It would be read by shim to update SbatLevel and revoke Photon kernel and
grub.
[DISCUSS]

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
GRUB2 will launch only linux kernel, no other component.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
grub2 verifies signatures on booted kernels via shim, all the other expected components are both verified 
by secureboot signatures and SBAT verification.
[DISCUSS]

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB2)?
*******************************************************************************
No.

*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
Currenly we are using 6.1.79 but we frequently upgrade to latest upstream 6.1.x version. We also 
configure kernel to lockdown with LOCK_DOWN_KERNEL_FORCE_INTEGRITY when UEFI Secure Boot enabled to 
enforce SBAT and signature verification.

[PATCH 1/3] kernel: lockdown when UEFI secure boot enabled

[PATCH 2/3] Add .sbat section (in kernel image)

[PATCH 3/3] Verify SBAT on kexec

[DISCUSS]

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
[NEED INFO]
