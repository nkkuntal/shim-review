Confirm the following are included in your repo, checking each box:

 - [x] completed README.md file with the necessary information
 - [x] shim.efi to be signed
 - [x] public portion of your certificate(s) embedded in shim (the file passed to VENDOR_CERT_FILE)
 - [x] binaries, for which hashes are added to vendor_db ( if you use vendor_db and have hashes allow-listed )
 - [x] any extra patches to shim via your own git tree or as files
 - [x] any extra patches to grub via your own git tree or as files
 - [x] build logs
 - [x] a Dockerfile to reproduce the build of the provided shim EFI binaries

*******************************************************************************
### What is the link to your tag in a repo cloned from rhboot/shim-review?
*******************************************************************************
https://github.com/nkkuntal/shim-review/tree/vmware-shim-x86_64-20240418

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
```
$ sha256sum shimx64.efi
3c644e2d1f4449fa761c540615f2b59178639ae2fa74c493de71b951afc80e11  shimx64.efi
```

*******************************************************************************
### What is the link to your previous shim review request (if any, otherwise N/A)?
*******************************************************************************
Previous version, based on shim 15.4, was approved here https://github.com/rhboot/shim-review/issues/164

*******************************************************************************
### If no security contacts have changed since verification, what is the link to your request, where they've been verified (if any, otherwise N/A)?
*******************************************************************************
`N/A` as security contacts are not verified recently.
