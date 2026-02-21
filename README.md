# mRemoteNG Password Decrypt (Bash)

Decrypt mRemoteNG configuration files (old and new formats).

Bash + C reimplementation of the original Python script:
https://github.com/gquere/mRemoteNG_password_decrypt

## Usage
```bash
mremoteng_decrypt.sh [-h] [-p PASSWORD] [--csv] [--debug] config_file
```
**Mandatory arguments**:
```
config_file              mRemoteNG XML configuration file
```

**Optional arguments**:
```
-p PASSWORD, --password PASSWORD   Master password (default: mR3m)
--csv                              Output CSV format
--debug                            Debug output
-h, --help                         Show help
```

Example
```bash
./mremoteng_decrypt.sh ./mRemoteNG-1.70/confCons.xml
```

With custom password:
```bash
./mremoteng_decrypt.sh -p MySecretPassword ./confCons.xml
```
