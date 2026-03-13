## apictl mi secret init

Initialize secret encryption

### Synopsis

Initialize the keystore or symmetric encryption key required for secret encryption

```
apictl mi secret init [symmetric] [flags]
```

### Examples

```
To initialize keystore information
  apictl mi secret init
To initialize a symmetric encryption key
  apictl mi secret init symmetric
```

### Options

```
  -h, --help   help for init
```

### Options inherited from parent commands

```
  -k, --insecure   Allow connections to SSL endpoints without certs
      --verbose    Enable verbose mode
```

### SEE ALSO

* [apictl mi secret](apictl_mi_secret.md)	 - Manage sensitive information
