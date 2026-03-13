## apictl secret init

Initialize secret encryption

### Synopsis

Initialize the key store or symmetric encryption key required for secret encryption

```
apictl secret init [symmetric] [flags]
```

### Examples

```
To initialize a Key Store information
  apictl secret init
To initialize a symmetric encryption key
  apictl secret init symmetric
NOTE: Asymmetric secret encryption supports only JKS Key Stores
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

* [apictl secret](apictl_secret.md)	 - Manage sensitive information

