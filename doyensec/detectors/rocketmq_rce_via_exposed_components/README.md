# Apache RocketMQ Remote Code Execution

The plugin detects Apache RocketMQ and attempts to execute arbitrary code
by using the update configuration function to execute commands as the system
users that RocketMQ is running as.

## Details

Apache RocketMQ 5.x below 5.1.1 or 4.x below 4.9.7, are vulnerable to this vulnerability

## References

- https://nvd.nist.gov/vuln/detail/cve-2023-33246
- https://www.vicarius.io/vsociety/posts/rocketmq-rce-cve-2023-33246-33247

## Build jar file for this plugin

Using `gradlew`:

```shell
./gradlew jar
```

Tsunami identifiable jar file is located at `build/libs` directory.
