# Rua documentation

| Page | Read it when |
|---|---|
| [Deploy](deploy.md) | Standing up a deployment, upgrading, rotating `SECRET_KEY` |
| [Entra app registration](entra-registration.md) | Registering the app and scoping it to one mailbox |
| [DNS you have to own](dns-records.md) | Understanding what each posture reads, and the `rua=` tag |
| [Configuration](configuration.md) | Every environment variable and every `rua` command |
| [Retention and sizing](retention-and-sizing.md) | Deciding how long to keep raw reports |
| [Troubleshooting](troubleshooting.md) | Something shows nothing, fails, or says "stale" |
| [Security and privacy](security-and-privacy.md) | What is held, what is reachable, what is refused |

The readiness score is described in the [README](../README.md#the-readiness-score) and, in
full, in the docstring of `rua/readiness.py`.
