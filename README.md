# SBT Encrypt

Use algon2 + chacha20.

## Usage

```typescript
import { decrypt, encrypt } from 'sbt-encrpyt'

const encrypted = await encrypt('data', 'password')
const decrypted = await decrypt(encrypted, 'password')
```
