Public standalone Signet contracts used for migration qualification.

The BFA.5 positive fixture is `dev-bridge-busdt-bfa5.rgb`. Its genesis was recovered
from the burn proof in bridge E2E run 41698713237 and independently checked by the
on-chain SDK. It is test evidence, with no wallet keys or allocations.

- Native name Bridged USDT, ticker BUSDT, precision 6.
- Asset ID `rgb:fbkO6B_i-qyLXa6d-x3sAOaX-cx~vZB9-rxNSUle-9lXBTf8`.
- SHA-256 `a678ebf73f3a0523b307cd2fe8019a321ac938eaf547c2c65a7ac079948332ce`.

The legacy `dev-bridge-usdt.rgb` export was supplied on 2026-10-20. Its older
encoding is retained to verify rejection without wallet mutation.

- Native name: Bridged USDT; ticker: BUSDT; precision: 6.
- Asset ID: `rgb:OG9No4hZ-UrxoWmR-09ohtOk-ppxBN7h-g~KkQro-ncKc9A4`.
- SHA-256: `dfb49261fed5ad3dd237dd3a03913793b76fe70e486372bbeb0769b82158a895`.

The fixture contains no wallet keys, funding, or transfer state. Registration tests
do not operate the hosted bridge or claim funded Signet/mint/receive qualification.
