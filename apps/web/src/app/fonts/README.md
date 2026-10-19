# Self-hosted fonts

These files replace `next/font/google` so `npm run build` never contacts Google
Fonts. Google Fonts sometimes answers with font URLs that have no file
extension, and the Next.js webpack font loader then fails the build
(vercel/next.js#99114). `src/app/layout.tsx` loads these files with
`next/font/local`, using the same weights, style, display, latin
`unicode-range` and CSS variable names as before.

| Family | Weights (normal style, latin subset) | Source | License |
|---|---|---|---|
| Inter Tight | 400, 500, 600, 700, 800 | npm `@fontsource/inter-tight@5.3.0` (font version v9, built by Fontsource from https://github.com/google/fonts; upstream https://github.com/rsms/inter-tight) | SIL OFL 1.1, `inter-tight/OFL.txt` |
| JetBrains Mono | 400, 500, 600, 700 | npm `@fontsource/jetbrains-mono@5.3.0` (font version v24, built by Fontsource from https://github.com/google/fonts; upstream https://github.com/JetBrains/JetBrainsMono) | SIL OFL 1.1, `jetbrains-mono/OFL.txt` |

Package integrity (npm registry `dist.integrity`):

- `@fontsource/inter-tight@5.3.0`: `sha512-uRwIrjKSUcCKIFeO2qm3yECA9phwge6Y1qQZvUmwqFgiIVWUELwwuq7pFlmlpPtO33ZtFQVOXQGNuvna1JPs6A==`
- `@fontsource/jetbrains-mono@5.3.0`: `sha512-fqDfB5I9f1p1TV486aUgB9t8zP84P0O1FtQR5Ol9vjwPy+S+EIGlVYm1cvj2W5shcZMTg2nZFdVMoH5wFu8a1A==`

The `.woff2` files are copied unmodified from each package's `files/`
directory (`<family>-latin-<weight>-normal.woff2`), and `OFL.txt` is that
package's `LICENSE` file. SHA-256 of each file:

```
6f32da94d4f26e98cb6ccd97034d306aa38945322c816f54a93c7d15dc0905b8  inter-tight/inter-tight-latin-400-normal.woff2
6c0019f88d5bc179f2c972998ed8c14e779254566da9081c5e29f364a0a0aeb6  inter-tight/inter-tight-latin-500-normal.woff2
db1a039d03ed646ef6a899f9ff92bf2f6fe382a49f1b0992066e85caf88b5be9  inter-tight/inter-tight-latin-600-normal.woff2
9c4f02f38678f2628292d66c4f7a1a6a06af7ffac4d279359b09074e7d0f1fe0  inter-tight/inter-tight-latin-700-normal.woff2
b4b4a0877ce8d65c2c194dec15236e4861d3b3c111b3aa3d54fc4efbe6171027  inter-tight/inter-tight-latin-800-normal.woff2
14425ba9c695763c1547f48a206b7aa60350a33ae23de09f0407877f3fcd89eb  jetbrains-mono/jetbrains-mono-latin-400-normal.woff2
cb182feeed4d798ff6961d3c79f7026279448fca0676438aaecb21f3fc39553a  jetbrains-mono/jetbrains-mono-latin-500-normal.woff2
400c6bfda18d5d14acad1c15d6dcb9f8e13c015e7286317e0b9a482539bef147  jetbrains-mono/jetbrains-mono-latin-600-normal.woff2
d0d4e818808f2a0ba39b2b09d1989366f63494e295f003c7ef436697378507e8  jetbrains-mono/jetbrains-mono-latin-700-normal.woff2
```

To update: `npm pack @fontsource/<family>@<version>`, copy the same files,
update this table and the hashes, and run `npm run build`.
