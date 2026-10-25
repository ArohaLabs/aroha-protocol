# Third-party licences

Licences for material redistributed inside Aroha's own artifacts, kept here
because a binary that embeds someone else's work has to carry their terms
with it — a link is not redistribution-safe, and the runtime is meant to
work with no network at all.

The entries below ship in the Aroha runtime, which is now developed in
[`ArohaLabs/aroha-runtime`](https://github.com/ArohaLabs/aroha-runtime). No package in this repository embeds them.

| Material | Where it ships | Licence |
| --- | --- | --- |
| **Public Sans** (variable, latin subset) | Base64 woff2 in `apps/aroha-runtime/src/ui/font.ts`, compiled into every `aroha` binary | OFL-1.1 — [`Public-Sans-LICENSE.md`](Public-Sans-LICENSE.md) |
| **React** and **React DOM** | Compiled into the `/app` bundle (`apps/aroha-runtime/src/ui/app-bundle.ts`) and so into every `aroha` binary | MIT — [`React-LICENSE.txt`](React-LICENSE.txt) (identical for both packages) |
| **Tabler Icons** (`@tabler/icons-react`) | Icon SVG/CSS compiled into the same bundle | MIT — [`Tabler-Icons-LICENSE.txt`](Tabler-Icons-LICENSE.txt) |

Public Sans is a US Government General Services Administration modification
of Libre Franklin; the file below carries both the GSA terms and the
underlying Libre Franklin OFL grant.
