# Submission assets

Devpost's current project-overview guidance accepts JPG, PNG, or GIF gallery
thumbnails up to 5 MB and recommends a 3:2 ratio. The selected thumbnail is
checked against those constraints by:

```bash
./docs/assets/verify-media.sh
```

The script also pins the committed architecture export's dimensions, catching
an accidental replacement, truncation, wrong format, or oversized file before
submission. It verifies machine-readable properties; the visual checks below
remain mandatory.

`devpost-thumbnail-v2.png` is the selected 1536×1024 (3:2) project thumbnail
generated on August 13, 2026 with OpenAI's built-in image-generation tool. It
is 1.7 MB and contains no CockroachDB or AWS trademark logo, so it does not
imply a sponsor endorsement or completed cloud deployment.

Generation prompt, condensed:

> Premium vector-like editorial tech illustration for OSTK Fleet Recall: three
> agent nodes share a luminous distributed vector-memory lattice, while a
> contradictory memory becomes an explicit coral conflict instead of being
> overwritten. Midnight navy, cyan/teal, coral, exact title “OSTK FLEET
> RECALL,” 3:2, no extra text, trademarks, people, watermark, or fake UI.

`architecture.png` is the 1568×1018 gallery rendering of the deployment
topology in `docs/ARCHITECTURE.md`. It was generated with the same pinned
`@mermaid-js/mermaid-cli@11.16.0` parser used by CI, on a white background,
with scale 2. It contains service names but no sponsor logos, account
identifiers, deployment URLs, or credentials. Regenerate it after changing the
first Mermaid block; CI separately renders every Mermaid block and rejects
syntax errors.

## Visual acceptance checklist

- View the thumbnail at original resolution and at a 600-pixel-wide gallery
  preview; its title must read exactly “OSTK FLEET RECALL.” View the
  architecture at original resolution and in Devpost's expanded gallery view;
  its labels and arrow directions must remain legible.
- Keep important thumbnail content inside the existing margins so a gallery
  preview cannot clip the title or agent nodes.
- Do not add third-party logos, screenshots, account identifiers, URLs,
  credentials, or fabricated cloud status to either image. Plain service names
  in the architecture explain the intended integration.
- If the deployment topology changes, update the Mermaid source first, render
  a new PNG from that source, inspect it, and update the pinned dimensions in
  `verify-media.sh` in the same commit.

Sources: the [official hackathon rules](https://cockroachdb-ai.devpost.com/rules)
and Devpost's [submission-step guidance](https://help.devpost.com/article/126-know-your-submission-steps).
