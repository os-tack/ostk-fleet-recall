# Stage-4 successor target package

This directory freezes the first authority-free Stage-4 target package. The
package contains exactly 27 full registry entries and four capability roots:
the v2 activation policy, GitHub push connector, authenticated-actor remember
route, and declared-support relation proof. Every other entry is reachable
from those roots. A legacy relation proof is deliberately absent.

The dependency graph is non-cyclic. Generic entry case manifests are hashed
into the 25 new entries; the activation entry retains its successor-policy
manifests and the rebuilt relation entry retains its relation-policy manifests.
Package case manifests pin all 27 completed entry digests and are used only by
the package. Finally, `vector-suite.jsonl` pins the completed package. The
package never embeds the aggregate vector-suite digest.

These bytes prove offline semantic closure only. They are not an active-head,
signature, transaction, or repository authority witness. Fixture principals
and keys are test-only.
