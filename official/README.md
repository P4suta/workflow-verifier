# Official-project compatibility suite

`official-projects-v1.json` pins two public projects for each supported CI
provider by commit and Git tree. The acquisition command creates sparse,
temporary Git worktrees, verifies those identities, rejects selected symlinks,
submodules, unsafe paths, and special files, and vendors only YAML into the
requested snapshot directory. It never runs upstream project code.

Acquisition and analysis are separate commands. After acquisition,
`official_compat.py` invokes only the workflow-verifier binary, supplies
network-disabled proxy settings, gives each repository a shared 60-second
budget for two analyses, and requires byte-identical reports. The fixed gate
checks provider detection, complete command execution, absence of internal
errors and `YAML-SYNTAX` diagnostics, commit/tree/snapshot identities, and the
checked-in `official-compat-v1` report digest.

The public report deliberately retains only project identities, counts, and
content digests. Security findings are not required to be zero and their
messages are not republished. A scheduled/manual workflow observes current
default branches separately; network drift cannot update or waive the pinned
pull-request gate.
