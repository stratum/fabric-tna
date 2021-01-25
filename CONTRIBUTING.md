<!--
Copyright 2020-present Open Networking Foundation
SPDX-License-Identifier: LicenseRef-ONF-Member-Only-1.0
-->

# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution,
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.opennetworking.org/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Submitting Code

### General Information

This project follows [Google's Engineering Practices](https://google.github.io/eng-practices/review/developer/). Use this document as a guide when submitting code and opening PRs.

Some additional points:

- Submit your changes early and often. Add the `WIP` label or prefix your PR title with `[WIP]` to signal that the PR is still work in progress and it's not ready for final review. Input and corrections early in the process prevent huge changes later.

- We follow [ONOS's Code Style Guidelines](https://wiki.onosproject.org/display/ONOS/Code+Style+Guidelines) for Java, and we automatically format Python code after each merge. We don't have a style guide for P4 yet. Please take a look at the rest of the P4 code and use common sense when formatting your P4 changes.
 
- When merging a PR (only project mantainers can) please use [squash and rebase](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-request-merges#squash-and-merge-your-pull-request-commits). You do **not** have to do this by hand! GitHub will guide you through it, if possible.

- Consider opening a separate issue describing the technical details there and [link it to the PR](https://help.github.com/en/github/managing-your-work-on-github/closing-issues-using-keywords). This keeps code review and design discussions clean.

### Steps to Follow

1. Fork fabric-tna into your personal or organization account via the fork button on GitHub.

2. Make your code changes.

3. Pass all tests locally (see [README.md](./README.md). Create new tests for new code. Execute the following command in the root directory to run all currently enabled tests: `TODO: add command`

4. Create a [Pull Request](https://github.com/stratum/stratum/compare). Consider [allowing maintainers](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/allowing-changes-to-a-pull-request-branch-created-from-a-fork) to make changes if you want direct assistance from maintainers.

5. Wait for CI checks to pass. Repeat steps 2-4 as necessary. **Passing CI is mandatory.** If the CI check does not run automatically, reach out to the project maintainers to enable CI jobs for your PR.

6. Await review. Everyone can comment on code changes, but only Collaborators and above can give final review approval. **All changes must get at least one approval**.

## Community Guidelines

This project follows [Google's Open Source Community Guidelines](https://opensource.google.com/conduct/) and ONF's [Code of Conduct](https://github.com/stratum/stratum/blob/master/CODE_OF_CONDUCT.md).
