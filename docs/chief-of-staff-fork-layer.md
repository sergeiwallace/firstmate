# The chief-of-staff layer in this fork

This repository is a fork of [kunchenguid/firstmate](https://github.com/kunchenguid/firstmate), Kun Chen's agent distro for running a crew of coding agents.
Everything upstream ships is here unchanged in purpose: the `AGENTS.md` supervisor contract, the built-in skills, the `bin/` toolbelt, the session backends and the test suite.
The fork adds one thing on top: a chief-of-staff authority layer that a separate harness uses to coordinate several interactive agent sessions on one machine.
This page says what that layer is, how it is consumed, and what it does not change.

## What the fork adds

The additions are scripts in `bin/`, their tests, two configuration files in a home, and the documentation for each.
None of them is invoked by the upstream supervisor; they are called by the consuming harness.

| Addition | Where it is documented |
| --- | --- |
| `fm-message-transport.sh` and `fm-message-transport-lib.sh`: validate the transport chain a home declares, answer the next allowed step after an attempt, compute durable deadlines, and refuse a dispatch that breaks the phrasing discipline | [scripts.md](scripts.md), [configuration.md](configuration.md#message-transports-configmessage-transportsjson) |
| `fm-dispatch-body.py`: the durable dispatch-body broker, one SQLite file per home, staging one hashed body per dispatch id before any transport | [configuration.md](configuration.md#dispatch-body-broker-dispatch-bodiessqlite3) |
| `fm-receive.sh` and `fm-forward-receive.sh`: the recipient claim gate and the owning chief's forwarded-dispatch entry point | [configuration.md](configuration.md#dispatch-body-broker-dispatch-bodiessqlite3) |
| `fm-vp-owner.py`: unattended provisioning of a machine's signer identity, owner-record signing and verification, and owner-route resolution | [configuration.md](configuration.md#vp-owner-authority-vp-owner-selfjson--chief-routesjson) |
| `config/message-transports.json`: the declared transport chain, with a native primary and any subset of the known fallbacks in any order, or none | [configuration.md](configuration.md#message-transports-configmessage-transportsjson) |
| `config/backlog-backend-required`: a home that must never fall back to a markdown backlog names its task adapter here | [configuration.md](configuration.md#required-backend-configbacklog-backend-required) |

Two properties hold across all of them.
The transport chain is read from configuration, so no fallback adapter is mandatory and an unknown adapter fails closed naming the field.
The dispatch body is staged once and hashed before anything is sent, so a dispatch id is idempotent and every route can be checked against the same hash.

## How the fork is consumed

Upstream's model is that you clone the repository, change into it and launch your harness there; the working directory is the distro and `AGENTS.md` takes over the session.
That still works in this fork, and nothing below removes it.

The consuming harness uses a different shape.
Its installer clones this repository as a sibling checkout at a pinned commit, seeds a per-machine home under the XDG state directory with the two configuration files above, and records which commit it deployed.
The coordinating session is then launched from the harness's own repository root, not from this checkout, with `FM_HOME` pointing at that per-machine home.
The scripts in `bin/` are called by absolute path from there.

Two consequences follow, and both are deliberate.
The `AGENTS.md` in this checkout is not loaded by that session, because the session's working directory is elsewhere; the session's behaviour comes from the harness's own skill and hooks.
And the upstream crew features (crewmates, secondmates, the watcher, the session backends) are not what that session runs; it uses the fork as a transport and broker library plus a state convention, and dispatches through its harness's native session messaging.

## What does not change

- Upstream behaviour when launched the upstream way. The added scripts sit beside the toolbelt and are inert unless called.
- The upstream test and documentation gates. The additions carry their own tests and are registered in the documentation inventory like every other page.
- Provenance. Firstmate is Kun Chen's work; the chief-of-staff layer and the configurable transport chain are this fork's additions, and the commit history shows which is which.

## Status

The layer is in use for a single machine: a coordinating session can reconcile the sessions on its host and dispatch to one of them over native session messaging.
A dispatch to a session on another machine, or over a mail-style transport, is not available yet; the owner-route resolution and the forwarding entry point exist, but the remote owner record they would read is not implemented, and the fork reports such a dispatch as blocked rather than attempting it.
Contributing these additions back to upstream has not been proposed yet and is tracked separately by the maintainer of this fork.
