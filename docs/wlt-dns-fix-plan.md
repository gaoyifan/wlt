# WLT-DNS review follow-up plan

This plan covers the accepted findings from the WLT-DNS and downstream
configuration review. It deliberately favors local fixes and code deletion
over new frameworks.

## Goals

1. Correct the deployment default-mark and endpoint-routing invariants before the
   next deployment.
2. Keep UDP exchanges out of the stateful TCP/DoH connection pool.
3. Let the generic WLT NixOS module consume both runtime and Nix-store config
   fragment directories without downstream `ExecStart` reconstruction.
4. Fail closed on unsupported platforms and make bounded shutdown normal.
5. Remove small, concrete sources of ambiguity and duplicated state.
6. Pin the downstream configuration to the resulting WLT revision and verify
   without input overrides.

## Implementation status

- Completed: all WLT and downstream source changes listed below.
- Verified: WLT formatting, clippy, tests, flake check and package build;
  downstream formatting, targeted evaluations, integration module check and
  the complete router VM test.
- Release sequence: publish the immutable WLT revision, then update
  the downstream lock file and repeat evaluation without an input override.

## WLT changes

- Route each UDP request through a fresh Hickory exchange. Cache only TCP and
  DoH clients, preserving UDP-to-TCP fallback on the same endpoint and mark.
- Make non-Linux `wlt-dns` startup fail explicitly instead of serving with an
  unmarked policy.
- Treat a drain deadline as a bounded normal shutdown. Do not add a second task
  framework solely for hypothetical embedded consumers.
- Change both NixOS `configDirectory` options from `externalPath` to `path`, so
  runtime absolute strings and generated store paths are both accepted.
- Remove the duplicated pool-key representation and disambiguate the upstream
  `DnsServer` name where this remains a net simplification.
- Express route/group lookup invariants as invariants rather than recoverable
  disappearance errors.

## Downstream changes

- Keep the domestic default selector at zero: pack the configured IPv4 and
  IPv6 defaults into the overseas lane only.
- Ensure WLT-DNS public endpoints can never match the UID-based unmarked-output
  rule, and assert exact endpoint collisions with listeners/local backends.
- Replace positional `take`/`drop` provider ownership with four named endpoint
  lists, while retaining aggregate lists for RPDB rules.
- Pass the generated selector fragment directory through the generic WLT module
  and delete downstream `ExecStart` reconstruction.
- After WLT is committed and available as an immutable revision, update only
  the WLT flake lock node.

## Verification

- WLT: formatting, clippy, all-target Rust tests, and flake checks.
- Downstream: formatting, router VM test, relevant integration test, and
  representative router evaluations without `--override-input`.
- Deployment verification remains separate from this code-fix pass and starts
  only after the immutable WLT lock is available.

## Explicitly deferred

- A complete metrics matrix; add only metrics tied to concrete operational
  questions in a separate change.
- A `PolicySource`/`QueryExchange` injection framework created only to test the
  small dual-family ordering block.
- A server-runtime abstraction created only to reduce argument counts.
- A central nftables classifier abstraction: each later base chain must still
  consume the DNS front-door bypass contract.
- General non-`inet` nft-family support until a real deployment requires it.
