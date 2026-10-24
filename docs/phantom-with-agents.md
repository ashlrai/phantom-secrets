# Phantom with agents

How `phantom exec`, the Phantom proxy, LiteLLM, Temporal and post-quantum TLS fit together when an AI agent does the work. Every claim below names the merged test that backs it. If a sentence has no test next to it, it is a limit, not a promise.

## 1. Launch the agent with `phantom exec`

```sh
phantom exec -- <your agent command>
```

- The agent gets a `*_BASE_URL` for each service that has a key in the vault, pointing at the local proxy (`/openai/_phantom/...`). A service with no vaulted key is not rerouted. Test: `exec_routes_only_vaulted_services` (`crates/phantom-cli/tests/exec_output_streams_test.rs`).
- A protected key that no route delivers is named in a warning, even with `--quiet`, instead of being counted as proxied. Test: `exec_warns_about_protected_keys_without_a_route` (same file).
- The per-session proxy token is hidden in the printed `*_BASE_URL` lines. Test: `printed_base_url_hides_session_token` (`crates/phantom-cli/src/commands/exec.rs`).
- The agent's stdout is passed through byte for byte, and its exit code is propagated. Tests: `exec_keeps_child_stdout_byte_for_byte`, `exec_quiet_still_propagates_child_exit_code` (`exec_output_streams_test.rs`).
- `phantom exec` refuses custom routes from `.phantom.toml`; `phantom start` builds them. Test: `custom_litellm_route_is_refused_by_exec_but_built_for_start` (`exec.rs`). See [litellm.md](litellm.md) for why.

## 2. What the proxy does with the key

- The agent holds only a `phm_` session placeholder. The proxy swaps in the real key only in the configured header, and only on the way to the configured upstream. A placeholder copied into a request body stays a placeholder. Test: `litellm_gateway_real_key_stays_at_proxy` (`crates/phantom-proxy/tests/litellm_gateway_hermetic_test.rs`).
- Host-header overrides, absolute-form URIs, forwarding headers and upstream redirects do not send the call to a host no route names. Test: same file.
- If an upstream echoes the real key back in a JSON body, a response header or a streamed SSE error, the agent does not see it, for both `Authorization` and `x-api-key`. Tests: `*_echo_*_does_not_reach_child` (`crates/phantom-proxy/tests/proxy_echo_leak_test.rs`).
- Partial echoes are redacted too: the first half, the last half, or any run of 12 or more characters, including runs split across stream chunks. A short masked form such as `sk-...abcd` is left alone. Tests: `first_half_echo_is_redacted_everywhere`, `last_half_echo_is_redacted_everywhere`, `middle_12_char_echo_is_redacted_everywhere`, `masked_form_survives_untouched_everywhere` (`proxy_echo_leak_test.rs`); `run_split_across_one_byte_chunks_is_redacted_once`, `eleven_byte_run_and_masked_form_survive` (`partial_run_scrub_test.rs`).

## 3. LiteLLM in the middle

LiteLLM can sit on either side of Phantom; [litellm.md](litellm.md) has both setups.

- LiteLLM as the upstream of a Phantom route (`phantom start` with a custom route): the proxy swaps the placeholder into each of the 7 key headers LiteLLM documents and scrubs echoes of them, buffered and streamed. Tests: `crates/phantom-proxy/tests/litellm_upstream_headers_test.rs` (streamed cases added in #317).
- LiteLLM run under `phantom exec`, end to end from agent to LiteLLM to the proxy to the provider: the real key exists only on the proxy-to-provider hop. It is not in the agent's environment or output, not in anything LiteLLM receives or gets back, and appears exactly once at the provider. A provider that echoes the key is scrubbed before LiteLLM sees the reply. Test: `real_key_exists_only_on_the_proxy_to_provider_hop` (`crates/phantom-proxy/tests/exec_agent_litellm_chain_test.rs`). Limit: that test drives the proxy library the way exec builds it, because the `phantom` binary cannot target a plain-HTTP mock upstream.
- `phantom doctor` warns when a LiteLLM config that routes through Phantom pins a version below 1.83.0, sets `allow_client_side_credentials: true`, or binds beyond loopback. It is report-only. Tests: `doctor_json_reports_risky_litellm_through_phantom_and_changes_nothing`, `doctor_ignores_litellm_config_not_routed_through_phantom` (`crates/phantom-cli/tests/doctor_test.rs`).

## 4. Temporal (optional)

`examples/temporal-codec-python` is a sketch of a Temporal payload codec, not a supported product.

- Round trip, key rotation by key id, tamper and unknown-key rejection, and key length are unit tested with fake keys. Tests: `test_codec.py` (`test_round_trip`, `test_old_key_still_decodes_after_rotation`, `test_tamper_and_unknown_key_rejected`, `test_key_length_enforced`). CI runs them (#307).
- The codec key can reach the worker through an inherited file descriptor, not argv or the environment. Test: `test_key_reaches_child_without_argv_or_environ` (`test_key_delivery.py`, Linux only).
- Limit: the codec does not get its key from the Phantom proxy, and it has not had a cryptographer's review. See the example's README.

## 5. Post-quantum TLS to the provider

- The proxy's upstream TLS client offers the hybrid group X25519MLKEM768 first, followed by classical groups. Tests: `upstream_client_pq_group_posture_is_pinned`, `reported_groups_match_the_client_hello` (`crates/phantom-proxy/tests/tls_client_hello_groups_test.rs`).
- Against a server that accepts only X25519MLKEM768, the handshake succeeds; against a server that accepts only a group the proxy does not offer, it fails. Tests: `proxy_upstream_negotiates_x25519mlkem768_with_a_pq_only_server`, `negative_control_server_with_a_group_the_proxy_does_not_offer_fails` (`tls_pq_negotiation_test.rs`).
- Limit: this covers the proxy-to-provider hop only. The agent-to-proxy hop is plain HTTP on loopback, and the provider decides which group is used.

## Run the tests

```sh
cargo test -p phantom-secrets-proxy
cargo test -p phantom-secrets --test exec_output_streams_test --test doctor_test
```
