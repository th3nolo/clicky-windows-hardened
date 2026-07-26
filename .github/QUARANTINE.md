# Ephemeral Windows quarantine

This manual workflow is a merge gate for an exact reviewed commit. It is not a
release or signing pipeline.

Before dispatching it:

1. Generate a one-time, unencrypted SSH key pair that `age` 1.3.1 supports.
2. Store the private key as the temporary Actions secret
   `AGE_SSH_PRIVATE_KEY`.
3. Pass the matching single-line public key as
   `age_ssh_public_recipient`.
4. Store the VirusTotal API key as `VT_API_KEY`.
5. Pass the exact target commit and the independently computed SHA-256 of
   `git archive --format=zip` for that commit.

After every run, whether it succeeds or fails, remove both `AGE_SSH_PRIVATE_KEY`
and `VT_API_KEY` from the repository Actions secrets. Confirm independently in
the Actions UI or API that the run has zero retained artifacts; manually delete
any residual quarantine artifact before merging. VirusTotal submissions should
be treated as public disclosures of the submitted source archive, full
distribution archive, and unsigned executable. The scanner binds the returned
VirusTotal file ID to each local SHA-256, requires at least 50 clean-participating
engines (undetected plus harmless), preserves the complete per-engine analysis and
file-report records in the run log, and additionally requires undetected verdicts
from Malwarebytes and Microsoft for the executable. API calls and uploads share a
start-to-start pacer of at least 16 seconds so the scan stays below the common
four-requests-per-minute public API limit.

The workflow deliberately uses four fresh Windows VMs:

- The build/runtime VM receives no secrets and uploads only four independently
  encrypted files.
- The verifier VM receives only the age identity. It decrypts and parses the
  evidence, reconstructs `Clicky.exe`, and emits exact hashes.
- The scanner VM receives the age identity and VirusTotal key. It decrypts only
  the three direct scan files, treats them as opaque bytes, binds them to the
  verifier hashes, and uploads them to VirusTotal.
- The cleanup VM receives only a run-scoped GitHub token and deletes the
  ciphertext artifact even after a failed verification or scan.

The build target executes as the same Windows user as the trusted harness.
Inline pre/post hashes detect ordinary overwrites of the trusted helper, and
the fresh verifier rejects malformed or hash-inconsistent evidence, but a
hostile process can still attempt same-user races inside the build VM. A successful
race could transiently upload a file that merely imitates an age header; the fresh
verifier would reject it only after upload. This is one reason the workflow remains
a merge-only signal, not a proof that hostile target code cannot influence its VM.

A release still requires the existing Windows Sandbox validation, a manual consumer Malwarebytes
scan of the exact built files, and an Authenticode-signed
production build. Unsigned quarantine output must never be distributed.
