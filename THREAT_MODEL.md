# python-smhasher threat model

## 1. Overview

python-smhasher is a CPython C++ extension exposing MurmurHash3 functions that return 64-bit or 128-bit Python integers. The interface offers separate x86/x64 variants and an optional seed. Its README explicitly identifies the underlying library as non-cryptographic (`README.md:2`). Normal use is an import and function call in an application-owned Python process; no network listener, account system or persistent data store is established by the wrapper.

The main path is Python arguments → CPython buffer/type conversion → a fixed MurmurHash3 routine → a 16-byte native output buffer → a Python integer. Although the repository vendors a broader SMHasher source/test suite, the extension build selects only the wrapper and `MurmurHash3.cpp`. Other vendored algorithms and test harnesses are not automatically Python-reachable (`setup.py:11`).

| Component | Responsibility | Evidence |
| --- | --- | --- |
| Public Python methods | Four fixed x86/x64 and 64/128-bit entry points | `smhasher.cpp:74` |
| Shared native wrapper | Decode input/seed, select routine, convert output | `smhasher.cpp:22` |
| MurmurHash3 implementation | Read blocks/tail bytes and produce fixed-size hash | `smhasher/MurmurHash3.cpp:150`, `smhasher/MurmurHash3.cpp:255` |
| Extension packaging | Select native compilation inputs and version macro | `setup.py:11` |
| Maintainer refresh tool | Back up vendored directory and import upstream source | `refresh.sh:3` |

| Workflow | Input/configuration chain | Effective resource | Recipients/control | Evidence |
| --- | --- | --- | --- | --- |
| Hash call | Wrapper → `s#` input and optional unsigned seed → chosen native routine | Caller buffer; seed defaults to zero; stack output is 16 bytes | Same Python process; CPython conversion and fixed method selection | `smhasher.cpp:22`, `smhasher.cpp:30` |
| Result conversion | Fixed wrapper chooses 8 or 16 output bytes | Unsigned Python integer from native output bytes | Python caller; output length is not a free caller parameter | `smhasher.cpp:40`, `smhasher.cpp:45` |
| Source build | Distutils `Extension` source/include list | `smhasher.cpp` + `smhasher/MurmurHash3.cpp`, headers under `smhasher` | Compiler and eventual extension consumers; trusted build inputs | `setup.py:11` |
| Upstream refresh | Script directory → timestamped backup → SVN export | `<repo>/smhasher`, imported from `http://smhasher.googlecode.com/svn/trunk/` | Maintainer workspace and later builds; explicit maintainer invocation | `refresh.sh:3`, `refresh.sh:6`, `refresh.sh:10` |

Python 2 and Python 3 module initialization use separate CPython API branches (`smhasher.cpp:89`). Actual supported modern interpreter/compiler combinations were not tested. The package’s historical compatibility metadata must not be treated as proof that every contemporary ABI or architecture works.

## 2. Threat Model, Trust Boundaries, and Assumptions

The protected assets are host process memory safety and availability, hash-result integrity, and extension/source provenance. A realistic attacker may choose values a host passes to hashing, including input content, length and seed where exposed. They do not automatically gain the ability to execute maintainer scripts, change native binaries, select build tools or read unrelated process data.

The Python-to-native boundary is concrete. CPython parses the input using `s#|I`, yielding a pointer and `Py_ssize_t` length, but both called native Murmur functions accept an `int` length (`smhasher.cpp:25`, `smhasher.cpp:30`, `smhasher/MurmurHash3.cpp:150`, `smhasher/MurmurHash3.cpp:255`). Length fidelity across these types is an architectural invariant. The source observations identify a validation target; this model does not claim an executed oversized-input exploit or its precise memory effect.

Native hashing walks blocks and tail bytes derived from that length. The caller buffer must remain valid and every native access must stay within its extent. Native output is locally allocated at a fixed 16 bytes, and the public wrappers request only fixed 8- or 16-byte conversions (`smhasher.cpp:28`, `smhasher.cpp:45`, `smhasher.cpp:59`). That constrains output size, but does not independently prove input-length handling, alignment behavior or all platform-specific loads.

Hash semantics form a separate integration boundary. These functions are deterministic non-cryptographic hashes; a seed is not an authentication key, and a 128-bit result does not establish collision resistance suitable for adversarial authorization or artifact authenticity (`README.md:2`, `smhasher.cpp:27`). Applications must use an appropriate cryptographic construction when they need those properties. Ordinary collisions or chosen seeds are not, by themselves, vulnerabilities in an explicitly non-cryptographic library.

Availability depends on where the host performs the work. Hashing reads input in native loops; no separate worker or library-level quota is established in the wrapper (`smhasher/MurmurHash3.cpp:171`, `smhasher/MurmurHash3.cpp:272`). Large inputs may therefore occupy the caller process for significant work. A shared-service denial-of-service claim needs actual exposure, accepted sizes and measured impact; input proportionality alone is not a defect.

The maintainer refresh path has different authority. Its URL uses HTTP and its export does not pin a source revision. It moves the existing vendor directory to a timestamped sibling before importing a replacement (`refresh.sh:3`, `refresh.sh:6`, `refresh.sh:10`). That backup supports local recovery, but is not provenance or transport authentication. Present availability of the historical upstream endpoint and use of the script in any release were not checked. No automatic package-publishing or release-credential path was established here.

The model excludes invented deployments: no tenant model, public service, cryptographic use, or live release environment is assumed. The full vendored test corpus is not equivalent to runtime exposure. Source inspection did not execute the extension or conduct a full native-code audit.

## 3. Attack Surface, Mitigations, and Attacker Stories

These prioritized hypotheses require validation of the specific input boundary and host impact. A suspicious conversion or old script is not a confirmed vulnerability without its relevant prerequisites.

| Priority | Scenario and capability gain | Prerequisites | Impact | Existing controls | Mitigation | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| High, conditional | Chosen input length violates the Python/native buffer contract | Host accepts an input large enough for relevant width conversion and native behavior is unsafe | Native memory-safety failure or shared process crash, if demonstrated | CPython parses a length; fixed native algorithms and output allocation | Preserve length range before native dispatch; validate exact affected platform/path | `smhasher.cpp:25`, `smhasher.cpp:35`, `smhasher/MurmurHash3.cpp:150` |
| Medium, conditional | Repeated large hashes consume shared request capacity | Attacker reaches an unbounded shared hashing operation | Latency or availability loss to other users | Work follows native block loops; no established separate worker | Bound accepted sizes/rates and measure host capacity | `smhasher/MurmurHash3.cpp:171`, `smhasher/MurmurHash3.cpp:272` |
| Context-dependent | Application mistakes Murmur output/seed for authentication or collision-resistant identity | Downstream security decision relies on a property not offered by the library | Forged identity/decision integrity only if that reliance is real | README explicitly says non-cryptographic | Use a cryptographic primitive with the required security contract | `README.md:2`, `smhasher.cpp:27` |
| High, conditional | A hostile upstream response becomes compiled native source | Maintainer uses refresh script; attacker controls reachable response/channel below maintainer authority | Modified native code reaches future extension consumers | Existing directory backup; explicit maintainer invocation | Authenticate and pin imported source; inspect changes before building/distributing | `refresh.sh:3`, `refresh.sh:10`, `setup.py:11` |

A clean assessment separates wrapper defects from host misuse and already-authorized build authority. Changing the installed extension with an account that already controls application binaries is not a new privilege gain. Similarly, knowing a hash or selecting the public seed does not give access to original inputs or unrelated memory without a separately demonstrated failure.

## 4. Severity Calibration (Critical, High, Medium, Low)

**Critical:** Requires independently demonstrated exceptional reach, such as a compromised trusted distribution introducing native execution across many privileged consumers. Neither the presence of C++ nor an HTTP maintainer script alone meets that threshold.

**High:** A reproducible caller-input-driven native memory violation, sensitive memory disclosure, or material shared-service outage may qualify. Successful compilation or a type-width mismatch alone is not proof of those outcomes. Compromise of an actually used source-refresh chain may qualify when it crosses a real trust boundary.

**Medium:** Bounded but meaningful shared availability degradation or a concrete host integrity failure from a misused hash contract. The relevant host usage must be shown. An expensive hash requested by its only local user is a counterexample.

**Low:** Recoverable conversion errors, narrow compatibility failures, or non-security hash/format differences. Documented algorithm characteristics and ordinary collisions are not defects merely because a downstream application wanted cryptographic guarantees.

Remaining questions are exact host exposure, accepted length limits, native platform behavior and whether the refresh workflow is used. No runtime or exploit validation was performed.

---

Repository: https://github.com/mathspace/python-smhasher  
Version: `f847d5e83d82779343f712fb2a121499dd1850bd`
