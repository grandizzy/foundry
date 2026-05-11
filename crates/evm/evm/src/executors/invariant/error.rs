use super::InvariantContract;
use crate::executors::RawCallResult;
use alloy_json_abi::Function;
use alloy_primitives::{Address, B256, Bytes, Selector, keccak256};
use foundry_config::InvariantConfig;
use foundry_evm_core::{
    decode::{ASSERTION_FAILED_PREFIX, EMPTY_REVERT_DATA, RevertDecoder},
    evm::FoundryEvmNetwork,
};
use foundry_evm_fuzz::{BasicTxDetails, Reason, invariant::FuzzRunIdentifiedContracts};
use proptest::test_runner::TestError;
use std::{collections::HashMap, fmt};

/// Records a single handler-side assertion bug discovered during an invariant campaign.
///
/// Handler-side assertions (e.g. a `require`/`assert` inside a fuzzed handler that the campaign
/// reaches with a malformed input) are bugs in their own right, but they are *not* invariant
/// predicate violations. We dedup them by the `(reverter, selector)` site of the asserting
/// call so the same handler function asserting via N different code paths counts as a single
/// bug (Echidna/Medusa semantics). The shortest call sequence wins on collision, so persisted
/// reproducers stay minimal. `edge_fingerprint` is still recorded on the failure value to let
/// the shrinker preserve path identity when minimizing a single reproducer.
#[derive(Clone, Debug)]
pub struct HandlerAssertionFailure {
    /// Address of the handler contract whose call asserted/reverted with an assertion.
    pub reverter: Address,
    /// 4-byte selector of the failing handler function.
    pub selector: Selector,
    /// Full call sequence leading up to (and including) the failing call. After shrinking
    /// this holds the minimal prefix that still triggers the anchor assertion.
    pub call_sequence: Vec<BasicTxDetails>,
    /// Pre-shrink length of `call_sequence`, used by the renderer's
    /// `(original: N, shrunk: M)` output.
    pub original_sequence_len: usize,
    /// Decoded revert/assert reason.
    pub revert_reason: String,
    /// Stable hash of the asserting call's edge coverage (or `(reverter, selector)` when
    /// edge coverage is unavailable). Not used for dedup (see `InvariantFailures.broken_handlers`)
    /// but kept so the shrinker can preserve path identity when minimizing this reproducer.
    pub edge_fingerprint: B256,
}

impl HandlerAssertionFailure {
    /// Builds a failure from a replayed sequence whose last call asserted; `(reverter,
    /// selector)` are derived from that call's `(target, calldata[..4])`.
    pub fn from_replayed_sequence(
        call_sequence: Vec<BasicTxDetails>,
        edge_fingerprint: B256,
        revert_reason: String,
    ) -> Self {
        let last = call_sequence.last().expect("replayed sequence is non-empty");
        let reverter = last.call_details.target;
        let selector_bytes: [u8; 4] =
            last.call_details.calldata.get(..4).and_then(|s| s.try_into().ok()).unwrap_or_default();
        let original_sequence_len = call_sequence.len();
        Self {
            reverter,
            selector: Selector::from(selector_bytes),
            call_sequence,
            original_sequence_len,
            revert_reason,
            edge_fingerprint,
        }
    }
}

/// Run-scoped context bundling the references that an invariant run needs in multiple places
/// (recording failures, attributing breaks to a specific invariant, etc.).
///
/// Constructed once per loop iteration and passed by reference; produces failure records via
/// [`InvariantRunCtx::failed_case`].
pub struct InvariantRunCtx<'a> {
    /// The invariant test contract definition.
    pub contract: &'a InvariantContract<'a>,
    /// Active invariant configuration (provides `shrink_run_limit`, `fail_on_revert`, ...).
    pub config: &'a InvariantConfig,
    /// Fuzz targets discovered for this run.
    pub targeted_contracts: &'a FuzzRunIdentifiedContracts,
    /// Inputs of the current run, used as the failing call sequence.
    pub calldata: &'a [BasicTxDetails],
}

impl<'a> InvariantRunCtx<'a> {
    /// Builds a [`FailedInvariantCaseData`] attributed to `broken_fn`.
    ///
    /// `fail_on_revert` is taken separately because `assert_invariants` overrides it with
    /// the per-invariant flag, while every other call site forwards `self.config.fail_on_revert`.
    /// `assertion_failure` is set when the failure originated from a Solidity `assert`/
    /// `vm.assert*` path; it normalizes empty decoded revert data into a stable user-facing
    /// message so invariant output is not blank.
    pub fn failed_case<FEN: FoundryEvmNetwork>(
        &self,
        broken_fn: &Function,
        fail_on_revert: bool,
        assertion_failure: bool,
        call_result: RawCallResult<FEN>,
        inner_sequence: &[Option<BasicTxDetails>],
    ) -> FailedInvariantCaseData {
        let revert_reason = self.decode_revert_reason(&call_result, assertion_failure);
        let origin = broken_fn.name.as_str();
        FailedInvariantCaseData {
            test_error: TestError::Fail(
                format!("{origin}, reason: {revert_reason}").into(),
                self.calldata.to_vec(),
            ),
            return_reason: "".into(),
            revert_reason,
            addr: self.contract.address,
            calldata: broken_fn.selector().to_vec().into(),
            inner_sequence: inner_sequence.to_vec(),
            shrink_run_limit: self.config.shrink_run_limit,
            fail_on_revert,
            assertion_failure,
        }
    }

    /// Decodes the revert/assert reason for `call_result` using the same fallback rules as
    /// [`Self::failed_case`], without building a full [`FailedInvariantCaseData`].
    ///
    /// Useful for callers that only need the reason (e.g. handler-bug recording in
    /// [`record_handler_assertion_bug`]), avoiding a full clone of `self.calldata` and
    /// the `TestError::Fail` allocation.
    pub fn decode_revert_reason<FEN: FoundryEvmNetwork>(
        &self,
        call_result: &RawCallResult<FEN>,
        assertion_failure: bool,
    ) -> String {
        // Collect abis of fuzzed and invariant contracts to decode custom error.
        let revert_reason = RevertDecoder::new()
            .with_abis(self.targeted_contracts.targets.lock().values().map(|c| &c.abi))
            .with_abi(self.contract.abi)
            .decode(call_result.result.as_ref(), call_result.exit_reason);
        // Non-reverting assertion failures surface through Foundry's failure flags instead of
        // revert data. Use a stable fallback so invariant output is not blank, both for the
        // successful-call/assertion path and the explicit assertion_failure flag.
        let needs_fallback = matches!(revert_reason.as_str(), "" | EMPTY_REVERT_DATA);
        if needs_fallback && (!call_result.reverted || assertion_failure) {
            ASSERTION_FAILED_PREFIX.to_string()
        } else {
            revert_reason
        }
    }
}

/// Computes the edge-coverage fingerprint for a handler-side assertion call. `target` is
/// the handler contract address whose call asserted/reverted (mirrors
/// `HandlerAssertionFailure::reverter`).
///
/// Prefers `pre_merge_edges_hash` (a hash of the call's edge coverage taken *before*
/// `merge_edge_coverage` zeroes the buffer). Falls back to a `(target, selector)` hash so
/// the dedup key is always defined and behavior degrades gracefully when edge coverage
/// collection is disabled.
pub fn handler_edge_fingerprint(
    pre_merge_edges_hash: Option<B256>,
    target: Address,
    selector: Selector,
) -> B256 {
    if let Some(hash) = pre_merge_edges_hash {
        return hash;
    }
    // Fallback: stable hash of (target || selector). Preserves prior key-based dedup.
    let mut buf = [0u8; 24];
    buf[..20].copy_from_slice(target.as_slice());
    buf[20..].copy_from_slice(selector.as_slice());
    keccak256(buf)
}

/// Records a handler-side assertion bug into `failures` (if it's a strictly shorter repro
/// than what we already have for this site) and pops the just-asserted reverted input from
/// `inputs` to mirror the standard reverted-input handling.
///
/// Centralizes the recording sequence shared by the periodic-check path
/// ([`super::result::can_continue`]) and the inline check-skipped path (campaign loop in
/// [`super::InvariantExecutor::invariant_fuzz`]). Both call sites previously inlined this 5-step
/// block; consolidating here keeps the dedup rule, the `revert_reason` extraction via
/// [`InvariantRunCtx::failed_case`], and the reverted-input pop in one place.
#[expect(clippy::too_many_arguments)]
pub(crate) fn record_handler_assertion_bug<FEN: FoundryEvmNetwork>(
    invariant_contract: &InvariantContract<'_>,
    config: &InvariantConfig,
    targeted_contracts: &FuzzRunIdentifiedContracts,
    failures: &mut InvariantFailures,
    inputs: &mut Vec<BasicTxDetails>,
    handler_target: Address,
    handler_selector: Selector,
    pre_merge_edges_hash: Option<B256>,
    call_result: RawCallResult<FEN>,
    call_reverted: bool,
    is_optimization: bool,
) {
    let fingerprint =
        handler_edge_fingerprint(pre_merge_edges_hash, handler_target, handler_selector);

    if !handler_site_already_minimal(
        &failures.failures,
        (handler_target, handler_selector),
        inputs.len(),
    ) {
        // Decode revert reason directly without building a full `FailedInvariantCaseData`
        // — handler bugs are recorded under `FailureKey::Handler`, not as invariant
        // predicate failures, so the heavier `failed_case` machinery isn't needed.
        let revert_reason = InvariantRunCtx {
            contract: invariant_contract,
            config,
            targeted_contracts,
            calldata: inputs,
        }
        .decode_revert_reason(&call_result, true);
        let call_sequence = inputs.clone();
        let original_sequence_len = call_sequence.len();
        failures.record_handler_failure(HandlerAssertionFailure {
            reverter: handler_target,
            selector: handler_selector,
            call_sequence,
            original_sequence_len,
            revert_reason,
            edge_fingerprint: fingerprint,
        });
    }

    // Mirror the standard reverted-input pop so the input doesn't appear in subsequent
    // prefixes. Delay-enabled campaigns keep reverted calls so shrinking can preserve
    // their warp/roll contribution.
    if call_reverted && !is_optimization && !config.has_delay() {
        inputs.pop();
    }
}

/// True if `failures` already holds a [`HandlerAssertionFailure`] for `site` whose
/// reproducer is no longer than `candidate_len`. Centralizes the dedup rule used to skip
/// inserting / building a strictly-not-shorter repro for the same `(reverter, selector)`
/// site (called from the campaign loop, the post-campaign result builder, the failure
/// recorder, and the persisted-replay path).
pub fn handler_site_already_minimal(
    failures: &HashMap<FailureKey, InvariantFuzzError>,
    site: (Address, Selector),
    candidate_len: usize,
) -> bool {
    failures
        .get(&FailureKey::Handler(site.0, site.1))
        .and_then(InvariantFuzzError::as_handler_assertion)
        .is_some_and(|existing| existing.call_sequence.len() <= candidate_len)
}

/// Snapshots the asserting call's edge coverage as a stable hash *before* the corpus's
/// `merge_edge_coverage` zeroes the buffer. Returns `None` when edge coverage is unavailable
/// (e.g. corpus / coverage collection disabled).
pub fn snapshot_edge_fingerprint<FEN: FoundryEvmNetwork>(
    call_result: &RawCallResult<FEN>,
) -> Option<B256> {
    let edges = call_result.edge_coverage.as_deref()?;
    if edges.is_empty() || edges.iter().all(|b| *b == 0) {
        return None;
    }
    Some(keccak256(edges))
}

/// Identifies a single entry in [`InvariantFailures::failures`].
///
/// Invariant predicate failures and handler-side assertion bugs share one map; this enum
/// keeps their key spaces separate while letting them flow through the same accessor surface.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum FailureKey {
    /// Keyed by invariant function name.
    Invariant(String),
    /// Keyed by handler `(reverter, selector)` site. The same handler function asserting via
    /// N different code paths counts as a single bug (Echidna/Medusa semantics).
    Handler(Address, Selector),
}

/// Stores information about failures and reverts of the invariant tests.
///
/// Invariant predicate failures and handler-side assertion bugs share a single
/// [`FailureKey`]-keyed map. Helpers like [`InvariantFailures::invariant_count`] and
/// [`InvariantFailures::handler_failures_mut`] partition the map by kind for callers that
/// only care about one side; at the campaign boundary [`InvariantFailures::partition`]
/// hands callers the two legacy maps so the public [`super::InvariantFuzzTestResult`] shape
/// stays unchanged.
///
/// TODO: dedup multiple distinct `assert(...)` failures within the same
/// `(reverter, selector)` handler. Echidna explicitly cannot tell them apart and our
/// current key collapses them as well; if/when callers need finer attribution
/// (e.g. per-assertion-label), extend the key with a stable per-call discriminator
/// (revert reason hash, source location, or label string).
#[derive(Clone, Default)]
pub struct InvariantFailures {
    /// Total number of reverts.
    pub reverts: usize,
    /// Invariant predicate failures and handler-side assertion bugs share one map.
    /// Mutate only via `record_failure` / `record_handler_failure` / `seed_handler_failure`
    /// so the cached counters stay in sync.
    pub(crate) failures: HashMap<FailureKey, InvariantFuzzError>,
    /// Cached `FailureKey::Invariant` count. Avoids an O(n) map scan on the fuzz hot path
    /// (read before/after every call to detect newly-broken invariants).
    invariant_count: usize,
    /// Cached `FailureKey::Handler` count. Same rationale, read on progress/metrics ticks.
    handler_count: usize,
}

impl InvariantFailures {
    pub fn new() -> Self {
        Self::default()
    }

    /// Splits `self.failures` into the legacy `(invariant_errors, handler_errors)` pair so
    /// the public [`super::InvariantFuzzTestResult`] surface stays unchanged.
    pub fn partition(
        self,
    ) -> (HashMap<String, InvariantFuzzError>, HashMap<(Address, Selector), InvariantFuzzError>)
    {
        let mut invariant_errors = HashMap::new();
        let mut handler_errors = HashMap::new();
        for (key, err) in self.failures {
            match key {
                FailureKey::Invariant(name) => {
                    invariant_errors.insert(name, err);
                }
                FailureKey::Handler(addr, sel) => {
                    handler_errors.insert((addr, sel), err);
                }
            }
        }
        (invariant_errors, handler_errors)
    }

    pub fn record_failure(&mut self, invariant: &Function, failure: InvariantFuzzError) {
        let prev = self.failures.insert(FailureKey::Invariant(invariant.name.clone()), failure);
        if prev.is_none() {
            self.invariant_count += 1;
        }
    }

    pub fn has_failure(&self, invariant: &Function) -> bool {
        self.failures.contains_key(&FailureKey::Invariant(invariant.name.clone()))
    }

    pub fn get_failure(&self, invariant: &Function) -> Option<&InvariantFuzzError> {
        self.failures.get(&FailureKey::Invariant(invariant.name.clone()))
    }

    /// Returns the recorded revert reason for `invariant`, or an empty string if the invariant
    /// has no recorded failure (or its failure carries no reason). Used when emitting failure
    /// events so the metrics payload mirrors the persisted failure.
    pub fn broken_reason(&self, invariant: &Function) -> String {
        self.get_failure(invariant).and_then(|e| e.revert_reason()).unwrap_or_default()
    }

    pub const fn can_continue(&self, invariants: usize) -> bool {
        self.invariant_count() < invariants
    }

    /// Number of unique broken invariant predicates (anchor + `assert_all` secondaries).
    /// O(1) — served from cached counter, called per fuzz call.
    pub const fn invariant_count(&self) -> usize {
        self.invariant_count
    }

    /// Number of unique handler-side assertion bugs. O(1) — served from cached counter.
    pub const fn handler_count(&self) -> usize {
        self.handler_count
    }

    /// Records a handler-side assertion bug. Keyed by the `(reverter, selector)` site of
    /// the failing call, so the same handler function asserting via different code paths
    /// counts as a single bug. On collision the shortest `call_sequence` wins, giving us
    /// a smaller reproducer over time. The bug is stored as the
    /// [`InvariantFuzzError::HandlerAssertion`] variant.
    pub fn record_handler_failure(&mut self, failure: HandlerAssertionFailure) {
        let site = (failure.reverter, failure.selector);
        if !handler_site_already_minimal(&self.failures, site, failure.call_sequence.len()) {
            let prev = self.failures.insert(
                FailureKey::Handler(site.0, site.1),
                InvariantFuzzError::HandlerAssertion(failure),
            );
            if prev.is_none() {
                self.handler_count += 1;
            }
        }
    }

    /// Inserts a persisted-replay handler bug. Skips the dedup check (caller seeds an
    /// empty map) but bumps `handler_count` so the live counter is correct from first tick.
    pub fn seed_handler_failure(
        &mut self,
        target: Address,
        selector: Selector,
        err: InvariantFuzzError,
    ) {
        let prev = self.failures.insert(FailureKey::Handler(target, selector), err);
        if prev.is_none() {
            self.handler_count += 1;
        }
    }

    /// Returns true if a handler bug has already been recorded for the given site.
    pub fn has_handler_failure(&self, target: Address, selector: Selector) -> bool {
        self.failures.contains_key(&FailureKey::Handler(target, selector))
    }

    /// Mutable iterator over handler-side assertion bug entries (used by the post-campaign
    /// shrink loop).
    pub fn handler_failures_mut(
        &mut self,
    ) -> impl Iterator<Item = ((Address, Selector), &mut InvariantFuzzError)> {
        self.failures.iter_mut().filter_map(|(key, err)| match key {
            FailureKey::Handler(addr, sel) => Some(((*addr, *sel), err)),
            FailureKey::Invariant(_) => None,
        })
    }
}

impl fmt::Display for InvariantFailures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f)?;
        writeln!(f, "      ❌ Failures: {}", self.invariant_count())?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum InvariantFuzzError {
    /// A handler call reverted under `fail_on_revert = true` (no Solidity assertion involved).
    Revert(FailedInvariantCaseData),
    /// An `invariant_*` predicate returned `false` (or asserted) — i.e. the property is broken.
    BrokenInvariant(FailedInvariantCaseData),
    /// A handler-side `assert(...)` / `vm.assert*` failed. Distinct from `BrokenInvariant`:
    /// the bug is *inside* a fuzzed handler function, not in any `invariant_*` predicate.
    /// Recorded once per `(reverter, selector)` site (Echidna/Medusa semantics).
    HandlerAssertion(HandlerAssertionFailure),
    /// `vm.assume` rejected more inputs than allowed.
    MaxAssumeRejects(u32),
}

impl InvariantFuzzError {
    pub fn revert_reason(&self) -> Option<String> {
        match self {
            Self::BrokenInvariant(case_data) | Self::Revert(case_data) => {
                (!case_data.revert_reason.is_empty()).then(|| case_data.revert_reason.clone())
            }
            Self::HandlerAssertion(failure) => {
                (!failure.revert_reason.is_empty()).then(|| failure.revert_reason.clone())
            }
            Self::MaxAssumeRejects(allowed) => {
                Some(format!("`vm.assume` rejected too many inputs ({allowed} allowed)"))
            }
        }
    }

    /// Returns the wrapped `HandlerAssertionFailure` if this is the [`Self::HandlerAssertion`]
    /// variant. Used by call sites that store handler bugs in their own map and need to read
    /// out the structured failure (call sequence, fingerprint, etc.).
    pub const fn as_handler_assertion(&self) -> Option<&HandlerAssertionFailure> {
        match self {
            Self::HandlerAssertion(failure) => Some(failure),
            _ => None,
        }
    }

    /// Mutable counterpart of [`Self::as_handler_assertion`]. Used by post-campaign shrinking
    /// to mutate the persisted call sequence in place.
    pub const fn as_handler_assertion_mut(&mut self) -> Option<&mut HandlerAssertionFailure> {
        match self {
            Self::HandlerAssertion(failure) => Some(failure),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FailedInvariantCaseData {
    /// The proptest error occurred as a result of a test case.
    pub test_error: TestError<Vec<BasicTxDetails>>,
    /// The return reason of the offending call.
    pub return_reason: Reason,
    /// The revert string of the offending call.
    pub revert_reason: String,
    /// Address of the invariant asserter.
    pub addr: Address,
    /// Function calldata for invariant check.
    pub calldata: Bytes,
    /// Inner fuzzing Sequence coming from overriding calls.
    pub inner_sequence: Vec<Option<BasicTxDetails>>,
    /// Shrink run limit
    pub shrink_run_limit: u32,
    /// Fail on revert, used to check sequence when shrinking.
    pub fail_on_revert: bool,
    /// Whether this failure originated from a handler assertion.
    pub assertion_failure: bool,
}
