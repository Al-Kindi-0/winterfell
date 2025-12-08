// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

//! Contains helper structs and methods to estimate the security of STARK proofs.

use core::cmp;

use crate::{BatchingMethod, ProofOptions};

// CONSTANTS
// ================================================================================================

const GRINDING_CONTRIBUTION_FLOOR: u32 = 80;
const MAX_PROXIMITY_PARAMETER: u64 = 1000;

// CONJECTURED SECURITY
// ================================================================================================

/// Security estimate (in bits) of the protocol under Conjecture 1 in [1].
///
/// [1]: https://eprint.iacr.org/2021/582
pub struct ConjecturedSecurity(u32);

impl ConjecturedSecurity {
    /// Computes the security level (in bits) of the protocol using Eq. (19) in [1].
    ///
    /// [1]: https://eprint.iacr.org/2021/582
    pub fn compute(
        options: &ProofOptions,
        base_field_bits: u32,
        collision_resistance: u32,
    ) -> Self {
        // compute max security we can get for a given field size
        let field_security = base_field_bits * options.field_extension().degree();

        // compute security we get by executing multiple query rounds
        let security_per_query = options.blowup_factor().ilog2();
        let mut query_security = security_per_query * options.num_queries() as u32;

        // include grinding factor contributions only for proofs adequate security
        if query_security >= GRINDING_CONTRIBUTION_FLOOR {
            query_security += options.grinding_factor();
        }

        Self(cmp::min(cmp::min(field_security, query_security) - 1, collision_resistance))
    }

    /// Returns the conjectured security level (in bits).
    pub fn bits(&self) -> u32 {
        self.0
    }

    /// Returns whether or not the conjectured security level is greater than or equal to the the
    /// specified security level in bits.
    pub fn is_at_least(&self, bits: u32) -> bool {
        self.0 >= bits
    }
}

// PROVEN SECURITY
// ================================================================================================

/// Proven security estimate (in bits), in list-decoding and unique decoding regimes, of the
/// protocol.
pub struct ProvenSecurity {
    unique_decoding: u32,
    list_decoding: u32,
}

impl ProvenSecurity {
    /// Computes the proven security level (in bits) of the protocol using Theorem 2 and Theorem 3
    /// in [1].
    ///
    /// [1]: https://eprint.iacr.org/2024/1553
    pub fn compute(
        options: &ProofOptions,
        base_field_bits: u32,
        trace_domain_size: usize,
        collision_resistance: u32,
        num_constraints: usize,
        num_committed_polys: usize,
    ) -> Self {
        let unique_decoding = cmp::min(
            proven_security_protocol_unique_decoding(
                options,
                base_field_bits,
                trace_domain_size,
                num_constraints,
                num_committed_polys,
            ),
            collision_resistance as u64,
        ) as u32;

        // determine the interval to which the which the optimal `m` belongs
        let m_min: usize = 3;
        let m_max = compute_upper_m(trace_domain_size);

        // search for optimal `m` i.e., the one at which we maximize the number of security bits
        let m_optimal = (m_min as u32..m_max as u32)
        .max_by_key(|&a| {
            proven_security_protocol_for_given_proximity_parameter(
                options,
                base_field_bits,
                trace_domain_size,
                a as usize,
                num_constraints,
                num_committed_polys,
            )
        })
        .expect(
            "Should not fail since m_max is larger than m_min for all trace sizes of length greater than 4",
        );

        let list_decoding = cmp::min(
            proven_security_protocol_for_given_proximity_parameter(
                options,
                base_field_bits,
                trace_domain_size,
                m_optimal as usize,
                num_constraints,
                num_committed_polys,
            ),
            collision_resistance as u64,
        ) as u32;

        Self { unique_decoding, list_decoding }
    }

    /// Computes the proven security level (in bits) using a per-round grinding schedule. In this
    /// variant, schedule.fri_query overrides options.grinding_factor (no double counting). This is
    /// a sketch API and is not used by default.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_with_schedule(
        options: &ProofOptions,
        base_field_bits: u32,
        trace_domain_size: usize,
        collision_resistance: u32,
        num_constraints: usize,
        num_committed_polys: usize,
        schedule: &GrindingSchedule,
    ) -> Self {
        let unique_decoding = cmp::min(
            proven_security_protocol_unique_decoding_with_schedule(
                options,
                base_field_bits,
                trace_domain_size,
                num_constraints,
                num_committed_polys,
                schedule,
            ),
            collision_resistance as u64,
        ) as u32;

        // determine the interval to which the optimal `m` belongs
        let m_min: usize = 3;
        let m_max = compute_upper_m(trace_domain_size);

        // search for optimal `m`
        let m_optimal = (m_min as u32..m_max as u32)
            .max_by_key(|&a| {
                proven_security_protocol_for_given_proximity_parameter_with_schedule(
                    options,
                    base_field_bits,
                    trace_domain_size,
                    a as usize,
                    num_constraints,
                    num_committed_polys,
                    schedule,
                )
            })
            .expect("m_max > m_min for valid trace sizes");

        let list_decoding = cmp::min(
            proven_security_protocol_for_given_proximity_parameter_with_schedule(
                options,
                base_field_bits,
                trace_domain_size,
                m_optimal as usize,
                num_constraints,
                num_committed_polys,
                schedule,
            ),
            collision_resistance as u64,
        ) as u32;

        Self { unique_decoding, list_decoding }
    }

    /// Returns the proven security level (in bits) in the list decoding regime.
    pub fn ldr_bits(&self) -> u32 {
        self.list_decoding
    }

    /// Returns the proven security level (in bits) in the unique decoding regime.
    pub fn udr_bits(&self) -> u32 {
        self.unique_decoding
    }

    /// Returns whether or not the proven security level is greater than or equal to the the
    /// specified security level in bits.
    pub fn is_at_least(&self, bits: u32) -> bool {
        self.list_decoding >= bits || self.unique_decoding >= bits
    }
}

// GRINDING SCHEDULE (sketch-only API)
// ================================================================================================
// Represents per-round grinding bits to boost round-by-round soundness, as per the grinding lemma
// in the ethSTARK paper (IACR ePrint 2021/582). Each value adds that many bits to the
// corresponding round's epsilon in the round-by-round composition.
//
// Rounds (Johnson-regime, following our estimator's structure):
//  - ali: randomness used to batch constraints in ALI
//  - deep: randomness to choose out-of-domain (OOD) challenges
//  - fri_batching: randomness to batch multiple words for the DEEP composition to be checked by FRI
//  - fri_first_intermediate: first FRI intermediate round (bounds intermediates when folding factor
//    is constant across layers)
//  - fri_query: randomness for the FRI query seed; in schedule variants this overrides
//    options.grinding_factor.
#[derive(Clone, Copy, Debug, Default)]
pub struct GrindingSchedule {
    pub ali: u32,
    pub deep: u32,
    pub fri_batching: u32,
    pub fri_first_intermediate: u32,
    pub fri_query: u32,
}

/// Computes a grinding schedule to reach a target security level in the list-decoding regime.
///
/// For each candidate proximity parameter m, this function computes the baseline security bits
/// for each round without grinding. It then calculates the grinding deltas needed to lift all
/// rounds to the target security level.
///
/// The optimal m is chosen to minimize total expected prover work, measured as the log-sum-exp
/// of the grinding deltas: Σ 2^{delta_i} (in base 2). Ties are broken by L1 norm (Σ delta_i),
/// then by preferring smaller m.
///
/// # Returns
///
/// Returns a tuple containing:
/// - The absolute grinding schedule (suitable for `compute_with_schedule`)
/// - The achieved security bits (capped by field/hash limits)
/// - The chosen proximity parameter m
///
/// # Note
///
/// In schedule-aware computation paths, `schedule.fri_query` overrides `options.grinding_factor`
/// to avoid double-counting grinding contributions.
pub fn plan_grinding_schedule_ldr(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    collision_resistance: u32,
    num_constraints: usize,
    num_committed_polys: usize,
    target_bits: u32,
) -> (GrindingSchedule, u32, u32) {
    // Cap target by field/hash limits
    let field_cap = base_field_bits * options.field_extension().degree();
    let cap = field_cap.min(collision_resistance);
    let t = target_bits.min(cap);

    // Helper: compute per-round bits (no schedule, query grinding = 0) for a given m
    fn round_bits_for_m(
        options: &ProofOptions,
        base_field_bits: u32,
        trace_domain_size: usize,
        m: usize,
        num_constraints: usize,
        num_committed_polys: usize,
    ) -> (f64, f64, f64, f64, f64) {
        let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
        let num_fri_queries = options.num_queries() as f64;
        let m = m as f64;
        let rho = 1.0 / options.blowup_factor() as f64;
        let alpha = (1.0 + 0.5 / m) * sqrt(rho);
        let max_deg = options.blowup_factor() as f64 + 1.0;
        let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
        let trace_domain_size = trace_domain_size as f64;
        let num_openings = 2.0;

        // ALI
        let l = m / (rho - (2.0 * m / lde_domain_size));
        let batching_constraints = match options.constraint_batching_method() {
            BatchingMethod::Linear => 1.0,
            BatchingMethod::Algebraic | BatchingMethod::Horner => num_constraints as f64 - 1.0,
        };
        let b1 = -log2(l) - log2(batching_constraints) + extension_field_bits;

        // DEEP
        let b2 = -log2(
            l * (max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0)),
        ) + extension_field_bits;

        // FRI batching
        let batching_deep = match options.deep_poly_batching_method() {
            BatchingMethod::Linear => 1.0,
            BatchingMethod::Algebraic | BatchingMethod::Horner => num_committed_polys as f64 - 1.0,
        };
        let b3 = extension_field_bits
            - log2((2.0 * powf(m + 0.5, 5.0) / (3.0 * powf(rho, 1.5))) * lde_domain_size * batching_deep);

        // First intermediate (ε4)
        let folding_factor = options.to_fri_options().folding_factor() as f64;
        let b4 = b3.min(
            extension_field_bits - log2(folding_factor) - log2(lde_domain_size + 1.0) - log2(2.0 * m + 1.0)
                + 0.5 * log2(rho),
        );

        // Query (no schedule, override)
        let bq = -log2(powf(alpha, num_fri_queries));
        (b1, b2, b3, b4, bq)
    }

    // Search for optimal m by minimizing Σ 2^{delta_i}
    let m_min: usize = 3;
    let m_max = compute_upper_m(trace_domain_size).max(4.0) as usize;
    let mut best_cost_log2 = f64::INFINITY;
    let mut best_l1 = u64::MAX;
    let mut best_m = m_min as u32;
    let mut best_schedule = GrindingSchedule::default();

    for m in m_min..m_max {
        let (b1, b2, b3, b4, bq) = round_bits_for_m(
            options,
            base_field_bits,
            trace_domain_size,
            m,
            num_constraints,
            num_committed_polys,
        );
        let d1 = (t as i64 - b1 as i64).max(0) as u32;
        let d2 = (t as i64 - b2 as i64).max(0) as u32;
        let d3 = (t as i64 - b3 as i64).max(0) as u32;
        let d4 = (t as i64 - b4 as i64).max(0) as u32;
        let dq = (t as i64 - bq as i64).max(0) as u32;
        let deltas = [d1, d2, d3, d4, dq];

        // log-sum-exp base-2 of 2^{d_i}
        let maxd = deltas.iter().copied().max().unwrap_or(0) as f64;
        let log2_cost = if maxd == 0.0 {
            0.0
        } else {
            let sum = deltas
                .iter()
                .map(|&di| powf(2.0, di as f64 - maxd))
                .fold(0.0, |a, b| a + b);
            maxd + log2(sum)
        };
        let l1 = deltas.iter().map(|&di| di as u64).sum::<u64>();
        let better = (log2_cost < best_cost_log2)
            || ((log2_cost - best_cost_log2).abs() < 1e-9 && l1 < best_l1)
            || ((log2_cost - best_cost_log2).abs() < 1e-9 && l1 == best_l1 && best_m > m as u32);

        if better {
            best_cost_log2 = log2_cost;
            best_l1 = l1;
            best_m = m as u32;
            best_schedule = GrindingSchedule {
                ali: d1,
                deep: d2,
                fri_batching: d3,
                fri_first_intermediate: d4,
                fri_query: dq,
            };
        }
    }

    let achieved = t; // by construction, schedule lifts all rounds to target t
    (best_schedule, achieved, best_m)
}

/// Computes a grinding schedule to reach a target security level in the unique-decoding regime.
///
/// This function computes the baseline security bits for each round without grinding, then
/// calculates the grinding deltas needed to lift all rounds to the target security level.
///
/// # Returns
///
/// Returns a tuple containing:
/// - The absolute grinding schedule (suitable for `compute_with_schedule`)
/// - The achieved security bits (capped by field/hash limits)
///
/// # Note
///
/// In schedule-aware computation paths, `schedule.fri_query` overrides `options.grinding_factor`
/// to avoid double-counting grinding contributions.
#[allow(dead_code)]
pub fn plan_grinding_schedule_udr(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    collision_resistance: u32,
    num_constraints: usize,
    num_committed_polys: usize,
    target_bits: u32,
) -> (GrindingSchedule, u32) {
    // Cap target by field/hash limits
    let field_cap = base_field_bits * options.field_extension().degree();
    let cap = field_cap.min(collision_resistance);
    let t = target_bits.min(cap);

    // Helper: compute per-round bits (no schedule, query grinding = 0)
    fn round_bits(
        options: &ProofOptions,
        base_field_bits: u32,
        trace_domain_size: usize,
        num_constraints: usize,
        num_committed_polys: usize,
    ) -> (f64, f64, f64, f64, f64) {
        let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
        let num_fri_queries = options.num_queries() as f64;
        let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
        let trace_domain_size = trace_domain_size as f64;
        let num_openings = 2.0;
        let rho_plus = (trace_domain_size + num_openings) / lde_domain_size;
        let alpha = (1.0 + rho_plus) * 0.5;
        let max_deg = options.blowup_factor() as f64 + 1.0;

        // ALI
        let batching_constraints = match options.constraint_batching_method() {
            BatchingMethod::Linear => 1.0,
            BatchingMethod::Algebraic | BatchingMethod::Horner => num_constraints as f64 - 1.0,
        };
        let b1 = -log2(batching_constraints) + extension_field_bits;

        // DEEP
        let b2 = -log2(max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0))
            + extension_field_bits;

        // FRI batching (UDR commit-like)
        let batching_deep = match options.deep_poly_batching_method() {
            BatchingMethod::Linear => 1.0,
            BatchingMethod::Algebraic | BatchingMethod::Horner => num_committed_polys as f64 - 1.0,
        };
        let b3 = extension_field_bits - log2(lde_domain_size * batching_deep);

        // Intermediate layer bound (UDR analogue)
        let folding_factor = options.to_fri_options().folding_factor() as f64;
        let b4 = extension_field_bits - log2((folding_factor - 1.0) * (lde_domain_size + 1.0));

        // Query (no schedule)
        let bq = -log2(powf(alpha, num_fri_queries));
        (b1, b2, b3, b4, bq)
    }

    let (b1, b2, b3, b4, bq) = round_bits(
        options,
        base_field_bits,
        trace_domain_size,
        num_constraints,
        num_committed_polys,
    );

    let d1 = (t as i64 - b1 as i64).max(0) as u32;
    let d2 = (t as i64 - b2 as i64).max(0) as u32;
    let d3 = (t as i64 - b3 as i64).max(0) as u32;
    let d4 = (t as i64 - b4 as i64).max(0) as u32;
    let dq = (t as i64 - bq as i64).max(0) as u32;

    let schedule = GrindingSchedule {
        ali: d1,
        deep: d2,
        fri_batching: d3,
        fri_first_intermediate: d4,
        fri_query: dq,
    };
    let achieved = t;

    (schedule, achieved)
}

/// Computes proven security level for the specified proof parameters for a fixed value of the
/// proximity parameter m in the list-decoding regime.
fn proven_security_protocol_for_given_proximity_parameter(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    m: usize,
    num_constraints: usize,
    num_committed_polys: usize,
) -> u64 {
    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let m = m as f64;
    let rho = 1.0 / options.blowup_factor() as f64;
    let alpha = (1.0 + 0.5 / m) * sqrt(rho);
    // we use the blowup factor in order to bound the max degree
    let max_deg = options.blowup_factor() as f64 + 1.0;
    let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
    let trace_domain_size = trace_domain_size as f64;
    let num_openings = 2.0;

    // We follow the round-by-round (RbR) composition from prior analyses and incorporate
    // the Johnson-regime proximity-gap improvements:
    // - For ALI/DEEP and query-phase we keep the structure as in prior work (e.g., 2024/1553 and
    //   2022/1216),
    // - For the FRI commit-phase in LDR we use the improved Johnson-regime bound from IACR ePrint
    //   2025/2055 (Theorem 4.2) which tightens the dominant term and reduces the scaling in n.
    // Note: the range of m must ensure a positive slackness (η > 0 / valid Johnson gap τ > 0);
    // the caller (search over m) is responsible for selecting admissible values.
    let mut epsilons_bits_neg = vec![];

    // list size
    let l = m / (rho - (2.0 * m / lde_domain_size));

    // ALI related soundness error. If algebraic/curve batching is used for batching the constraints
    // then there is a loss of log2(C - 1) where C is the total number of constraints.
    let batching_factor = match options.constraint_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic | BatchingMethod::Horner => num_constraints as f64 - 1.0,
    };
    let epsilon_1_bits_neg = -log2(l) - log2(batching_factor) + extension_field_bits;
    epsilons_bits_neg.push(epsilon_1_bits_neg);

    // DEEP related soundness error. Note that this uses that the denominator |F| - |D ∪ H|
    // can be approximated by |F| for all practical domain sizes. We also use the blow-up factor
    // as an upper bound for the maximal constraint degree.
    let epsilon_2_bits_neg =
        -log2(l * (max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0)))
            + extension_field_bits;
    epsilons_bits_neg.push(epsilon_2_bits_neg);

    // compute FRI commit-phase (i.e., pre-query) soundness error.
    // Johnson-regime improvement (IACR ePrint 2025/2055): dominant term scales as
    //   2 * (m + 1/2)^5 / (3 * ρ^{3/2}) * n * (N - 1),
    // replacing the older (m + 1/2)^7 * n^2 /(3 * ρ^{3/2}) dependence. Here n is the LDE domain size,
    // and N is the number of batched polynomials (captured by batching_factor below).
    let batching_factor = match options.deep_poly_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic | BatchingMethod::Horner => num_committed_polys as f64 - 1.0,
    };
    // LDR commit-phase improvement (per IACR ePrint 2025/2055 proximity-gap results):
    // - Replace n^2 with n in the pre-query term (O(n) “exceptions” instead of O(n^2)) in LDR
    //   (e.g., Theorem 4.2 in IACR ePrint 2025/2055).
    // - Replace (m + 0.5)^7 with (m + 0.5)^5 (dominant term exponent tightened by the refined analysis).
    // Johnson-gap parameterization (Theorem 4.2 in IACR ePrint 2025/2055 and Theorem 5.1 in IACR ePrint 2020/654):
    //   Let J(δ) = 1 - sqrt(ρ) and τ = J(δ) - γ. Then
    //     m = max( sqrt(ρ) / (2 * τ), 3 ).
    // Our estimator searches over m directly, so it captures this regime without explicitly computing γ.
    // Lower-order term (∝ (m + 0.5) * γ * ρ) is omitted since its effect is negligible:
    // using γ ≤ J(δ) = 1 - sqrt(ρ), the ratio of lower-order to dominant term satisfies
    //   R ≤ (3/2) * (J(δ) * ρ) / (m + 0.5)^4 = (3/2) * (ρ * (1 - sqrt(ρ))) / (m + 0.5)^4.
    // Numerical example (conservative): m = 3 ⇒ m + 0.5 = 3.5, ρ = 1/2 ⇒ J(δ) ≈ 0.2929.
    // Then R ≤ ~0.00146 ⇒ Δ_bits = log2(1 + R) ≈ 0.002 bits. For larger m or smaller ρ this only decreases.
    let epsilon_3_bits_neg = extension_field_bits
        - log2(
            (2.0 * powf(m + 0.5, 5.0) / (3.0 * powf(rho, 1.5))) * lde_domain_size * batching_factor,
        );
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // epsilon_i for i in [3..(k-1)] (intermediate FRI layers). Using Theorem 5 of IACR ePrint
    // 2021/582 and Theorem 4.2 in IACR ePrint 2025/2055. Noting that t_i are the FRI
    // folding factors, we include for layer j ≥ 0 a contribution of the form
    //   ε_i ≈ ε_3 * (∏_{r=0}^{i-1} 1 / t_r)  and an additive term ~ (n / q).
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    // With fixed folding factor across layers, intermediate errors decrease with layer index.
    // Thus, we bound the entire intermediate range by the first intermediate round (k = 4):
    //   from ε3:            term_from_e3 = ε3_bits_neg
    //   from t_ℓ · C ·(n+1)/q: term_from_n_over_q = ext_bits - log2(folding_factor) - log2(lde_domain_size + 1)
    //                                                 - log2(2m + 1) + 0.5 * log2(ρ)
    let term_from_e3 = epsilon_3_bits_neg;
    let term_from_n_over_q = extension_field_bits
        - log2(folding_factor)
        - log2(lde_domain_size + 1.0)
        - log2(2.0 * m + 1.0)
        + 0.5 * log2(rho);
    let epsilon_i_min_bits_neg = term_from_e3.min(term_from_n_over_q);
    epsilons_bits_neg.push(epsilon_i_min_bits_neg);

    // compute FRI query-phase soundness error
    let epsilon_k_bits_neg = options.grinding_factor() as f64 - log2(powf(alpha, num_fri_queries));
    epsilons_bits_neg.push(epsilon_k_bits_neg);

    // return the round-by-round (RbR) soundness error
    epsilons_bits_neg.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

/// LDR kernel with an explicit per-round grinding schedule. In this variant, fri_query grinding
/// overrides options.grinding_factor; other rounds receive additive bits as per the schedule.
#[allow(clippy::too_many_arguments)]
fn proven_security_protocol_for_given_proximity_parameter_with_schedule(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    m: usize,
    num_constraints: usize,
    num_committed_polys: usize,
    schedule: &GrindingSchedule,
) -> u64 {
    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let m = m as f64;
    let rho = 1.0 / options.blowup_factor() as f64;
    let alpha = (1.0 + 0.5 / m) * sqrt(rho);
    let max_deg = options.blowup_factor() as f64 + 1.0;
    let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
    let trace_domain_size = trace_domain_size as f64;
    let num_openings = 2.0;

    let mut epsilons_bits_neg = vec![];

    // ALI
    let l = m / (rho - (2.0 * m / lde_domain_size));
    let batching_factor = match options.constraint_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic | BatchingMethod::Horner => num_constraints as f64 - 1.0,
    };
    let mut epsilon_1_bits_neg = -log2(l) - log2(batching_factor) + extension_field_bits;
    epsilon_1_bits_neg += schedule.ali as f64;
    epsilons_bits_neg.push(epsilon_1_bits_neg);

    // DEEP
    let mut epsilon_2_bits_neg = -log2(
     l * (max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0)),
    ) + extension_field_bits;
    epsilon_2_bits_neg += schedule.deep as f64;
    epsilons_bits_neg.push(epsilon_2_bits_neg);

    // FRI batching (pre-query)
    let batching_factor = match options.deep_poly_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic | BatchingMethod::Horner => num_committed_polys as f64 - 1.0,
    };
    let mut epsilon_3_bits_neg = extension_field_bits
        - log2(
            (2.0 * powf(m + 0.5, 5.0) / (3.0 * powf(rho, 1.5))) * lde_domain_size * batching_factor,
        );
    epsilon_3_bits_neg += schedule.fri_batching as f64;
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // First intermediate (bounds entire intermediate range for fixed folding factor)
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    let mut epsilon_4_bits_neg = extension_field_bits
        .min(
            // from ε3 (no attenuation at first intermediate)
            epsilon_3_bits_neg,
        )
        .min(
            // additive path with constant C = (2m+1)/sqrt(ρ)
            extension_field_bits
                - log2(folding_factor)
                - log2(lde_domain_size + 1.0)
                - log2(2.0 * m + 1.0)
                + 0.5 * log2(rho),
        );
    epsilon_4_bits_neg += schedule.fri_first_intermediate as f64;
    epsilons_bits_neg.push(epsilon_4_bits_neg);

    // FRI query (override options.grinding_factor)
    let epsilon_k_bits_neg = schedule.fri_query as f64 - log2(powf(alpha, num_fri_queries));
    epsilons_bits_neg.push(epsilon_k_bits_neg);

    epsilons_bits_neg.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

/// Computes proven security level for the specified proof parameters in the unique-decoding regime.
fn proven_security_protocol_unique_decoding(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    num_constraints: usize,
    num_committed_polys: usize,
) -> u64 {
    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
    let trace_domain_size = trace_domain_size as f64;
    let num_openings = 2.0;
    let rho_plus = (trace_domain_size + num_openings) / lde_domain_size;
    let alpha = (1.0 + rho_plus) * 0.5;
    // we use the blowup factor in order to bound the max degree
    let max_deg = options.blowup_factor() as f64 + 1.0;

    // we apply Theorem 3 in https://eprint.iacr.org/2024/1553
    let mut epsilons_bits_neg = vec![];

    // ALI related soundness error. If algebraic/curve batching is used for batching the constraints
    // then there is a loss of log2(C - 1) where C is the total number of constraints.
    let batching_factor = match options.constraint_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic | BatchingMethod::Horner => num_constraints as f64 - 1.0,
    };
    let epsilon_1_bits_neg = -log2(batching_factor) + extension_field_bits;
    epsilons_bits_neg.push(epsilon_1_bits_neg);

    // DEEP related soundness error. Note that this uses that the denominator |F| - |D ∪ H|
    // can be approximated by |F| for all practical domain sizes. We also use the blow-up factor
    // as an upper bound for the maximal constraint degree
    let epsilon_2_bits_neg =
        -log2(max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0))
            + extension_field_bits;
    epsilons_bits_neg.push(epsilon_2_bits_neg);

    // compute FRI commit-phase (i.e., pre-query) soundness error. Note that there is no soundness
    // degradation in the case of linear batching while there is a degradation in the order
    // of log2(N - 1) in the case of algebraic batching, where N is the number of polynomials
    // being batched.
    let batching_factor = match options.deep_poly_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic | BatchingMethod::Horner => num_committed_polys as f64 - 1.0,
    };
    let epsilon_3_bits_neg = extension_field_bits - log2(lde_domain_size * batching_factor);
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // epsilon_i for i in [3..(k-1)], where k is number of rounds
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    let num_fri_layers = options.to_fri_options().num_fri_layers(lde_domain_size as usize);
    let epsilon_i_min_bits_neg = (0..num_fri_layers)
        .map(|_| extension_field_bits - log2((folding_factor - 1.0) * (lde_domain_size + 1.0)))
        .fold(f64::INFINITY, |a, b| a.min(b));
    epsilons_bits_neg.push(epsilon_i_min_bits_neg);

    // compute FRI query-phase soundness error
    let epsilon_k_bits_neg = options.grinding_factor() as f64 - log2(powf(alpha, num_fri_queries));
    epsilons_bits_neg.push(epsilon_k_bits_neg);

    // return the round-by-round (RbR) soundness error
    epsilons_bits_neg.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

#[allow(clippy::too_many_arguments)]
fn proven_security_protocol_unique_decoding_with_schedule(
    options: &ProofOptions,
    base_field_bits: u32,
    trace_domain_size: usize,
    num_constraints: usize,
    num_committed_polys: usize,
    schedule: &GrindingSchedule,
) -> u64 {
    let extension_field_bits = (base_field_bits * options.field_extension().degree()) as f64;
    let num_fri_queries = options.num_queries() as f64;
    let lde_domain_size = (trace_domain_size * options.blowup_factor()) as f64;
    let trace_domain_size = trace_domain_size as f64;
    let num_openings = 2.0;
    let rho_plus = (trace_domain_size + num_openings) / lde_domain_size;
    let alpha = (1.0 + rho_plus) * 0.5;
    let max_deg = options.blowup_factor() as f64 + 1.0;

    let mut epsilons_bits_neg = vec![];

    // ALI
    let batching_factor = match options.constraint_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic | BatchingMethod::Horner => num_constraints as f64 - 1.0,
    };
    let mut epsilon_1_bits_neg = -log2(batching_factor) + extension_field_bits;
    epsilon_1_bits_neg += schedule.ali as f64;
    epsilons_bits_neg.push(epsilon_1_bits_neg);

    // DEEP
    let mut epsilon_2_bits_neg =
        -log2(max_deg * (trace_domain_size + num_openings - 1.0) + (trace_domain_size - 1.0))
            + extension_field_bits;
    epsilon_2_bits_neg += schedule.deep as f64;
    epsilons_bits_neg.push(epsilon_2_bits_neg);

    // FRI batching (commit-like term in UDR)
    let batching_factor = match options.deep_poly_batching_method() {
        BatchingMethod::Linear => 1.0,
        BatchingMethod::Algebraic | BatchingMethod::Horner => num_committed_polys as f64 - 1.0,
    };
    let mut epsilon_3_bits_neg = extension_field_bits - log2(lde_domain_size * batching_factor);
    epsilon_3_bits_neg += schedule.fri_batching as f64;
    epsilons_bits_neg.push(epsilon_3_bits_neg);

    // Intermediate layers (UDR analogue): include the per-layer minimal bound (as before)
    let folding_factor = options.to_fri_options().folding_factor() as f64;
    let _num_fri_layers = options.to_fri_options().num_fri_layers(lde_domain_size as usize);
    let epsilon_i_min_bits_neg = extension_field_bits
        - log2((folding_factor - 1.0) * (lde_domain_size + 1.0));
    let mut epsilon_4_bits_neg = epsilon_i_min_bits_neg;
    epsilon_4_bits_neg += schedule.fri_first_intermediate as f64;
    epsilons_bits_neg.push(epsilon_4_bits_neg);

    // Query phase (override options.grinding_factor)
    let epsilon_k_bits_neg = schedule.fri_query as f64 - log2(powf(alpha, num_fri_queries));
    epsilons_bits_neg.push(epsilon_k_bits_neg);

    epsilons_bits_neg.into_iter().fold(f64::INFINITY, |a, b| a.min(b)) as u64
}

// HELPER FUNCTIONS
// ================================================================================================

/// Computes the largest proximity parameter m such that eta is greater than 0 in the proof of
/// Theorem 1 in https://eprint.iacr.org/2021/582. See Theorem 2 in https://eprint.iacr.org/2024/1553
/// and its proof for more on this point.
///
/// The bound on m in Theorem 2 in https://eprint.iacr.org/2024/1553 is sufficient but we can use
/// the following to compute a better bound.
fn compute_upper_m(h: usize) -> f64 {
    let h = h as f64;
    let ratio = (h + 2.0) / h;
    let m_max = ceil(1.0 / (2.0 * (sqrt(ratio) - 1.0)));
    assert!(m_max >= h / 2.0, "the bound in the theorem should be tighter");

    // We cap the range to 1000 as the optimal m value will be in the lower range of [m_min, m_max]
    // since increasing m too much will lead to a deterioration in the FRI commit soundness making
    // any benefit gained in the FRI query soundess mute.
    cmp::min(m_max as u64, MAX_PROXIMITY_PARAMETER) as f64
}

#[cfg(feature = "std")]
pub fn log2(value: f64) -> f64 {
    value.log2()
}

#[cfg(not(feature = "std"))]
pub fn log2(value: f64) -> f64 {
    libm::log2(value)
}

#[cfg(feature = "std")]
pub fn sqrt(value: f64) -> f64 {
    value.sqrt()
}

#[cfg(not(feature = "std"))]
pub fn sqrt(value: f64) -> f64 {
    libm::sqrt(value)
}

#[cfg(feature = "std")]
pub fn powf(value: f64, exp: f64) -> f64 {
    value.powf(exp)
}

#[cfg(not(feature = "std"))]
pub fn powf(value: f64, exp: f64) -> f64 {
    libm::pow(value, exp)
}

#[cfg(feature = "std")]
pub fn ceil(value: f64) -> f64 {
    value.ceil()
}

#[cfg(not(feature = "std"))]
pub fn ceil(value: f64) -> f64 {
    libm::ceil(value)
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use libc_print::libc_println;
    use math::{fields::f64::BaseElement, StarkField};

    use super::ProofOptions;
    use crate::{proof::security::ProvenSecurity, BatchingMethod, FieldExtension};

    #[test]
    fn get_100_bits_security() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 2;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 4;
        let num_queries = 119;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 100);
        assert_eq!(list_decoding, 94);

        // increasing the queries does not help the LDR case
        let num_queries = 150;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 94);

        // increasing the extension degree does help and we then need fewer queries by virtue
        // of being in LDR
        let field_extension = FieldExtension::Cubic;
        let num_queries = 81;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 100);
    }

    #[test]
    fn unique_decoding_folding_factor_effect() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 2;
        let fri_remainder_max_degree = 7;
        let grinding_factor = 16;
        let blowup_factor = 8;
        let num_queries = 123;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(8);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 116);

        let fri_folding_factor = 4;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 115);
    }

    #[test]
    fn unique_versus_list_decoding_rate_effect() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 2;
        let fri_remainder_max_degree = 7;
        let grinding_factor = 20;
        let blowup_factor = 2;
        let num_queries = 195;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(8);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 100);

        // when the rate is large, going to a larger extension field in order to make full use of
        // being in the LDR might not always be justified

        // we increase the extension degree
        let field_extension = FieldExtension::Cubic;
        // and we reduce the number of required queries to reach the target level, but this is
        // a relatively small, approximately 16%, reduction
        let num_queries = 163;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 100);

        // reducing the rate further changes things
        let field_extension = FieldExtension::Quadratic;
        let blowup_factor = 4;
        let num_queries = 119;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding, list_decoding: _ } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(unique_decoding, 100);

        // the improvement is now at approximately 32%
        let field_extension = FieldExtension::Cubic;
        let num_queries = 81;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 100);
    }

    #[test]
    fn get_96_bits_security() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 4;
        let num_queries = 80;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(18);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 99);

        // increasing the blowup factor should increase the bits of security gained per query
        let blowup_factor = 8;
        let num_queries = 53;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 99);
    }

    #[test]
    fn get_128_bits_security() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 80;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 128);

        // increasing the blowup factor should increase the bits of security gained per query
        let blowup_factor = 16;
        let num_queries = 65;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 128);
    }

    #[test]
    fn grinding_schedule_quadratic_reaches_target() {
        // Show that the grinding schedule planner correctly reaches the target security level
        // in LDR for the quadratic extension case.
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let blowup_factor = 8;
        let num_queries = 65;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 200;
        let num_constraints = 100;

        let options = ProofOptions::new(
            num_queries,
            blowup_factor,
            0, // baseline grinding factor is ignored by schedule variant
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );

        // Plan a schedule to reach 110 bits in LDR and verify it achieves the target.
        let target_bits = 110;
        let (schedule, achieved, _m) = super::plan_grinding_schedule_ldr(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
            target_bits,
        );
libc_println!("schedule {:?}", schedule);
        let ProvenSecurity { unique_decoding: _, list_decoding } =
            ProvenSecurity::compute_with_schedule(
                &options,
                base_field_bits,
                trace_length,
                collision_resistance,
                num_constraints,
                num_committed_polys,
                &schedule,
            );

        // Verify that the planner achieved the target and the computed security matches
        assert_eq!(achieved, target_bits);
        assert_eq!(list_decoding, target_bits);
    }

    #[test]
    fn extension_degree() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 85;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(18);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 94);

        // increasing the extension degree improves the FRI commit phase soundness error and permits
        // reaching 128 bits security
        let field_extension = FieldExtension::Cubic;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity { unique_decoding: _, list_decoding } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(list_decoding, 128);
    }

    #[test]
    fn trace_length() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 80;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        let trace_length = 2_usize.pow(16);

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert!(security_1 <= security_2);
    }

    #[test]
    fn num_fri_queries() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 60;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        let num_queries = 80;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert!(security_1 < security_2);
    }

    #[test]
    fn blowup_factor() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 127;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 30;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(20);
        let num_committed_polys = 2;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        let blowup_factor = 16;

        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert!(security_1 < security_2);
    }

    #[test]
    fn deep_batching_method_udr() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 255;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 120;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(16);
        let num_committed_polys = 1 << 1;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: security_1,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_1, 106);

        // when the FRI batching error is not largest when compared to the other soundness error
        // terms, increasing the number of committed polynomials might not lead to a degradation
        // in the round-by-round soundness of the protocol
        let num_committed_polys = 1 << 2;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 106);

        // but after a certain point, there will be a degradation
        let num_committed_polys = 1 << 5;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 104);

        // and this degradation is on the order of log2(N - 1) where N is the number of
        // committed polynomials
        let num_committed_polys = num_committed_polys << 3;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 101);
    }

    #[test]
    fn deep_batching_method_ldr() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 255;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 120;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(22);
        let num_committed_polys = 1 << 1;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_1, 128);

        // increasing the number of committed polynomials might lead to a degradation
        // in the round-by-round soundness of the protocol on the order of log2(N - 1) where
        // N is the number of committed polynomials. This happens when the FRI batching error
        // is the largest among all errors
        let num_committed_polys = 1 << 8;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Algebraic,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        // with improved Johnson-regime bounds, degradation may occur only for very large N;
        // ensure non-increase when increasing the number of committed polynomials
        assert!(security_2 <= security_1);
    }

    #[test]
    fn constraints_batching_method_udr() {
        let field_extension = FieldExtension::Quadratic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 2;
        let fri_remainder_max_degree = 255;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 120;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(16);
        let num_committed_polys = 1 << 1;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: security_1,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_1, 108);

        // when the total number of constraints is on the order of the size of the LDE domain size
        // there is no degradation in the soundness error when using algebraic/curve batching
        // to batch constraints
        let num_constraints = trace_length * blowup_factor;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 108);

        // but after a certain point, there will be a degradation
        let num_constraints = (trace_length * blowup_factor) << 2;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 107);

        // and this degradation is on the order of log2(C - 1) where C is the total number of
        // constraints
        let num_constraints = num_constraints << 2;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: security_2,
            list_decoding: _,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 105);
    }

    #[test]
    fn constraints_batching_method_ldr() {
        let field_extension = FieldExtension::Cubic;
        let base_field_bits = BaseElement::MODULUS_BITS;
        let fri_folding_factor = 8;
        let fri_remainder_max_degree = 255;
        let grinding_factor = 20;
        let blowup_factor = 8;
        let num_queries = 120;
        let collision_resistance = 128;
        let trace_length = 2_usize.pow(22);
        let num_committed_polys = 1 << 1;
        let num_constraints = 100;

        let mut options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Linear,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_1,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_1, 128);

        // when the total number of constraints is on the order of the size of the LDE domain size
        // square there is no degradation in the soundness error when using algebraic/curve batching
        // to batch constraints
        let num_constraints = (trace_length * blowup_factor).pow(2);
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_2,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_2, 128);

        // and we have a good margin until we see any degradation in the soundness error
        let num_constraints = num_constraints << 12;
        options = ProofOptions::new(
            num_queries,
            blowup_factor,
            grinding_factor,
            field_extension,
            fri_folding_factor as usize,
            fri_remainder_max_degree as usize,
            BatchingMethod::Algebraic,
            BatchingMethod::Linear,
        );
        let ProvenSecurity {
            unique_decoding: _,
            list_decoding: security_3,
        } = ProvenSecurity::compute(
            &options,
            base_field_bits,
            trace_length,
            collision_resistance,
            num_constraints,
            num_committed_polys,
        );

        assert_eq!(security_3, 125);
    }

    #[test]
    fn ldr_lower_order_term_negligible() {
        // Show the lower-order term (proportional to (m + 0.5) * γ * ρ) contributes negligibly
        // to the commit-phase bound in the Johnson regime, using γ ≤ J(δ) = 1 - sqrt(ρ).
        // The bit impact is Δ_bits = log2(1 + R) where R = (3/2) * (γ * ρ) / (m + 0.5)^4.

        // Conservative concrete example from the comment: m = 3, ρ = 1/2.
        let m = 3.0;
        let rho = 0.5;
        let gamma = 1.0 - super::sqrt(rho);
        let a = m + 0.5;
        let r = 1.5 * (gamma * rho) / super::powf(a, 4.0);
        let delta_bits = super::log2(1.0 + r);
        assert!(delta_bits < 0.005);

        // Typical ranges: blowup in {2,4,8,16} ⇒ ρ ∈ {1/2,1/4,1/8,1/16};
        // m in {3,6,12,20}. The bound should stay well below 0.005 bits.
        for blowup in [2_usize, 4, 8, 16] {
            let rho = 1.0 / (blowup as f64);
            let gamma = 1.0 - super::sqrt(rho);
            for m in [3.0_f64, 6.0, 12.0, 20.0] {
                let a = m + 0.5;
                let r = 1.5 * (gamma * rho) / super::powf(a, 4.0);
                let delta_bits = super::log2(1.0 + r);
                assert!(delta_bits < 0.005);
            }
        }
    }
}
