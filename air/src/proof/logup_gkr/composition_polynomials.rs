use math::{polynom::MultiLinearPoly, FieldElement};

pub fn evaluate_composition_poly<E: FieldElement>(
    numerators: &[E],
    denominators: &[E],
    eq_eval: E,
    r_sum_check: E,
    tensored_merge_randomness: &[E],
) -> E {
    let numerators = MultiLinearPoly::from_evaluations(numerators.to_vec()).unwrap();
    let denominators = MultiLinearPoly::from_evaluations(denominators.to_vec()).unwrap();

    let (left_numerators, right_numerators) = numerators.project_least_significant_variable();
    let (left_denominators, right_denominators) = denominators.project_least_significant_variable();

    let eval_left_numerators =
        left_numerators.evaluate_with_lagrange_kernel(&tensored_merge_randomness);
    let eval_right_numerators =
        right_numerators.evaluate_with_lagrange_kernel(&tensored_merge_randomness);

    let eval_left_denominators =
        left_denominators.evaluate_with_lagrange_kernel(&tensored_merge_randomness);
    let eval_right_denominators =
        right_denominators.evaluate_with_lagrange_kernel(&tensored_merge_randomness);

    eq_eval
        * ((eval_left_numerators * eval_right_denominators
            + eval_right_numerators * eval_left_denominators)
            + eval_left_denominators * eval_right_denominators * r_sum_check)
}
