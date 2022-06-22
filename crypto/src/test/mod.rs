use super::{
    hashers::{
        Rp64_256, Rp_64_1, Rp_64_2, Rp_64_3, Rp_64_4, Rp_64_5, Rp_64_6, Rp_64m_256, Rp_64m_3,
    },
    Hasher,
};
use math::{fields::f64m::BaseElement as BaseElement64m, StarkField};
use math::{fields::f64::BaseElement as BaseElement64};

#[test]
fn montgomery_fft() {
    /*
        let mut state: [BaseElement64; 12] = [
            BaseElement64::new(0),
            BaseElement64::new(1),
            BaseElement64::new(2),
            BaseElement64::new(3),
            BaseElement64::new(4),
            BaseElement64::new(5),
            BaseElement64::new(6),
            BaseElement64::new(7),
            BaseElement64::new(8),
            BaseElement64::new(9),
            BaseElement64::new(10),
            BaseElement64::new(11),
        ];

        let mut state_: [BaseElement64; 12] = [
            BaseElement64::new(0),
            BaseElement64::new(1),
            BaseElement64::new(2),
            BaseElement64::new(3),
            BaseElement64::new(4),
            BaseElement64::new(5),
            BaseElement64::new(6),
            BaseElement64::new(7),
            BaseElement64::new(8),
            BaseElement64::new(9),
            BaseElement64::new(10),
            BaseElement64::new(11),
        ];
        Rp64_256::apply_permutation(&mut state);
        Rp64_256::apply_permutation_freq_original(&mut state_);
    */
    use rand_utils::rand_array;

    for _ in 0..10000 {
        let mut s1: [BaseElement64; 12] = rand_array();
        let mut s2: [BaseElement64; 12] = s1.clone();
        let mut s3: [BaseElement64m; 12] = convert_to_montgomery(&s1.clone());
        let mut s4: [BaseElement64m; 12] = convert_to_montgomery(&s2.clone());

        Rp64_256::apply_permutation(&mut s1);
        Rp64_256::apply_permutation_freq_original(&mut s2);
        Rp_64m_256::apply_permutation(&mut s3);
        Rp_64m_256::apply_permutation_freq_original(&mut s4);

        assert_eq!(s1, s2); // Check correctness of MDS multiplication in frequency domain for f64
        assert_eq!(s3, s4); // Check correctness of MDS multiplication in frequency domain for f64m

        // Since we have to transform back from the Montgomery representation in order to compare the implementations
        // for f64 and f64m, we do the following:
        for i in 0..12 {
            assert_eq!(s1[i].as_int(), s3[i].as_int());
            assert_eq!(s2[i].as_int(), s4[i].as_int()); // Redundant check given the previous ones
            eprintln!(
                "{:?} {:?} {:?} {:?}",
                s1[i].as_int(),
                s2[i].as_int(),
                s3[i].as_int(),
                s4[i].as_int()
            );
        }
    }
}

pub fn convert_to_montgomery(s: &[BaseElement64; 12]) -> [BaseElement64m; 12] {
    let mut result = [BaseElement64m::new(0); 12];
    for i in 0..12 {
        result[i] = BaseElement64m::new(s[i].0);
    }
    return result;
}
