use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

pub struct ChaunPedersonZKP {
    pub generator_g: BigUint,
    pub generator_h: BigUint,
    pub modulus_p: BigUint,
    pub subgroup_order_q: BigUint,
}

impl ChaunPedersonZKP {
    pub fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) {
        base.modpow(exponent, modulus);
    }

    pub fn rand_bigUint_below(bound: &BigUint) -> BigUint {
        let mut rng = thread_rng();
        rng.gen_biguint_below(bound)
    }

    pub fn compute_response(
        &self,
        nounce_r: BigUint,
        challenge_c: BigUint,
        secret_x: BigUint,
    ) -> BigUint {
        let cx = challenge_c * secret_x;
        let exponent = BigUint::from(1u32);
        if nounce_r >= cx {
            return (nounce_r - cx).modpow(&exponent, &self.subgroup_order_q);
        } else {
            return &self.subgroup_order_q
                - (cx - nounce_r).modpow(&exponent, &self.subgroup_order_q);
        }
    }

    pub fn verify_proof(
        &self,
        commitment_t1: &BigUint,
        commitment_t2: &BigUint,
        response_s: &BigUint,
        challenge_c: &BigUint,
        public_y1: &BigUint,
        public_y2: &BigUint,
    ) -> bool {
        let lhs_one = commitment_t1;
        let lhs_two = commitment_t2;

        let rhs_one = &self.generator_g.modpow(&response_s, &self.modulus_p)  * public_y1.modpow(&challenge_c, &self.modulus_p);

        let rhs_two = &self.generator_h.modpow(&response_s, &self.modulus_p)  * public_y2.modpow(&challenge_c, &self.modulus_p);

        *lhs_one == rhs_one && *lhs_two == rhs_two
    }
}
