use hex;
use num_bigint::{BigUint, RandBigInt};
use rand::{Rng, thread_rng};

pub struct ChaumPedersenZKP {
    pub generator_g: BigUint,
    pub generator_h: BigUint,
    pub modulus_p: BigUint,
    pub subgroup_order_q: BigUint,
}

impl ChaumPedersenZKP {
    //base^exponent mod modulus
    //10^5 mod 23
    pub fn mod_exp(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        base.modpow(exponent, modulus)
    }

    pub fn random_biguint_below(bound: &BigUint) -> BigUint {
        let mut rng = thread_rng();
        rng.gen_biguint_below(bound)
    }
    // s = nonce_r - challenge_c * secret_x mod subgroup_order_q if nonce_r> challenge_c * secret_x
    // s = subgroup_order_q + nonce_r - challenge_c * secret_x mod subgroup_order_q
    pub fn compute_response(
        &self,
        nonce_r: &BigUint,
        challenge_c: &BigUint,
        secret_x: &BigUint,
    ) -> BigUint {
        let cx = challenge_c * secret_x; //20
        let exponent = BigUint::from(1u32);
        if *nonce_r >= cx {
            return (nonce_r - cx)
                .modpow(&exponent, &self.subgroup_order_q)
         
        } else {
            return &self.subgroup_order_q
                - (cx - nonce_r).modpow(&exponent, &self.subgroup_order_q);
        }
    }
    /// Verifies the ZKP:
    /// checks:
    /// t1 == (g^s mod p * y1^c mod p) mod p
    /// t2 == h^s * y2^c mod p
    pub fn verify_proof(
        &self,
        commitment_t1: &BigUint,
        commitment_t2: &BigUint,
        public_y1: &BigUint,
        public_y2: &BigUint,
        response_s: &BigUint,
        challenge_c: &BigUint,
    ) -> bool {
        let lhs_one = commitment_t1;
        let lhs_two = commitment_t2;

        let rhs_one = (&self.generator_g.modpow(&response_s, &self.modulus_p)
            * public_y1.modpow(&challenge_c, &self.modulus_p))
        .modpow(&BigUint::from(1u32), &self.modulus_p);

        let rhs_two = (&self.generator_h.modpow(response_s, &self.modulus_p)
            * public_y2.modpow(challenge_c, &self.modulus_p))
        .modpow(&BigUint::from(1u32), &self.modulus_p);

        *lhs_one == rhs_one && *lhs_two == rhs_two
    }

    // Returns standard constants (1024-bit p, q and generators alpha, beta)
    pub fn get_standard_parameters() -> (BigUint, BigUint, BigUint, BigUint) {
        let generator_g_bytes = hex::decode("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5").unwrap();
        let modulus_p_bytes = hex::decode("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371").unwrap();
        let subgroup_q_bytes = hex::decode("F518AA8781A8DF278ABA4E7D64B7CB9D49462353").unwrap();

        let generator_g = BigUint::from_bytes_be(&generator_g_bytes);
        let modulus_p = BigUint::from_bytes_be(&modulus_p_bytes);
        let subgroup_q = BigUint::from_bytes_be(&subgroup_q_bytes);

        let exp = BigUint::from_bytes_be(&hex::decode("266D31266FEA1E5C41564B777E69").unwrap());
        let generator_h = generator_g.modpow(&exp, &modulus_p);

        (generator_g, generator_h, modulus_p, subgroup_q)
    }
    pub fn random_alphanumeric_string(length: usize) -> String {
        thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(length)
            .map(char::from)
            .collect()
    }
}

#[cfg(test)]

mod test {
    use super::*;

    #[test]
    fn test_with_fixed_values() {
        let modulus_p = BigUint::from(23u32);
        let subgroup_order_q = BigUint::from(11u32);
        let generator_g = BigUint::from(2u32);
        let generator_h = BigUint::from(3u32);
        let secret_x = BigUint::from(4u32);
        let challenge_c = BigUint::from(5u32);

        let public_y1 = ChaumPedersenZKP::mod_exp(&generator_g, &secret_x, &modulus_p);
        let public_y2 = ChaumPedersenZKP::mod_exp(&generator_h, &secret_x, &modulus_p);
        assert!(public_y1 == BigUint::from(16u32));
        assert!(public_y2 == BigUint::from(12u32));

        //let nonce_r = ChaumPedersenZKP::random_biguint_below(&subgroup_order_q);
        let commitment_t1 =
            ChaumPedersenZKP::mod_exp(&generator_g, &BigUint::from(6u32), &modulus_p);
        let commitment_t2 =
            ChaumPedersenZKP::mod_exp(&generator_h, &BigUint::from(6u32), &modulus_p);

        assert!(commitment_t1 == BigUint::from(18u32));
        assert!(commitment_t2 == BigUint::from(16u32));

        let zkp = ChaumPedersenZKP {
            modulus_p,
            subgroup_order_q,
            generator_g,
            generator_h,
        };
        let response_s = zkp.compute_response(&BigUint::from(6u32), &challenge_c, &secret_x);
        assert!(response_s == BigUint::from(8u32));

        let result = zkp.verify_proof(
            &commitment_t1,
            &commitment_t2,
            &public_y1,
            &public_y2,
            &response_s,
            &challenge_c,
        );
        assert!(result == true);
    }

    #[test]
    fn test_with_dynamic_values() {
        let modulus_p = BigUint::from(23u32);
        let subgroup_order_q = BigUint::from(11u32);
        let generator_g = BigUint::from(2u32);
        let generator_h = BigUint::from(3u32);
        let secret_x = BigUint::from(4u32);
        let challenge_c = BigUint::from(5u32);

        let public_y1 = ChaumPedersenZKP::mod_exp(&generator_g, &secret_x, &modulus_p);
        let public_y2 = ChaumPedersenZKP::mod_exp(&generator_h, &secret_x, &modulus_p);
        assert!(public_y1 == BigUint::from(16u32));
        assert!(public_y2 == BigUint::from(12u32));

        let nonce_r = ChaumPedersenZKP::random_biguint_below(&subgroup_order_q);
        let commitment_t1 = ChaumPedersenZKP::mod_exp(&generator_g, &nonce_r, &modulus_p);
        let commitment_t2 = ChaumPedersenZKP::mod_exp(&generator_h, &nonce_r, &modulus_p);

        let zkp = ChaumPedersenZKP {
            modulus_p,
            subgroup_order_q,
            generator_g,
            generator_h,
        };
        let response_s = zkp.compute_response(&nonce_r, &challenge_c, &secret_x);

        let result = zkp.verify_proof(
            &commitment_t1,
            &commitment_t2,
            &public_y1,
            &public_y2,
            &response_s,
            &challenge_c,
        );
        assert!(result == true);
    }
    #[test]
    fn test_with_random_values() {
        let modulus_p = BigUint::from(23u32);
        let subgroup_order_q = BigUint::from(11u32);
        let generator_g = BigUint::from(2u32);
        let generator_h = BigUint::from(3u32);

        let zkp = ChaumPedersenZKP {
            modulus_p: modulus_p.clone(),
            subgroup_order_q: subgroup_order_q.clone(),
            generator_g: generator_g.clone(),
            generator_h: generator_h.clone(),
        };

        for _ in 0..10 {
            let mut rng = thread_rng();

            let secret_x = rng.gen_biguint_below(&subgroup_order_q);
            let challenge_c = rng.gen_biguint_below(&subgroup_order_q);
            let nonce_r = rng.gen_biguint_below(&subgroup_order_q);

            let public_y1 = ChaumPedersenZKP::mod_exp(&generator_g, &secret_x, &modulus_p);
            let public_y2: BigUint = ChaumPedersenZKP::mod_exp(&generator_h, &secret_x, &modulus_p);

            let commitment_t1 = ChaumPedersenZKP::mod_exp(&generator_g, &nonce_r, &modulus_p);
            let commitment_t2 = ChaumPedersenZKP::mod_exp(&generator_h, &nonce_r, &modulus_p);

            let response_s = zkp.compute_response(&nonce_r, &challenge_c, &secret_x);

            let result = zkp.verify_proof(
                &commitment_t1,
                &commitment_t2,
                &public_y1,
                &public_y2,
                &response_s,
                &challenge_c,
            );

            assert!(
                result,
                "ZKP failed for random test case:\n\
            secret_x = {}\nchallenge_c = {}\nnonce_r = {}\nresponse_s = {}",
                secret_x, challenge_c, nonce_r, response_s
            );
        }
    }
}