use num_bigint::BigUint;
use std::io::stdin;
pub mod zkp_auth {
    include!("./zkp_auth.rs");
}
use ZKP::ChaumPedersenZKP;
use zkp_auth::{
    ChallengeAnswerRequest, ChallengeRequest, RegisterRequest,
    zkp_auth_service_client::ZkpAuthServiceClient,
};

#[tokio::main]
async fn main() {
    let (generator_g, generator_h, modulus_p, subgroup_order_q) =
        ChaumPedersenZKP::get_standard_parameters();
    let zkp = ChaumPedersenZKP {
        modulus_p: modulus_p.clone(),
        subgroup_order_q: subgroup_order_q.clone(),
        generator_g: generator_g.clone(),
        generator_h: generator_h.clone(),
    };
    //1. Connecting to the server
    println!("***Connecting... to the server***");
    let mut client = ZkpAuthServiceClient::connect("http://127.0.0.1:50051")
        .await
        .expect("could not connect to the server");

    //2. Registration Process
    println!("***Registration Process started**");
    let mut input = String::new();
    println!("Please provide the username");
    stdin()
        .read_line(&mut input)
        .expect("Could not get the username from stdin");
    let username = input.trim().to_string();
    input.clear();

    println!("Please provide the password (for registration)");
    stdin()
        .read_line(&mut input)
        .expect("Could not get the username from stdin");
    let password = BigUint::from_bytes_be(input.trim().as_bytes());

    input.clear();

    let public_y1 = ChaumPedersenZKP::mod_exp(&generator_g, &password, &modulus_p);
    let public_y2 = ChaumPedersenZKP::mod_exp(&generator_h, &password, &modulus_p);

    let request = RegisterRequest {
        username: username.clone(),
        public_y1: public_y1.to_bytes_be(), // generator_g^x mod p
        public_y2: public_y2.to_bytes_be(), // generator_h^x mod p
    };
    let response = client
        .register(request)
        .await
        .expect("Could not register in server");
    println!("Response: {}", response.get_ref().message);

    //3. Login Process
    //a. Challenge Request
    println!("***Login Process started**");
    println!("Please provide the password(to login)");
    stdin()
        .read_line(&mut input)
        .expect("Could not get the username from stdin");
    let password = BigUint::from_bytes_be(input.trim().as_bytes());
    input.clear();

    let nonce_r = ChaumPedersenZKP::random_biguint_below(&subgroup_order_q);
    let commitment_t1 = ChaumPedersenZKP::mod_exp(&generator_g, &nonce_r, &modulus_p);
    let commitment_t2 = ChaumPedersenZKP::mod_exp(&generator_h, &nonce_r, &modulus_p);
    println!("***Requesting for challenge**");
    let request = ChallengeRequest {
        username: username,
        commitment_t1: commitment_t1.to_bytes_be(),
        commitment_t2: commitment_t2.to_bytes_be(),
    };
    let response = client
        .request_challenge(request)
        .await
        .expect("Could not request challenge in server")
        .into_inner();

    println!("{:?}", response);

    //b. Challenge Response
    println!("***Solving the challenge**");
    let auth_id = response.auth_id;
    let challenge_c = BigUint::from_bytes_be(&response.challenge_c);
    let solution_to_challenge = zkp.compute_response(&nonce_r, &challenge_c, &password);
    let request = ChallengeAnswerRequest {
        auth_id,
        response_s: solution_to_challenge.to_bytes_be(),
    };
    let response = client
        .submit_challenge_answer(request)
        .await
        .expect("Could not verify in server")
        .into_inner();
    println!("You logged in, session_id:{}", response.session_id);
}