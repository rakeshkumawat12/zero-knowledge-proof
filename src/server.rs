mod zkp_auth {
    include!("./zkp_auth.rs");
}
use num_bigint::BigUint;
use std::{collections::HashMap, sync::Mutex};
use tonic::{Code, Response, Status, transport::Server};
use ZKP::ChaumPedersenZKP;

use zkp_auth::{
    ChallengeAnswerRequest, ChallengeAnswerResponse, ChallengeRequest, ChallengeResponse,
    RegisterRequest, RegisterResponse,
    zkp_auth_service_server::{ZkpAuthService, ZkpAuthServiceServer},
};

#[derive(Debug, Default)]
struct UserZKPData {
    username: String,
    public_y1: BigUint,
    public_y2: BigUint,
    commitment_t1: BigUint,
    commitment_t2: BigUint,
    challenge_c: BigUint,
}

#[derive(Debug, Default)]
struct AuthService {
    user_registry: Mutex<HashMap<String, UserZKPData>>,
    auth_sessions: Mutex<HashMap<String, String>>,
}

#[tonic::async_trait]
impl ZkpAuthService for AuthService {
    async fn register(
        &self,
        request: tonic::Request<RegisterRequest>,
    ) -> std::result::Result<tonic::Response<RegisterResponse>, tonic::Status> {
        let req = request.into_inner();
        let user_name = req.username;
        let public_y1 = BigUint::from_bytes_be(&req.public_y1);
        let public_y2 = BigUint::from_bytes_be(&req.public_y2);

        let mut user_info = UserZKPData::default();
        user_info.username = user_name.clone();
        user_info.public_y1 = public_y1;
        user_info.public_y2 = public_y2;

        let user_info_hashmap = &mut self.user_registry.lock().unwrap();
        user_info_hashmap.insert(user_name.clone(), user_info);
        Ok(Response::new(RegisterResponse {
            message: format!("User {} registration successful", user_name),
        }))
    }
    async fn request_challenge(
        &self,
        request: tonic::Request<ChallengeRequest>,
    ) -> std::result::Result<tonic::Response<ChallengeResponse>, tonic::Status> {
        let req = request.into_inner();
        let user_name = req.username;

        let user_info_hashmap = &mut self.user_registry.lock().unwrap();
        if let Some(user_info) = user_info_hashmap.get_mut(&user_name) {
            let (_, _, _, subgroup_q) = ChaumPedersenZKP::get_standard_parameters();
            let challenge_c = ChaumPedersenZKP::random_biguint_below(&subgroup_q);
            let auth_id = ChaumPedersenZKP::random_alphanumeric_string(12);

            let commitment_t1 = req.commitment_t1;
            let commitment_t2 = req.commitment_t2;
            user_info.challenge_c = challenge_c.clone();
            user_info.commitment_t1 = BigUint::from_bytes_be(&commitment_t1);
            user_info.commitment_t2 = BigUint::from_bytes_be(&commitment_t2);

            let auth_sessions_hashmap = &mut self.auth_sessions.lock().unwrap();
            auth_sessions_hashmap.insert(auth_id.clone(), user_name);
            Ok(Response::new(ChallengeResponse {
                auth_id,
                challenge_c: challenge_c.to_bytes_be(),
            }))
        } else {
            return Err(Status::new(
                Code::NotFound,
                format!("User: {} not found in hashmap", user_name),
            ));
        }
    }
    async fn submit_challenge_answer(
        &self,
        request: tonic::Request<ChallengeAnswerRequest>,
    ) -> std::result::Result<tonic::Response<ChallengeAnswerResponse>, tonic::Status> {
        let req = request.into_inner();
        let auth_id = req.auth_id;

        let auth_id_to_user_hashmap = &mut self.auth_sessions.lock().unwrap();
        if let Some(user_name) = auth_id_to_user_hashmap.get(&auth_id) {
            let user_info_hashmap = &mut self.user_registry.lock().unwrap();
            let user_info = user_info_hashmap
                .get_mut(user_name)
                .expect("auth_id not found");

            let response_s = BigUint::from_bytes_be(&req.response_s);

            let (generator_g, generator_h, modulus_p, subgroup_order_q) =
                ChaumPedersenZKP::get_standard_parameters();
            let zkp = ChaumPedersenZKP {
                modulus_p,
                subgroup_order_q,
                generator_g,
                generator_h,
            };
            let verification = zkp.verify_proof(
                &user_info.commitment_t1,
                &user_info.commitment_t2,
                &user_info.public_y1,
                &user_info.public_y2,
                &user_info.challenge_c,
                &response_s,
            );
            if verification {
                let session_id = ChaumPedersenZKP::random_alphanumeric_string(12);
                return Ok(Response::new(ChallengeAnswerResponse { session_id }));
            } else {
                return Err(Status::new(
                    Code::PermissionDenied,
                    format!(
                        "User: {} sent a wrong solution to the challenge",
                        user_info.username
                    ),
                ));
            }
        } else {
            return Err(Status::new(
                Code::NotFound,
                format!("User: {} not found in database", auth_id),
            ));
        }
    }
}
#[tokio::main]
async fn main() {
    let address = "127.0.0.1:50051".to_string();
    println!("Running the server at {}", address);
    let auth_impl = AuthService::default();
    Server::builder()
        .add_service(ZkpAuthServiceServer::new(auth_impl))
        .serve(address.parse().expect("Could not convert the address"))
        .await
        .unwrap()
}