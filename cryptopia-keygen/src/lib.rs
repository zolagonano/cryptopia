use scrypt::{scrypt, Params};

const RECOMMENDED_N: u8 = 20;
const RECOMMENDED_R: u32 = 8;
const RECOMMENDED_P: u32 = 1;

pub enum WorkFactor {
    Recommended,
    Balanced(usize),
    Custom(u8, u32, u32),
}

impl WorkFactor {
    fn get_scrypt_params(&self) -> Params {
        let recommended_params = Params::new(RECOMMENDED_N, RECOMMENDED_R, RECOMMENDED_P);

        let scrypt_params = match self {
            WorkFactor::Recommended => recommended_params,
            WorkFactor::Balanced(memory_avail) => {
                let log_n = (*memory_avail as f64 / 128f64 / RECOMMENDED_R as f64).log2() as u8;
                if log_n < RECOMMENDED_N {
                    let p = (2u32.pow(RECOMMENDED_N as u32) / 2u32.pow(log_n as u32)) as u32;
                    Params::new(log_n, RECOMMENDED_R, p)
                } else {
                    recommended_params
                }
            }
            WorkFactor::Custom(log_n, r, p) => Params::new(*log_n, *r, *p),
        };

        scrypt_params.unwrap()
    }
}

// TODO: Implement new function
pub struct KeyParams {
    pub work_factor: WorkFactor,
    pub passphrase: Vec<u8>,
    pub salt: Vec<u8>,
    pub key_len: u32,
}

pub enum KdfAlgo {
    Scrypt,
}

impl KdfAlgo {
    pub fn keygen(&self, key_params: &KeyParams) -> Result<Vec<u8>, String> {
        match self {
            KdfAlgo::Scrypt => Self::keygen_scrypt(&key_params),
        }
    }

    fn keygen_scrypt(key_params: &KeyParams) -> Result<Vec<u8>, String> {
        let scrypt_params = key_params.work_factor.get_scrypt_params();

        let mut buffer = vec![0u8; key_params.key_len as usize];

        let scrypt_result = scrypt(
            &key_params.passphrase,
            &key_params.salt,
            &scrypt_params,
            &mut buffer,
        );

        match scrypt_result {
            Ok(_) => Ok(buffer),
            Err(e) => Err(e.to_string()), /*TODO: Use an Enum for Errors*/
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{KdfAlgo, KeyParams, WorkFactor};

    #[test]
    fn balanced() {
        let passphrase = b"Kubn1xG4ps".to_vec();
        let salt = b"AFyIoGyDLJ3Yk2Z6HQKK077524q0E7SOkE6gT4dcd".to_vec();

        // balanced parameters for 33554432 bytes of available RAM:
        // N = 32768 (2^15)
        // r = 8
        // p = 32

        let work_factor = WorkFactor::Balanced(33554432);
        let key_params = KeyParams {
            work_factor,
            passphrase,
            salt,
            key_len: 10,
        };

        let key = KdfAlgo::Scrypt.keygen(&key_params).unwrap();
        let expected_result = vec![137, 142, 34, 170, 170, 102, 59, 225, 3, 53];

        assert_eq!(expected_result, key);
    }
}
