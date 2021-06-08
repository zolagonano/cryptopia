use scrypt::{scrypt, Params};

pub enum WorkFactor {
    Recommended,
    Balanced(usize),
    Custom(u8, u32, u32),
}

pub fn keygen(
    work_factor: &WorkFactor,
    passphrase: &[u8],
    salt: &[u8],
    key_len: u32,
) -> Result<Vec<u8>, String> {
    let scrypt_params = match work_factor {
        WorkFactor::Recommended => Params::new(20, 8, 1),
        WorkFactor::Balanced(memory_avail) => {
            let log_n = (*memory_avail as f64 / 128f64 / 8f64).log2() as u8;
            if log_n < 20 {
                let p = (2u32.pow(20) / 2u32.pow(log_n as u32)) as u32;
                Params::new(log_n, 8, p)
            } else {
                Params::new(20, 8, 1)
            }
        }
        WorkFactor::Custom(log_n, r, p) => Params::new(*log_n, *r, *p),
    };

    if let Err(e) = &scrypt_params {
        return Err(e.to_string());
    }

    let mut buffer = vec![0u8; key_len as usize];

    let scrypt_result = scrypt(passphrase, salt, &scrypt_params.unwrap(), &mut buffer);

    if let Err(e) = scrypt_result {
        return Err(e.to_string());
    }

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::{keygen, WorkFactor};

    #[test]
    fn balanced() {
        let passphrase = b"Kubn1xG4ps";
        let salt = b"AFyIoGyDLJ3Yk2Z6HQKK077524q0E7SOkE6gT4dcd";

        // balanced parameters for 33554432 bytes of available RAM:
        // N = 32768 (2^15)
        // r = 8
        // p = 32
        let key = keygen(&WorkFactor::Balanced(33554432), passphrase, salt, 10).unwrap();

        let expected_result = vec![137, 142, 34, 170, 170, 102, 59, 225, 3, 53];

        assert_eq!(expected_result, key);
    }
}
