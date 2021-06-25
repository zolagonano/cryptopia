pub struct CryptopiaKDF{
    salt: Vec<u8>,
    log_n: u8,
    r: u32,
    p: u32,
}

pub struct CryptopiaSecret{
    nonce: Vec<u8>,
    key: Vec<u8>,
}

pub struct CryptopiaChunk{
    secret: CryptopiaSecret,
    encrypted_data: Vec<u8>,
}

pub struct CryptopiaHeader{    
    kdf_params: CryptopiaKDF,
    secrets: Vec<CryptopiaSecret>,
}

pub struct CryptopiaFile{
    header: CryptopiaHeader,
}
