use air::ProofOptions;
use crypto::hashers::Rp64_256;
use math::{fields::f64::BaseElement, FieldElement};
use prover::Proof;
use rand::Rng;
use utils::{
    ByteReader, ByteWriter, Deserializable, DeserializationError, Randomizable, Serializable,
};

use crate::stark::{hash, RpoSignature};

// PUBLIC KEY
// ================================================================================================

pub struct PublicKey {
    pk: [BaseElement; 4],
}

impl PublicKey {
    /// Verifies the provided signature against provided message and this public key.
    pub fn verify(&self, message: [BaseElement; 4], signature: &Signature) -> bool {
        signature.verify(message, self.pk)
    }
}

// SECRET KEY
// ================================================================================================

pub struct SecretKey {
    sk: [BaseElement; 4],
}

impl SecretKey {
    pub fn generate_secret_key<R: Rng>(rng: &mut R) -> Self {
        let mut sk = [BaseElement::ZERO; 4];

        let mut dest = vec![0_u8; 8];
        for s in sk.iter_mut() {
            rng.fill_bytes(&mut dest);
            *s = BaseElement::from_random_bytes(&dest).expect("");
        }

        Self { sk }
    }

    pub fn compute_public_key(&self) -> PublicKey {
        let pk = hash(self.sk);
        PublicKey { pk }
    }

    pub fn sign(&self, message: [BaseElement; 4]) -> Signature {
        let options = get_proof_options();
        let signature: RpoSignature<Rp64_256> = RpoSignature::new(options);
        let proof = signature.sign(self.sk, message);
        Signature { proof }
    }
}

// SIGNATURE
// ================================================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    proof: Proof,
}

impl Signature {
    /// Returns true if this signature is a valid signature for the specified message generated
    /// against the secret key matching the specified public key commitment.
    pub fn verify(&self, message: [BaseElement; 4], pk: [BaseElement; 4]) -> bool {
        let options = get_proof_options();
        let signature: RpoSignature<Rp64_256> = RpoSignature::new(options);

        signature.verify(pk, message, self.proof.clone()).is_ok()
    }
}

fn get_proof_options() -> ProofOptions {
    ProofOptions::new(80, 8, 16, ::air::FieldExtension::Cubic, 8, 255, true)
}

// SERIALIZATION / DESERIALIZATION
// ================================================================================================

impl Serializable for PublicKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.pk.write_into(target);
    }
}

impl Deserializable for PublicKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let pk = <[BaseElement; 4]>::read_from(source)?;
        Ok(Self { pk })
    }
}

impl Serializable for SecretKey {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.sk.write_into(target);
    }
}

impl Deserializable for SecretKey {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let sk = <[BaseElement; 4]>::read_from(source)?;
        Ok(Self { sk })
    }
}

impl Serializable for Signature {
    fn write_into<W: ByteWriter>(&self, target: &mut W) {
        self.proof.write_into(target);
    }
}

impl Deserializable for Signature {
    fn read_from<R: ByteReader>(source: &mut R) -> Result<Self, DeserializationError> {
        let proof = Proof::read_from(source)?;
        Ok(Self { proof })
    }
}

#[test]
fn test_signature() {
    use rand::thread_rng;
    use rand_utils::rand_array;

    let mut rng = thread_rng();
    let sk = SecretKey::generate_secret_key(&mut rng);

    let message = rand_array();
    let signature = sk.sign(message);
    println!("signature size is {:?} bytes", signature.to_bytes().len());
    println!("security level {:?} bits", signature.proof.security_level::<Rp64_256>(false));

    let pk = sk.compute_public_key();
    assert!(pk.verify(message, &signature))
}
