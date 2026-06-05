//! The traits representing the basic elliptic curve operations.
//!
//! These traits are instantiatable by all the commonly used elliptic curves and should help in
//! organizing syscall support for other curves in the future. More complicated or curve-specific
//! functions that are needed in cryptographic applications should be representable by combining
//! the associated functions of these traits.

// Functions are organized by the curve traits, which can be instantiated by multiple curve
// representations. The functions take in a `curve_id` (e.g. `CURVE25519_EDWARDS`) and should run
// the associated functions in the appropriate trait instantiation. The `curve_op` function
// additionally takes in an `op_id` (e.g. `ADD`) that controls which associated functions to run in
// `GroupOperations`.

pub trait PointValidation {
    type Point;

    /// Verifies if a byte representation of a curve point lies in the curve.
    fn validate_point(&self) -> bool;
}

pub trait GroupOperations {
    type Point;
    type Scalar;

    /// Adds two curve points: P_0 + P_1.
    fn add(left_point: &Self::Point, right_point: &Self::Point) -> Option<Self::Point>;

    /// Subtracts two curve points: P_0 - P_1.
    fn subtract(left_point: &Self::Point, right_point: &Self::Point) -> Option<Self::Point>;

    /// Multiplies a scalar S with a curve point P: S*P
    fn multiply(scalar: &Self::Scalar, point: &Self::Point) -> Option<Self::Point>;
}

pub trait MultiScalarMultiplication {
    type Scalar;
    type Point;

    /// Given a vector of scalars S_1, ..., S_N, and curve points P_1, ..., P_N, computes the
    /// "inner product": S_1*P_1 + ... + S_N*P_N.
    fn multiscalar_multiply(
        scalars: &[Self::Scalar],
        points: &[Self::Point],
    ) -> Option<Self::Point>;
}

pub trait Pairing {
    type G1Point;
    type G2Point;
    type GTPoint;

    /// Applies the bilinear pairing operation to two curve points P1, P2 -> e(P1, P2). This trait
    /// is only relevant for "pairing-friendly" curves such as BN254 and BLS12-381.
    fn pairing_map(
        left_point: &Self::G1Point,
        right_point: &Self::G2Point,
    ) -> Option<Self::GTPoint>;
}

pub const CURVE25519_EDWARDS: u64 = 0;
pub const CURVE25519_RISTRETTO: u64 = 1;

pub const ADD: u64 = 0;
pub const SUB: u64 = 1;
pub const MUL: u64 = 2;
