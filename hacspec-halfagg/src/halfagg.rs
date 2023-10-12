//! WARNING: This specification is EXPERIMENTAL and has _not_ received adequate
//! security review.

use hacspec_bip_340::*;
use hacspec_lib::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidPublicKey(usize),
    InvalidSignature,
    AggSigTooBig,
    MalformedSignature,
}

pub type AggSig = ByteSeq;

public_bytes!(TaggedHashHalfAggPrefix, 18);
// string "HalfAgg/randomizer"
const HALFAGG_RANDOMIZER: TaggedHashHalfAggPrefix = TaggedHashHalfAggPrefix([
    0x48u8, 0x61u8, 0x6cu8, 0x66u8, 0x41u8, 0x67u8, 0x67u8, 0x2fu8, 0x72u8, 0x61u8, 0x6eu8, 0x64u8,
    0x6fu8, 0x6du8, 0x69u8, 0x7au8, 0x65u8, 0x72u8,
]);
pub fn hash_halfagg(input: &Seq<(PublicKey, Message, Bytes32)>) -> Bytes32 {
    let mut c = ByteSeq::new(0);
    for i in 0..input.len() {
        let (pk, msg, rx) = input[i];
        c = c.concat(&rx).concat(&pk).concat(&msg);
    }
    tagged_hash(&PublicByteSeq::from_seq(&HALFAGG_RANDOMIZER), &c)
}

pub type AggregateResult = Result<AggSig, Error>;
pub fn aggregate(pms: &Seq<(PublicKey, Message, Signature)>) -> AggregateResult {
    let aggsig = AggSig::new(32);
    inc_aggregate(&aggsig, &Seq::<(PublicKey, Message)>::new(0), pms)
}

pub fn inc_aggregate(
    aggsig: &AggSig,
    pm_aggd: &Seq<(PublicKey, Message)>,
    pms_to_agg: &Seq<(PublicKey, Message, Signature)>,
) -> AggregateResult {
    let (sum, overflow) = pm_aggd.len().overflowing_add(pms_to_agg.len());
    if overflow || sum > 0xffff {
        AggregateResult::Err(Error::AggSigTooBig)?;
    }
    if aggsig.len() != 32 * (pm_aggd.len() + 1) {
        AggregateResult::Err(Error::MalformedSignature)?;
    }
    let v = aggsig.len() / 32 - 1;
    let u = pms_to_agg.len();
    let mut pmr = Seq::<(PublicKey, Message, Bytes32)>::new(v + u);
    for i in 0..v {
        let (pk, msg) = pm_aggd[i];
        pmr[i] = (pk, msg, Bytes32::from_slice(aggsig, 32 * i, 32));
    }
    let mut s = scalar_from_bytes_strict(Bytes32::from_seq(&aggsig.slice(32 * v, 32)))
        .ok_or(Error::MalformedSignature)?;

    for i in v..v + u {
        let (pk, msg, sig) = pms_to_agg[i - v];
        pmr[i] = (pk, msg, Bytes32::from_slice(&sig, 0, 32));
        // TODO: The following line hashes i elements and therefore leads to
        // quadratic runtime. Instead, we should cache the intermediate result
        // and only hash the new element.
        let z = scalar_from_bytes(hash_halfagg(
            &Seq::<(PublicKey, Message, Bytes32)>::from_slice(&pmr, 0, i + 1),
        ));
        let si = scalar_from_bytes_strict(Bytes32::from_slice(&sig, 32, 32))
            .ok_or(Error::MalformedSignature)?;
        s = s + z * si;
    }
    let mut ret = Seq::<U8>::new(0);
    for i in 0..pmr.len() {
        let (_, _, rx) = pmr[i];
        ret = ret.concat(&rx)
    }
    ret = ret.concat(&bytes_from_scalar(s));
    AggregateResult::Ok(ret)
}

fn point_multi_mul(b: Scalar, terms: &Seq<(Scalar, AffinePoint)>) -> Point {
    let mut acc = point_mul_base(b);
    for i in 0..terms.len() {
        let (s, p) = terms[i];
        acc = point_add(acc, point_mul(s, Point::Affine(p)));
    }
    acc
}

pub type VerifyResult = Result<(), Error>;
pub fn verify_aggregate(aggsig: &AggSig, pm_aggd: &Seq<(PublicKey, Message)>) -> VerifyResult {
    if pm_aggd.len() > 0xffff {
        VerifyResult::Err(Error::AggSigTooBig)?;
    }
    if aggsig.len() != 32 * (pm_aggd.len() + 1) {
        VerifyResult::Err(Error::InvalidSignature)?;
    }
    let u = pm_aggd.len();
    let mut terms = Seq::<(Scalar, AffinePoint)>::new(2 * u);
    let mut pmr = Seq::<(PublicKey, Message, Bytes32)>::new(u);
    for i in 0..u {
        let (pk, msg) = pm_aggd[i];
        let px = fieldelem_from_bytes(pk).ok_or(Error::InvalidPublicKey(i))?;
        let p_res = lift_x(px);
        if p_res.is_err() {
            VerifyResult::Err(Error::InvalidPublicKey(i))?;
        }
        let p = p_res.unwrap();
        let rx = Bytes32::from_slice(aggsig, 32 * i, 32);
        let rx_f = fieldelem_from_bytes(rx).ok_or(Error::InvalidSignature)?;
        let r_res = lift_x(rx_f);
        if r_res.is_err() {
            VerifyResult::Err(Error::InvalidSignature)?;
        }
        let r = r_res.unwrap();
        let e = scalar_from_bytes(hash_challenge(rx, bytes_from_point(p), msg));
        pmr[i] = (pk, msg, rx);
        // TODO: The following line hashes i elements and therefore leads to
        // quadratic runtime. Instead, we should cache the intermediate result
        // and only hash the new element.
        let z = scalar_from_bytes(hash_halfagg(
            &Seq::<(PublicKey, Message, Bytes32)>::from_slice(&pmr, 0, i + 1),
        ));
        terms[2 * i] = (z, r);
        terms[2 * i + 1] = (z * e, p);
    }
    let s = scalar_from_bytes_strict(Bytes32::from_seq(&aggsig.slice(32 * u, 32)))
        .ok_or(Error::InvalidSignature)?;
    match point_multi_mul(Scalar::ZERO() - s, &terms) {
        Point::Affine(_) => VerifyResult::Err(Error::InvalidSignature),
        Point::AtInfinity => VerifyResult::Ok(()),
    }
}
