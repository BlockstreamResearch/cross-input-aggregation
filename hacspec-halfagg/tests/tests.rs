use hacspec_bip_340::*;
use hacspec_halfagg::*;
use hacspec_lib::*;

fn strip_sigs(pms_triple: &Seq<(PublicKey, Message, Signature)>) -> Seq<(PublicKey, Message)> {
    let pm_tuple = Seq::<(PublicKey, Message)>::from_vec(
        pms_triple
            .native_slice()
            .to_vec()
            .iter()
            .map(|&(x, y, _)| (x, y))
            .collect::<Vec<_>>(),
    );
    pm_tuple
}

#[allow(dead_code)]
fn test_verify_vectors_gen() -> Vec<(Seq<(PublicKey, Message)>, AggSig)> {
    let skm = vec![
        (
            SecretKey::from_public_array([1; 32]),
            Message::from_public_array([2; 32]),
            AuxRand::from_public_array([3; 32]),
        ),
        (
            SecretKey::from_public_array([4; 32]),
            Message::from_public_array([5; 32]),
            AuxRand::from_public_array([6; 32]),
        ),
    ];
    let vectors_input = vec![vec![], vec![skm[0]], vec![skm[0], skm[1]]];

    let mut vectors = vec![];
    for v_in in vectors_input {
        let mut pms = Seq::<(PublicKey, Message, Signature)>::new(0);
        for skm in v_in {
            let sk = skm.0;
            let pk = pubkey_gen(sk).unwrap();
            let sig = sign(skm.1, sk, skm.2).unwrap();
            pms = pms.push(&(pk, skm.1, sig));
        }
        let aggsig = aggregate(&pms).unwrap();
        vectors.push((strip_sigs(&pms), aggsig));
    }
    vectors
}

#[allow(dead_code)]
fn test_verify_vectors_print(vectors: &Vec<(Seq<(PublicKey, Message)>, AggSig)>) {
    println!("let vectors_raw = vec![");
    for v in vectors {
        let s: String =
            v.0.iter()
                .map(|(pk, m)| format!("(\"{}\", \"{}\"),", pk.to_hex(), m.to_hex()))
                .collect();
        println!("(vec![{}], \"{}\"),", s, v.1.to_hex());
    }
    println!("];");
}

fn test_verify_vectors_process(
    vectors: &Vec<(Vec<(&str, &str)>, &str)>,
) -> Vec<(Seq<(PublicKey, Message)>, AggSig)> {
    let mut processed_vectors = vec![];
    for v in vectors {
        let pm = Seq::from_vec(
            v.0.iter()
                .map(|(pk, m)| (PublicKey::from_hex(&pk), Message::from_hex(&m)))
                .collect(),
        );
        let aggsig = AggSig::from_hex(v.1);
        processed_vectors.push((pm, aggsig));
    }
    processed_vectors
}

#[test]
fn test_verify_vectors() {
    #[rustfmt::skip]
    let vectors_raw = vec![
        (vec![],
         "0000000000000000000000000000000000000000000000000000000000000000"),
        (vec![("1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", "0202020202020202020202020202020202020202020202020202020202020202"),],
         "b070aafcea439a4f6f1bbfc2eb66d29d24b0cab74d6b745c3cfb009cc8fe4aa837387e8aff16b773d5f31ba82f6cb6bbeb757c707f43af0d559e782b7fd19da9"),
        (vec![("1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f", "0202020202020202020202020202020202020202020202020202020202020202"),
              ("462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b", "0505050505050505050505050505050505050505050505050505050505050505"),],
         "b070aafcea439a4f6f1bbfc2eb66d29d24b0cab74d6b745c3cfb009cc8fe4aa8a3afbdb45a6a34bf7c8c00f1b6d7e7d375b54540f13716c87b62e51e2f4f22ffcc0b8ae4598b28aa30ec01ce33423fb90462b43f25167aec10a9a08b19782667"),
    ];
    let vectors = test_verify_vectors_process(&vectors_raw);
    // Uncomment to generate and print test vectors:
    // let vectors_expected = test_verify_vectors_gen();
    // test_verify_vectors_print(&vectors_expected);
    // TODO: fix assert_eq!(vectors, vectors_expected);
    for i in 0..vectors.len() {
        let aggsig = &vectors[i].1;
        let pm = &vectors[i].0;
        assert!(verify_aggregate(aggsig, pm).is_ok())
    }
}

#[test]
fn test_aggregate_verify() {
    let mut pms_triples = Seq::<(PublicKey, Message, Signature)>::new(0);
    let mut aggsigs = Seq::new(0);
    for i in 0..3usize {
        let sk = [i as u8 + 1; 32];
        let sk = SecretKey::from_public_array(sk);
        let msg = [i as u8 + 2; 32];
        let msg = Message::from_public_array(msg);
        let aux_rand = [i as u8 + 3; 32];
        let aux_rand = AuxRand::from_public_array(aux_rand);
        let sig = sign(msg, sk, aux_rand).unwrap();
        pms_triples = pms_triples.push(&(pubkey_gen(sk).unwrap(), msg, sig));
        let aggsig = aggregate(&pms_triples).unwrap();
        aggsigs = aggsigs.push(&aggsig);
        let pm_tuples = strip_sigs(&pms_triples);
        assert!(verify_aggregate(&aggsig, &pm_tuples).is_ok());
        for j in 0..i {
            // Incrementally aggregate aggsig[j] (which has j+1) signatures, and
            // the remaining i - j pms_triples (pms_triples.len() = i + 1 = (j +
            // 1) + (i - j)).
            let aggsig = inc_aggregate(
                &aggsigs[j],
                &Seq::from_slice(&pm_tuples, 0, j + 1),
                &Seq::from_slice(&pms_triples, j + 1, i - j),
            )
            .unwrap();
            assert!(verify_aggregate(&aggsig, &pm_tuples).is_ok());
        }
    }
}

#[test]
fn test_edge_cases() {
    let empty_pm = Seq::<(PublicKey, Message)>::new(0);
    let empty_pms = Seq::<(PublicKey, Message, Signature)>::new(0);
    let aggsig = aggregate(&empty_pms).unwrap();
    let inc_aggsig = inc_aggregate(&aggsig, &empty_pm, &empty_pms).unwrap();
    assert!(verify_aggregate(&aggsig, &empty_pm).is_ok());
    assert!(verify_aggregate(&inc_aggsig, &empty_pm).is_ok());

    let aggsig = AggSig::new(32);
    let inc_aggsig = inc_aggregate(&aggsig, &empty_pm, &empty_pms).unwrap();
    assert!(verify_aggregate(&aggsig, &empty_pm).is_ok());
    assert!(verify_aggregate(&inc_aggsig, &empty_pm).is_ok());

    let aggsig = AggSig::new(0);
    assert!(
        inc_aggregate(&aggsig, &empty_pm, &empty_pms).unwrap_err()
            == hacspec_halfagg::Error::MalformedSignature
    );
    assert!(
        verify_aggregate(&aggsig, &empty_pm).unwrap_err()
            == hacspec_halfagg::Error::InvalidSignature
    );
}
