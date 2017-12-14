extern crate privcount;
extern crate rand;
extern crate crypto;

use privcount::data::*;
use privcount::{client,server,shamir};

use rand::Rng;
use rand::os::OsRng;
use std::collections::HashMap;
use std::iter::FromIterator;

fn gen_server_keys(rng : &mut Rng) -> server::ServerKeys {
    use crypto::curve25519::curve25519_base;
    use privcount::encrypt::keygen;
    let mut signing_key = [0 ; 32];
    rng.fill_bytes(&mut signing_key);
    let seckey = keygen::curve25519_seckey_gen(rng);
    let pk = curve25519_base(&seckey);
    server::ServerKeys { enc_secret : seckey ,
                         public : TrKeys { enc_key : pk, signing_key } }
}

fn test_combination(n_counters : usize,
                    n_clients : usize,
                    n_trs : usize,
                    k_value : usize) {

    let mut rng = OsRng::new().unwrap();

    assert!(k_value <= n_trs);

    let server_keys = Vec::from_iter(
        (0..n_trs).map(|_| gen_server_keys(&mut rng)) );
    let tr_keys = Vec::from_iter(
        server_keys.iter().map(|sk| sk.public.clone()) );
    let counter_ids = Vec::from_iter(
        (1..n_counters+1).map(|n| CtrId(n as u32)) );

    let mut client_data = Vec::new();

    let mut accurate_sum = HashMap::new();

    // simulate each client.
    for client_idx in 0..n_clients {
        let mut ctrs = client::CounterSet::new(
            &mut rng, &counter_ids, &tr_keys, k_value);

        for id in counter_ids.iter() {
            let to_add = id.0 + (client_idx*17) as u32; // add a dummy value
            ctrs.ctr(*id).unwrap().inc(to_add);
            let true_ctr = accurate_sum.entry(*id).or_insert(0);
            *true_ctr += to_add;
        }
        client_data.push(ctrs.finalize(&mut rng));
    }

    // then simulate each server; create each one's share of each counter's
    // sum.
    let mut shares = Vec::new();
    for my_keys in server_keys.iter() {
        let mut all_my_client_data = Vec::new();
        for this_client in client_data.iter() {
            // all clients get the same id for now.
            let client_id = ClientKey{signing_key:[42;32]};

            // my data from this client
            let my_data =
                this_client.tr_data.iter()
                .find(|trdata| trdata.keys == my_keys.public)
                .unwrap();

            let decoded = my_keys.decode_from(
                &client_id,
                &this_client.counter_ids,
                my_data).unwrap();

            all_my_client_data.push(decoded);
        }
        let my_shares = server::SumShares(&all_my_client_data);
        shares.push( ( my_keys.public.get_x_coord(),
                       my_shares) );
    }

    // use the first k shares to reconstruct the secret for each counter.
    for cid in counter_ids.iter() {
        let mut ctr_shares = Vec::new();
        for &(x, ref map) in shares[0..k_value].iter() {
            let y = map.get(cid).unwrap();
            ctr_shares.push(shamir::Share{ x, y:*y});
        }
        let sum = shamir::recover_secret(&ctr_shares);

        println!("{:?} : {}", cid, sum);

        // make sure that the reconstructed 
        assert_eq!(*accurate_sum.get(cid).unwrap() as u64, sum.value());
    }

}

#[test]
fn one_out_of_one() {
    test_combination(5, 2, 1, 1);
}

#[test]
fn two_out_of_two() {
    test_combination(5, 2, 2, 2);
}


#[test]
fn three_out_of_five() {
    test_combination(10, 3, 5, 3);
}
