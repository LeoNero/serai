use core::ops::Deref;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use crate::{
  Commitment, random_scalar,
  wallet::Decoys,
  ringct::{
    generate_key_image,
    clsag::{ClsagInput, Clsag},
  },
};

const RING_LEN: u64 = 11;
const AMOUNT: u64 = 1337;

#[test]
fn clsag() {
  for real in 0..RING_LEN {
    let msg = [1; 32];

    let mut secrets = (Zeroizing::new(Scalar::zero()), Scalar::zero());
    let mut ring = vec![];
    for i in 0..RING_LEN {
      let dest = Zeroizing::new(random_scalar(&mut OsRng));
      let mask = random_scalar(&mut OsRng);
      let amount;
      if i == real {
        secrets = (dest.clone(), mask);
        amount = AMOUNT;
      } else {
        amount = OsRng.next_u64();
      }
      ring
        .push([dest.deref() * &ED25519_BASEPOINT_TABLE, Commitment::new(mask, amount).calculate()]);
    }

    let image = generate_key_image(&secrets.0);
    let (clsag, pseudo_out) = Clsag::sign(
      &mut OsRng,
      vec![(
        secrets.0,
        image,
        ClsagInput::new(
          Commitment::new(secrets.1, AMOUNT),
          Decoys {
            i: u8::try_from(real).unwrap(),
            offsets: (1..=RING_LEN).collect(),
            ring: ring.clone(),
          },
        )
        .unwrap(),
      )],
      random_scalar(&mut OsRng),
      msg,
    )
    .swap_remove(0);
    clsag.verify(&ring, &image, &pseudo_out, &msg).unwrap();
  }
}
