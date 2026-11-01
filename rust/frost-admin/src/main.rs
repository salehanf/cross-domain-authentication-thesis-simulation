use frost_ed25519 as frost;

use serde::Serialize;

use sha2::{
    Digest,
    Sha256,
};

use std::{
    collections::BTreeMap,
    env,
    error::Error,
    fs,
    path::Path,
    time::Instant,
};


// ======================================================
// JSON result structure
// ======================================================

#[derive(Serialize)]
struct AdminPublicInfo {
    admin_number: u16,
    identifier_hex: String,
    verifying_share_hex: String,
}


#[derive(Serialize)]
struct TimingInfo {
    dkg_round1_ms: f64,
    dkg_round2_ms: f64,
    dkg_round3_ms: f64,
    dkg_total_ms: f64,
    self_test_sign_ms: f64,
}


#[derive(Serialize)]
struct FrostSetupResult {

    scheme: String,
    ciphersuite: String,

    domain_id: u64,
    scheme_id: u64,

    n: u16,
    t: u16,

    key_version: u32,
    key_id: String,

    group_public_key_hex: String,

    admins: Vec<AdminPublicInfo>,

    self_test: bool,

    timing: TimingInfo,

    note: String,
}


// ======================================================
// Compute protocol key_id
// ======================================================

fn compute_key_id(
    scheme_id: u64,
    domain_id: u64,
    key_version: u32,
    public_key: &[u8],
) -> String {

    let mut hasher =
        Sha256::new();


    /*
        Domain-separated operational key identifier.

        This is NOT a cryptographic signing key.

        It only identifies which domain threshold
        public key/version was used.
    */

    hasher.update(
        b"THESIS_FROST_KEY_ID_V1"
    );

    hasher.update(
        scheme_id.to_be_bytes()
    );

    hasher.update(
        domain_id.to_be_bytes()
    );

    hasher.update(
        key_version.to_be_bytes()
    );

    hasher.update(
        public_key
    );


    hex::encode(
        hasher.finalize()
    )
}


// ======================================================
// Main
// ======================================================

fn main() -> Result<(), Box<dyn Error>> {

    println!(
        "============================================"
    );

    println!(
        " Thesis Protocol - FROST Admin Setup"
    );

    println!(
        "============================================"
    );


    // ==================================================
    // Read arguments
    //
    // frost-admin <n> <t> <scheme_id> <domain_id>
    // ==================================================

    let args: Vec<String> =
        env::args().collect();


    if args.len() != 5 {

        eprintln!(
            "Usage: frost-admin <n> <t> <scheme_id> <domain_id>"
        );

        std::process::exit(1);
    }


    let n: u16 =
        args[1].parse()?;


    let t: u16 =
        args[2].parse()?;


    let scheme_id: u64 =
        args[3].parse()?;


    let domain_id: u64 =
        args[4].parse()?;


    if t < 2 || t > n {

        return Err(
            "Threshold must satisfy 2 <= t <= n."
                .into()
        );
    }


    let key_version: u32 =
        1;


    println!();

    println!(
        "Threshold configuration: {}-of-{}",
        t,
        n
    );

    println!(
        "Ciphersuite: FROST(Ed25519, SHA-512)"
    );


    // ==================================================
    // Randomness
    // ==================================================

    let mut rng =
        rand::rngs::OsRng;


    let dkg_total_start =
        Instant::now();


    // ==================================================
    // DKG ROUND 1
    // ==================================================

    let round1_start =
        Instant::now();


    let mut round1_secret_packages =
        BTreeMap::new();


    /*
        For every receiver, store all Round-1
        packages received from the other admins.
    */

    let mut received_round1_packages:
        BTreeMap<
            frost::Identifier,
            BTreeMap<
                frost::Identifier,
                frost::keys::dkg::round1::Package
            >
        > =
        BTreeMap::new();


    for participant_index in 1..=n {

        let participant_identifier:
            frost::Identifier =
            participant_index
                .try_into()
                .expect(
                    "Participant identifier must be non-zero."
                );


        let (
            secret_package,
            round1_package
        ) =
            frost::keys::dkg::part1(
                participant_identifier,
                n,
                t,
                &mut rng,
            )?;


        /*
            Secret package remains local to
            this simulated admin.
        */

        round1_secret_packages.insert(
            participant_identifier,
            secret_package
        );


        /*
            Round 1 is a broadcast.

            Every other participant receives
            the same public Round-1 package.
        */

        for receiver_index in 1..=n {

            if receiver_index ==
               participant_index
            {
                continue;
            }


            let receiver_identifier:
                frost::Identifier =
                receiver_index
                    .try_into()
                    .expect(
                        "Participant identifier must be non-zero."
                    );


            received_round1_packages
                .entry(
                    receiver_identifier
                )
                .or_default()
                .insert(
                    participant_identifier,
                    round1_package.clone()
                );
        }
    }


    let dkg_round1_ms =
        round1_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    // ==================================================
    // DKG ROUND 2
    // ==================================================

    let round2_start =
        Instant::now();


    let mut round2_secret_packages =
        BTreeMap::new();


    let mut received_round2_packages:
        BTreeMap<
            frost::Identifier,
            BTreeMap<
                frost::Identifier,
                frost::keys::dkg::round2::Package
            >
        > =
        BTreeMap::new();


    for participant_index in 1..=n {

        let participant_identifier:
            frost::Identifier =
            participant_index
                .try_into()
                .expect(
                    "Participant identifier must be non-zero."
                );


        let round1_secret_package =
            round1_secret_packages
                .remove(
                    &participant_identifier
                )
                .expect(
                    "Missing Round-1 secret package."
                );


        let round1_packages =
            &received_round1_packages[
                &participant_identifier
            ];


        let (
            round2_secret_package,
            round2_packages
        ) =
            frost::keys::dkg::part2(
                round1_secret_package,
                round1_packages,
            )?;


        round2_secret_packages.insert(
            participant_identifier,
            round2_secret_package
        );


        /*
            Round 2 packages are receiver-specific.

            Each destination gets its own package.
        */

        for (
            receiver_identifier,
            round2_package
        ) in round2_packages
        {

            received_round2_packages
                .entry(
                    receiver_identifier
                )
                .or_default()
                .insert(
                    participant_identifier,
                    round2_package
                );
        }
    }


    let dkg_round2_ms =
        round2_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    // ==================================================
    // DKG ROUND 3 / FINALIZATION
    // ==================================================

    let round3_start =
        Instant::now();


    let mut key_packages =
        BTreeMap::new();


    let mut public_key_packages =
        BTreeMap::new();


    for participant_index in 1..=n {

        let participant_identifier:
            frost::Identifier =
            participant_index
                .try_into()
                .expect(
                    "Participant identifier must be non-zero."
                );


        let round2_secret_package =
            &round2_secret_packages[
                &participant_identifier
            ];


        let round1_packages =
            &received_round1_packages[
                &participant_identifier
            ];


        let round2_packages =
            &received_round2_packages[
                &participant_identifier
            ];


        let (
            key_package,
            public_key_package
        ) =
            frost::keys::dkg::part3(
                round2_secret_package,
                round1_packages,
                round2_packages,
            )?;


        key_packages.insert(
            participant_identifier,
            key_package
        );


        public_key_packages.insert(
            participant_identifier,
            public_key_package
        );
    }


    let dkg_round3_ms =
        round3_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    let dkg_total_ms =
        dkg_total_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    // ==================================================
    // Verify all admins derived the SAME public package
    // ==================================================

    let first_identifier:
        frost::Identifier =
        1u16
            .try_into()
            .expect(
                "Identifier 1 must be valid."
            );


    let public_key_package =
        public_key_packages
            .get(
                &first_identifier
            )
            .expect(
                "Missing public key package."
            );


    let canonical_public_package =
        public_key_package
            .serialize()?;


    for package in
        public_key_packages.values()
    {

        let serialized =
            package.serialize()?;


        if serialized !=
           canonical_public_package
        {

            return Err(
                "DKG participants derived different public key packages."
                    .into()
            );
        }
    }


    // ==================================================
    // Group public key
    // ==================================================

    let group_public_key_bytes =
        public_key_package
            .verifying_key()
            .serialize()?;


    let group_public_key_hex =
        hex::encode(
            &group_public_key_bytes
        );


    let key_id =
        compute_key_id(
            scheme_id,
            domain_id,
            key_version,
            &group_public_key_bytes,
        );


    // ==================================================
    // Save PRIVATE KeyPackage for each admin
    //
    // NOTE:
    // These files contain SECRET signing shares.
    // They are for laboratory simulation only.
    // ==================================================

    let private_dir =
        Path::new(
            "private"
        )
        .join(
            "frost"
        );


    fs::create_dir_all(
        &private_dir
    )?;


    for participant_index in 1..=n {

        let identifier:
            frost::Identifier =
            participant_index
                .try_into()
                .expect(
                    "Participant identifier must be valid."
                );


        let key_package =
            &key_packages[
                &identifier
            ];


        let serialized =
            key_package.serialize()?;


        let filename =
            format!(
                "admin_{:02}.keypkg",
                participant_index
            );


        fs::write(
            private_dir.join(
                filename
            ),
            serialized
        )?;
    }


    // ==================================================
    // Save PUBLIC package
    // ==================================================

    let state_dir =
        Path::new(
            "state"
        )
        .join(
            "frost"
        );


    fs::create_dir_all(
        &state_dir
    )?;


    fs::write(
        state_dir.join(
            "public_key_package.bin"
        ),
        &canonical_public_package
    )?;


    // ==================================================
    // Public verification shares
    // ==================================================

    let mut admin_public_info =
        Vec::new();


    for participant_index in 1..=n {

        let identifier:
            frost::Identifier =
            participant_index
                .try_into()
                .expect(
                    "Participant identifier must be valid."
                );


        let verifying_share =
            public_key_package
                .verifying_shares()
                .get(
                    &identifier
                )
                .expect(
                    "Missing public verifying share."
                );


        admin_public_info.push(
            AdminPublicInfo {

                admin_number:
                    participant_index,

                identifier_hex:
                    hex::encode(
                        identifier.serialize()
                    ),

                verifying_share_hex:
                    hex::encode(
                        verifying_share
                            .serialize()?
                    ),
            }
        );
    }


    // ==================================================
    // FROST SELF TEST
    //
    // Use exactly t admins to sign one test message.
    // ==================================================

    let self_test_start =
        Instant::now();


    let test_message =
        b"THESIS_FROST_ADMIN_SETUP_SELF_TEST_V1";


    let mut nonces_map =
        BTreeMap::new();


    let mut commitments_map =
        BTreeMap::new();


    /*
        Use admins 1..t.
    */

    for participant_index in 1..=t {

        let identifier:
            frost::Identifier =
            participant_index
                .try_into()
                .expect(
                    "Participant identifier must be valid."
                );


        let key_package =
            &key_packages[
                &identifier
            ];


        let (
            nonces,
            commitments
        ) =
            frost::round1::commit(
                key_package
                    .signing_share(),
                &mut rng,
            );


        nonces_map.insert(
            identifier,
            nonces
        );


        commitments_map.insert(
            identifier,
            commitments
        );
    }


    let signing_package =
        frost::SigningPackage::new(
            commitments_map,
            test_message,
        );


    let mut signature_shares =
        BTreeMap::new();


    for (
        identifier,
        nonces
    ) in &nonces_map
    {

        let key_package =
            &key_packages[
                identifier
            ];


        let signature_share =
            frost::round2::sign(
                &signing_package,
                nonces,
                key_package,
            )?;


        signature_shares.insert(
            *identifier,
            signature_share
        );
    }


    let group_signature =
        frost::aggregate(
            &signing_package,
            &signature_shares,
            public_key_package,
        )?;


    let self_test =
        public_key_package
            .verifying_key()
            .verify(
                test_message,
                &group_signature,
            )
            .is_ok();


    let self_test_sign_ms =
        self_test_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    if !self_test {

        return Err(
            "FROST threshold signature self-test failed."
                .into()
        );
    }


    // ==================================================
    // Write public experiment snapshot
    // ==================================================

    fs::create_dir_all(
        "results"
    )?;


    let setup_result =
        FrostSetupResult {

            scheme:
                "FROST".to_string(),

            ciphersuite:
                "FROST(Ed25519, SHA-512)"
                    .to_string(),

            domain_id,

            scheme_id,

            n,

            t,

            key_version,

            key_id:
                key_id.clone(),

            group_public_key_hex:
                group_public_key_hex.clone(),

            admins:
                admin_public_info,

            self_test,

            timing:
                TimingInfo {

                    dkg_round1_ms,

                    dkg_round2_ms,

                    dkg_round3_ms,

                    dkg_total_ms,

                    self_test_sign_ms,
                },

            note:
                "DKG communication is simulated locally in memory; timings measure local computation, not network latency."
                    .to_string(),
        };


    fs::write(
        Path::new(
            "results"
        ).join(
            "frost_setup.json"
        ),

        serde_json::to_string_pretty(
            &setup_result
        )?
    )?;


    // ==================================================
    // Display result
    // ==================================================

    println!();

    println!(
        "FROST DKG completed successfully."
    );


    println!(
        "Threshold : {}-of-{}",
        t,
        n
    );


    println!(
        "Key ID    : {}",
        key_id
    );


    println!(
        "Group public key:"
    );

    println!(
        "{}",
        group_public_key_hex
    );


    println!();

    println!(
        "DKG Round 1 : {:.3} ms",
        dkg_round1_ms
    );


    println!(
        "DKG Round 2 : {:.3} ms",
        dkg_round2_ms
    );


    println!(
        "DKG Round 3 : {:.3} ms",
        dkg_round3_ms
    );


    println!(
        "DKG total   : {:.3} ms",
        dkg_total_ms
    );


    println!(
        "Threshold signature self-test: {}",
        self_test
    );


    println!();

    println!(
        "Private admin shares:"
    );

    println!(
        "private\\frost\\admin_01.keypkg ... admin_{:02}.keypkg",
        n
    );


    println!(
        "Public key package:"
    );

    println!(
        "state\\frost\\public_key_package.bin"
    );


    println!(
        "Setup snapshot:"
    );

    println!(
        "results\\frost_setup.json"
    );


    println!(
        "============================================"
    );


    Ok(())
}