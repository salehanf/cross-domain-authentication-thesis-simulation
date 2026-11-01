use frost_ed25519 as frost;

use serde::Serialize;

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    error::Error,
    fs,
    io::{Error as IoError, ErrorKind},
    path::Path,
    time::Instant,
};


#[derive(Serialize)]
struct SignTiming {
    round1_ms: f64,
    round2_ms: f64,
    aggregate_ms: f64,
    verify_ms: f64,
    total_ms: f64,
}


#[derive(Serialize)]
struct SignReport {
    scheme: String,
    ciphersuite: String,

    threshold: u16,
    signers: Vec<u16>,

    message_bytes: usize,
    signature_bytes: usize,

    verified: bool,

    timing: SignTiming,
}


fn input_error(
    message: impl Into<String>
) -> IoError {

    IoError::new(
        ErrorKind::InvalidInput,
        message.into()
    )
}


fn load_public_key_package()
    -> Result<
        frost::keys::PublicKeyPackage,
        Box<dyn Error>
    >
{
    let path =
        Path::new("state")
            .join("frost")
            .join("public_key_package.bin");


    let bytes =
        fs::read(&path)?;


    let package =
        frost::keys::PublicKeyPackage
            ::deserialize(&bytes)?;


    Ok(package)
}


fn load_key_package(
    admin_number: u16
) -> Result<
        frost::keys::KeyPackage,
        Box<dyn Error>
    >
{
    let filename =
        format!(
            "admin_{:02}.keypkg",
            admin_number
        );


    let path =
        Path::new("private")
            .join("frost")
            .join(filename);


    let bytes =
        fs::read(&path)?;


    let package =
        frost::keys::KeyPackage
            ::deserialize(&bytes)?;


    Ok(package)
}


fn parse_signers(
    csv: &str
) -> Result<Vec<u16>, Box<dyn Error>> {

    let mut signers =
        Vec::new();

    let mut seen =
        BTreeSet::new();


    for item in csv.split(',') {

        let value: u16 =
            item
                .trim()
                .parse()?;


        if value == 0 {

            return Err(
                input_error(
                    "Admin identifiers must start from 1."
                )
                .into()
            );
        }


        if !seen.insert(value) {

            return Err(
                input_error(
                    format!(
                        "Duplicate admin identifier: {}",
                        value
                    )
                )
                .into()
            );
        }


        signers.push(value);
    }


    if signers.is_empty() {

        return Err(
            input_error(
                "At least one signer is required."
            )
            .into()
        );
    }


    Ok(signers)
}


fn sign_message(
    message_file: &str,
    signature_file: &str,
    signers_csv: &str,
    report_file: &str,
) -> Result<(), Box<dyn Error>> {

    let message =
        fs::read(message_file)?;


    let public_key_package =
        load_public_key_package()?;


    let threshold =
        public_key_package
            .min_signers()
            .ok_or_else(
                || input_error(
                    "PublicKeyPackage does not contain min_signers."
                )
            )?;


    let signers =
        parse_signers(
            signers_csv
        )?;


    if signers.len() <
       threshold as usize
    {

        return Err(
            input_error(
                format!(
                    "At least {} signers are required; got {}.",
                    threshold,
                    signers.len()
                )
            )
            .into()
        );
    }


    if signers.len() >
       public_key_package
           .max_signers() as usize
    {

        return Err(
            input_error(
                "Too many signers were provided."
            )
            .into()
        );
    }


    // --------------------------------------------------
    // Load selected long-term admin KeyPackages
    // --------------------------------------------------

    let mut key_packages =
        BTreeMap::new();


    for admin_number in &signers {

        let identifier:
            frost::Identifier =
            (*admin_number)
                .try_into()
                .expect(
                    "Non-zero u16 identifier must be valid."
                );


        let key_package =
            load_key_package(
                *admin_number
            )?;


        key_packages.insert(
            identifier,
            key_package
        );
    }


    let mut rng =
        rand::rngs::OsRng;


    let total_start =
        Instant::now();


    // ==================================================
    // FROST Signing Round 1
    // ==================================================

    let round1_start =
        Instant::now();


    let mut nonces_map =
        BTreeMap::new();


    let mut commitments_map =
        BTreeMap::new();


    for (
        identifier,
        key_package
    ) in &key_packages
    {

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
            *identifier,
            nonces
        );


        commitments_map.insert(
            *identifier,
            commitments
        );
    }


    let round1_ms =
        round1_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    // ==================================================
    // Signing package
    // ==================================================

    let signing_package =
        frost::SigningPackage::new(
            commitments_map,
            &message,
        );


    // ==================================================
    // FROST Signing Round 2
    // ==================================================

    let round2_start =
        Instant::now();


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


    let round2_ms =
        round2_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    // ==================================================
    // Aggregate
    // ==================================================

    let aggregate_start =
        Instant::now();


    let group_signature =
        frost::aggregate(
            &signing_package,
            &signature_shares,
            &public_key_package,
        )?;


    let aggregate_ms =
        aggregate_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    // ==================================================
    // Final signature verification
    // ==================================================

    let verify_start =
        Instant::now();


    let verified =
        public_key_package
            .verifying_key()
            .verify(
                &message,
                &group_signature,
            )
            .is_ok();


    let verify_ms =
        verify_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    if !verified {

        return Err(
            input_error(
                "Final FROST signature verification failed."
            )
            .into()
        );
    }


    // ==================================================
    // Serialize final signature
    // ==================================================

    let signature_bytes =
        group_signature
            .serialize()?;


    fs::write(
        signature_file,
        &signature_bytes
    )?;


    let total_ms =
        total_start
            .elapsed()
            .as_secs_f64()
            * 1000.0;


    let report =
        SignReport {

            scheme:
                "FROST".to_string(),

            ciphersuite:
                "FROST(Ed25519, SHA-512)"
                    .to_string(),

            threshold,

            signers:
                signers.clone(),

            message_bytes:
                message.len(),

            signature_bytes:
                signature_bytes.len(),

            verified,

            timing:
                SignTiming {

                    round1_ms,

                    round2_ms,

                    aggregate_ms,

                    verify_ms,

                    total_ms,
                },
        };


    fs::write(
        report_file,

        serde_json::to_string_pretty(
            &report
        )?
    )?;


    println!(
        "FROST signature created successfully."
    );

    println!(
        "Threshold : {}-of-{}",
        threshold,
        public_key_package.max_signers()
    );

    println!(
        "Signers   : {:?}",
        signers
    );

    println!(
        "Signature : {} bytes",
        signature_bytes.len()
    );

    println!(
        "Verified  : true"
    );

    println!(
        "Signing total: {:.3} ms",
        total_ms
    );


    Ok(())
}


fn verify_message(
    message_file: &str,
    signature_file: &str,
) -> Result<(), Box<dyn Error>> {

    let message =
        fs::read(
            message_file
        )?;


    let signature_bytes =
        fs::read(
            signature_file
        )?;


    let signature =
        frost::Signature
            ::deserialize(
                &signature_bytes
            )?;


    let public_key_package =
        load_public_key_package()?;


    let valid =
        public_key_package
            .verifying_key()
            .verify(
                &message,
                &signature,
            )
            .is_ok();


    if !valid {

        return Err(
            input_error(
                "FROST signature is INVALID."
            )
            .into()
        );
    }


    println!(
        "FROST signature verification: VALID"
    );


    Ok(())
}


fn main()
    -> Result<(), Box<dyn Error>>
{
    let args: Vec<String> =
        env::args().collect();


    if args.len() < 2 {

        eprintln!(
            "Usage:"
        );

        eprintln!(
            "  frost-sign sign <message_file> <signature_file> <signers_csv> <report_file>"
        );

        eprintln!(
            "  frost-sign verify <message_file> <signature_file>"
        );

        std::process::exit(1);
    }


    match args[1].as_str() {

        "sign" => {

            if args.len() != 6 {

                return Err(
                    input_error(
                        "Invalid arguments for sign."
                    )
                    .into()
                );
            }


            sign_message(
                &args[2],
                &args[3],
                &args[4],
                &args[5],
            )
        }


        "verify" => {

            if args.len() != 4 {

                return Err(
                    input_error(
                        "Invalid arguments for verify."
                    )
                    .into()
                );
            }


            verify_message(
                &args[2],
                &args[3],
            )
        }


        other => {

            Err(
                input_error(
                    format!(
                        "Unknown command: {}",
                        other
                    )
                )
                .into()
            )
        }
    }
}