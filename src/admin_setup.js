const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const config = require("./config");


function main() {

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Admin Threshold Setup"
    );

    console.log(
        "============================================"
    );


    const projectRoot =
        config.paths.projectRoot;


    // --------------------------------------------------
    // Read parameters from config.js
    // --------------------------------------------------

    const n =
        config.admins.n;

    const t =
        config.admins.t;

    const schemeId =
        config.protocol.schemeId;

    const domainId =
        config.domain.domainId;


    // --------------------------------------------------
    // Validate configuration
    // --------------------------------------------------

    if (
        !Number.isInteger(n) ||
        !Number.isInteger(t) ||
        t < 2 ||
        t > n
    ) {

        throw new Error(
            "Invalid threshold configuration. Expected 2 <= t <= n."
        );
    }


    // --------------------------------------------------
    // Compiled Rust executable
    // --------------------------------------------------

    const frostExecutable =
        path.join(
            projectRoot,
            "rust",
            "frost-admin",
            "target",
            "release",
            "frost-admin.exe"
        );


    if (
        !fs.existsSync(
            frostExecutable
        )
    ) {

        throw new Error(
            [
                "FROST executable was not found.",
                "",
                "Build it first with:",
                "",
                "cargo build --release --manifest-path rust\\frost-admin\\Cargo.toml"
            ].join("\n")
        );
    }


    console.log("");

    console.log(
        "Configuration loaded from src/config.js"
    );

    console.log(
        "Administrators:",
        `${t}-of-${n}`
    );

    console.log(
        "Scheme ID:",
        schemeId
    );

    console.log(
        "Domain ID:",
        domainId
    );


    if (
        config.admins.thresholdSignature
    ) {

        console.log(
            "Threshold scheme:",
            config.admins
                .thresholdSignature
                .scheme
        );

        console.log(
            "Ciphersuite:",
            config.admins
                .thresholdSignature
                .ciphersuite
        );
    }


    console.log("");
    console.log(
        "Starting FROST DKG..."
    );

    console.log("");


    // --------------------------------------------------
    // Execute compiled Rust program
    //
    // IMPORTANT:
    // cwd = project root
    //
    // Therefore Rust outputs:
    //
    // private/
    // state/
    // results/
    //
    // are created in D:\thesis-simulation
    // --------------------------------------------------

    execFileSync(
        frostExecutable,

        [
            String(n),
            String(t),
            String(schemeId),
            String(domainId)
        ],

        {
            cwd: projectRoot,
            stdio: "inherit"
        }
    );


    console.log("");

    console.log(
        "Admin threshold setup completed successfully."
    );

    console.log(
        "============================================"
    );
}


try {

    main();

} catch (error) {

    console.error("");

    console.error(
        "Admin threshold setup failed:"
    );

    console.error(
        error.message
    );

    process.exit(1);
}