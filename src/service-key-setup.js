const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const config = require("./config");


function saveFile(filePath, data) {

    fs.mkdirSync(
        path.dirname(filePath),
        { recursive: true }
    );

    fs.writeFileSync(
        filePath,
        data
    );
}


function main() {

    const projectRoot =
        config.paths.projectRoot;


    const serviceId =
        process.argv[2] ??
        "benchmark-service";


    const privateDir =
        path.join(
            projectRoot,
            "private",
            "services",
            serviceId
        );


    const stateDir =
        path.join(
            projectRoot,
            "state",
            "services",
            serviceId
        );


    const privateKeyFile =
        path.join(
            privateDir,
            "service_private_key.pem"
        );


    const publicKeyFile =
        path.join(
            stateDir,
            "service_public_key.pem"
        );


    const metadataFile =
        path.join(
            stateDir,
            "service_identity.json"
        );


    if (
        fs.existsSync(privateKeyFile) ||
        fs.existsSync(publicKeyFile)
    ) {

        throw new Error(
            "Service identity already exists. Refusing to overwrite."
        );
    }


    const {
        publicKey,
        privateKey
    } =
        crypto.generateKeyPairSync(
            "ed25519"
        );


    const privatePem =
        privateKey.export({
            type: "pkcs8",
            format: "pem"
        });


    const publicPem =
        publicKey.export({
            type: "spki",
            format: "pem"
        });


    const publicDer =
        publicKey.export({
            type: "spki",
            format: "der"
        });


    const keyId =
        crypto
            .createHash("sha256")
            .update(publicDer)
            .digest("hex");


    saveFile(
        privateKeyFile,
        privatePem
    );


    saveFile(
        publicKeyFile,
        publicPem
    );


    const metadata = {

        version: 1,

        service_id:
            serviceId,

        signature_scheme:
            "Ed25519",

        key_id:
            keyId,

        public_key_file:
            publicKeyFile,

        created_at:
            new Date().toISOString()
    };


    saveFile(
        metadataFile,
        JSON.stringify(
            metadata,
            null,
            2
        )
    );


    // Self-test
    const message =
        Buffer.from(
            "service-key-self-test",
            "utf8"
        );


    const signature =
        crypto.sign(
            null,
            message,
            privateKey
        );


    const verified =
        crypto.verify(
            null,
            message,
            publicKey,
            signature
        );


    if (!verified) {

        throw new Error(
            "Service key self-test failed."
        );
    }


    console.log(
        "============================================"
    );

    console.log(
        " Destination Service Identity Setup"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Service ID : ${serviceId}`
    );

    console.log(
        "Scheme     : Ed25519"
    );

    console.log(
        `Key ID     : ${keyId}`
    );

    console.log(
        "Self-test  : VALID"
    );

    console.log("");

    console.log(
        "Private key:"
    );

    console.log(
        privateKeyFile
    );

    console.log("");

    console.log(
        "Public identity:"
    );

    console.log(
        metadataFile
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
        "Service identity setup failed:"
    );

    console.error(
        error.message
    );

    process.exit(1);
}