const fs = require("fs");
const path = require("path");
const {
    execFileSync
} = require("child_process");

const config =
    require("./config");


const projectRoot =
    config.paths.projectRoot;


const executable =
    path.join(
        projectRoot,
        "rust",
        "frost-admin",
        "target",
        "release",
        "frost-sign.exe"
    );


function ensureExecutable() {

    if (!fs.existsSync(executable)) {

        throw new Error(
            "frost-sign.exe was not found. Build it first."
        );
    }
}


function defaultSigners() {

    const t =
        config.admins.t;


    return Array.from(
        { length: t },
        (_, i) => i + 1
    );
}


function validateArtifactName(name) {

    if (
        !/^[a-zA-Z0-9_-]+$/.test(name)
    ) {

        throw new Error(
            "Invalid FROST artifact name."
        );
    }
}


function signMessage(
    messageBuffer,
    artifactName,
    signerIds = defaultSigners()
) {

    ensureExecutable();
    validateArtifactName(
        artifactName
    );


    if (
        !Buffer.isBuffer(
            messageBuffer
        )
    ) {

        throw new Error(
            "messageBuffer must be a Buffer."
        );
    }


    const outputDir =
        path.join(
            projectRoot,
            "state",
            "frost",
            "signatures"
        );


    fs.mkdirSync(
        outputDir,
        {
            recursive: true
        }
    );


    const messageFile =
        path.join(
            outputDir,
            `${artifactName}.msg.bin`
        );


    const signatureFile =
        path.join(
            outputDir,
            `${artifactName}.sig.bin`
        );


    const reportFile =
        path.join(
            outputDir,
            `${artifactName}.report.json`
        );


    fs.writeFileSync(
        messageFile,
        messageBuffer
    );


    execFileSync(
        executable,

        [
            "sign",
            messageFile,
            signatureFile,
            signerIds.join(","),
            reportFile
        ],

        {
            cwd:
                projectRoot,

            stdio:
                "inherit"
        }
    );


    const signature =
        fs.readFileSync(
            signatureFile
        );


    const report =
        JSON.parse(
            fs.readFileSync(
                reportFile,
                "utf8"
            )
        );


    return {

        signatureHex:
            signature.toString(
                "hex"
            ),

        report,

        messageFile,
        signatureFile,
        reportFile
    };
}


function verifyMessage(
    messageBuffer,
    signatureHex
) {

    ensureExecutable();


    const tempDir =
        path.join(
            projectRoot,
            "state",
            "frost",
            "tmp"
        );


    fs.mkdirSync(
        tempDir,
        {
            recursive: true
        }
    );


    const messageFile =
        path.join(
            tempDir,
            "verify_message.bin"
        );


    const signatureFile =
        path.join(
            tempDir,
            "verify_signature.bin"
        );


    fs.writeFileSync(
        messageFile,
        messageBuffer
    );


    fs.writeFileSync(
        signatureFile,
        Buffer.from(
            signatureHex,
            "hex"
        )
    );


    try {

        execFileSync(
            executable,

            [
                "verify",
                messageFile,
                signatureFile
            ],

            {
                cwd:
                    projectRoot,

                stdio:
                    "pipe"
            }
        );


        return true;

    } catch {

        return false;

    } finally {

        fs.rmSync(
            messageFile,
            {
                force: true
            }
        );

        fs.rmSync(
            signatureFile,
            {
                force: true
            }
        );
    }
}


module.exports = {
    signMessage,
    verifyMessage,
    defaultSigners
};