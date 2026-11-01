const crypto = require("crypto");
const { buildBabyjub } = require("circomlibjs");

const Q =
2736030358979909402780800718157159386076813972158567259200215660948447373041n;

function mod(x, q) {
    const r = x % q;
    return r >= 0n ? r : r + q;
}

function randomScalarQ() {
    return mod(
        BigInt("0x" + crypto.randomBytes(32).toString("hex")),
        Q
    );
}

function byteSize(obj) {
    return Buffer.byteLength(
        JSON.stringify(obj),
        "utf8"
    );
}

function pointToJson(point, F) {
    return {
        x: F.toString(point[0]),
        y: F.toString(point[1])
    };
}

async function main() {

    const n = 5;
    const t = 3;

    const babyJub = await buildBabyjub();
    const F = babyJub.F;

    const polys = [];
    const commitmentMessages = [];

    for (let senderId = 1; senderId <= n; senderId++) {

        const coefficients = [];
        const commitments = [];

        for (let k = 1; k <= t - 1; k++) {

            const coeff = randomScalarQ();

            coefficients.push(coeff);

            commitments.push(
                babyJub.mulPointEscalar(
                    babyJub.Base8,
                    coeff
                )
            );
        }

        polys.push({
            sender_id: senderId,
            coefficients
        });

        commitmentMessages.push({
            sender_id: senderId,
            coefficients_committed:
                commitments.map(
                    (point, index) => ({
                        degree: index + 1,
                        commitment:
                            pointToJson(point, F)
                    })
                )
        });
    }

    const deltaMessages = [];

    for (const p of polys) {

        for (
            let recipientId = 1;
            recipientId <= n;
            recipientId++
        ) {

            let alpha =
                BigInt(recipientId);

            let alphaPower =
                alpha;

            let delta =
                0n;

            for (
                const coefficient
                of p.coefficients
            ) {

                delta =
                    mod(
                        delta +
                        coefficient * alphaPower,
                        Q
                    );

                alphaPower =
                    mod(
                        alphaPower * alpha,
                        Q
                    );
            }

            // self-delta is local computation,
            // not a network message
            if (p.sender_id === recipientId) {
                continue;
            }

            deltaMessages.push({
                sender_id:
                    p.sender_id,

                recipient_id:
                    recipientId,

                recipient_alpha:
                    alpha.toString(),

                delta:
                    delta.toString()
            });
        }
    }

    const commitmentSizes =
        commitmentMessages.map(byteSize);

    const deltaSizes =
        deltaMessages.map(byteSize);

    const commitmentLogicalTotal =
        commitmentSizes.reduce(
            (a,b) => a+b, 0
        );

    const deltaTotal =
        deltaSizes.reduce(
            (a,b) => a+b, 0
        );

    /*
     * Each commitment broadcast must reach
     * the other n-1 administrators.
     */
    const commitmentDeliveryTotal =
        commitmentLogicalTotal *
        (n - 1);

    const networkTotal =
        commitmentDeliveryTotal +
        deltaTotal;

    console.log("");
    console.log("============================================");
    console.log("Proactive Refresh Communication");
    console.log("============================================");

    console.log("");
    console.log("Commitment broadcasts:");
    commitmentSizes.forEach(
        (b, i) =>
            console.log(
                `Admin ${i+1}: ${b} B`
            )
    );

    console.log("");
    console.log(
        "Commitment logical messages :",
        commitmentSizes.length
    );

    console.log(
        "Commitment logical total    :",
        commitmentLogicalTotal,
        "B"
    );

    console.log(
        "Commitment deliveries       :",
        n * (n - 1)
    );

    console.log(
        "Commitment network bytes    :",
        commitmentDeliveryTotal,
        "B"
    );

    console.log("");
    console.log(
        "Delta messages              :",
        deltaSizes.length
    );

    console.log(
        "Delta min                   :",
        Math.min(...deltaSizes),
        "B"
    );

    console.log(
        "Delta max                   :",
        Math.max(...deltaSizes),
        "B"
    );

    console.log(
        "Delta average               :",
        (
            deltaTotal /
            deltaSizes.length
        ).toFixed(2),
        "B"
    );

    console.log(
        "Delta total                 :",
        deltaTotal,
        "B"
    );

    console.log("");
    console.log("--------------------------------------------");

    console.log(
        "Logical messages            :",
        commitmentSizes.length +
        deltaSizes.length
    );

    console.log(
        "Point-to-point transmissions:",
        n * (n - 1) +
        deltaSizes.length
    );

    console.log(
        "TOTAL NETWORK BYTES         :",
        networkTotal,
        "B"
    );

    console.log("============================================");
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
