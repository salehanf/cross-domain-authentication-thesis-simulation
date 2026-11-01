const fs = require("fs");
const path = require("path");
const os = require("os");
const config = require("../src/config");

function parseArgs(argv, extra = {}) {
    const args = {
        warmup: config.experiment.warmupRuns,
        runs: config.experiment.repetitions,
        ...extra
    };

    for (let i = 0; i < argv.length; i++) {
        const token = argv[i];
        if (!token.startsWith("--")) continue;

        const key = token.slice(2);
        const value = argv[i + 1];
        if (value === undefined || value.startsWith("--")) {
            throw new Error(`Missing value for --${key}`);
        }
        i++;

        if (key === "warmup" || key === "runs" || key === "depth") {
            const n = Number(value);
            if (!Number.isInteger(n) || n < 0 || (key !== "warmup" && n < 1)) {
                throw new Error(`Invalid --${key}: ${value}`);
            }
            args[key] = n;
        } else if (key === "output") {
            args.output = value;
        } else {
            throw new Error(`Unknown option: --${key}`);
        }
    }

    if (args.warmup < 0) throw new Error("warmup must be >= 0");
    if (args.runs < 1) throw new Error("runs must be >= 1");

    return args;
}

function percentile(sorted, p) {
    if (sorted.length === 0) return null;
    const rank = Math.ceil(p * sorted.length) - 1;
    return sorted[Math.max(0, Math.min(rank, sorted.length - 1))];
}

function summarize(values) {
    if (!Array.isArray(values) || values.length === 0) {
        throw new Error("Cannot summarize an empty sample set.");
    }

    const sorted = [...values].sort((a, b) => a - b);
    const n = values.length;
    const mean = values.reduce((a, b) => a + b, 0) / n;
    const median = n % 2 === 1
        ? sorted[(n - 1) / 2]
        : (sorted[n / 2 - 1] + sorted[n / 2]) / 2;

    const variance = n > 1
        ? values.reduce((sum, x) => sum + ((x - mean) ** 2), 0) / (n - 1)
        : 0;
    const stddev = Math.sqrt(variance);

    return {
        n,
        mean_ms: mean,
        median_ms: median,
        stddev_ms: stddev,
        min_ms: sorted[0],
        max_ms: sorted[sorted.length - 1],
        p95_ms: percentile(sorted, 0.95),
        cv_percent: mean === 0 ? 0 : (stddev / mean) * 100
    };
}

function summarizeMetricObjects(samples) {
    const keys = new Set();
    for (const sample of samples) {
        for (const key of Object.keys(sample)) keys.add(key);
    }

    const summary = {};
    for (const key of keys) {
        const values = samples
            .map(s => s[key])
            .filter(v => Number.isFinite(v));
        if (values.length) summary[key] = summarize(values);
    }
    return summary;
}

function defaultEnvironment() {
    return {
        platform: process.platform,
        arch: process.arch,
        node: process.version,
        cpu_model: os.cpus()?.[0]?.model ?? "unknown",
        cpu_logical_cores: os.cpus()?.length ?? null,
        memory_total_bytes: os.totalmem()
    };
}

function ensureDir(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

function writeJson(file, value) {
    ensureDir(path.dirname(file));
    fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function timestampForFilename() {
    return new Date().toISOString().replace(/[:.]/g, "-");
}

async function executeBenchmark({
    name,
    warmup,
    runs,
    operation,
    metadata = {},
    outputFile
}) {
    console.log("============================================");
    console.log(` Benchmark: ${name}`);
    console.log("============================================");
    console.log(`Warm-up runs : ${warmup}`);
    console.log(`Measured runs: ${runs}`);
    console.log("");

    for (let i = 0; i < warmup; i++) {
        await operation({ measured: false, index: i });
        process.stdout.write(`\rWarm-up: ${i + 1}/${warmup}`);
    }
    if (warmup > 0) process.stdout.write("\n");

    const samples = [];
    for (let i = 0; i < runs; i++) {
        const metrics = await operation({ measured: true, index: i });
        samples.push(metrics);
        process.stdout.write(`\rMeasured: ${i + 1}/${runs}`);
    }
    process.stdout.write("\n\n");

    const report = {
        benchmark: name,
        created_at: new Date().toISOString(),
        warmup_runs: warmup,
        measured_runs: runs,
        environment: defaultEnvironment(),
        metadata,
        summary: summarizeMetricObjects(samples),
        samples
    };

    writeJson(outputFile, report);

    console.log("Summary (ms):");
    for (const [metric, stats] of Object.entries(report.summary)) {
        console.log(
            `${metric.padEnd(24)} mean=${stats.mean_ms.toFixed(3)}  ` +
            `median=${stats.median_ms.toFixed(3)}  ` +
            `sd=${stats.stddev_ms.toFixed(3)}  p95=${stats.p95_ms.toFixed(3)}`
        );
    }
    console.log("");
    console.log(`Report: ${outputFile}`);
    console.log("============================================");

    return report;
}

module.exports = {
    parseArgs,
    summarize,
    summarizeMetricObjects,
    executeBenchmark,
    timestampForFilename
};
