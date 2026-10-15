import { main } from "./cli.js";

process.exitCode = await main(process.argv.slice(2), {
    stdout: (l) => {
        process.stdout.write(`${l}\n`);
    },
    stderr: (l) => {
        process.stderr.write(`${l}\n`);
    },
});
