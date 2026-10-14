/**
 * Diagnose & fix "escaped template literal" corruption.
 * Some source files were saved with backslashes before backticks, `${`,
 * and double-quotes — probably a botched find/replace or editor export.
 *
 * Usage: node scripts/fix-escaped-backticks.js [--fix] [--file path]
 */
const fs = require('fs');
const path = require('path');

const args = process.argv.slice(2);
const doFix = args.includes('--fix');
const onlyFile = args.includes('--file') ? args[args.indexOf('--file') + 1] : null;

const srcDir = path.join(__dirname, '..', 'src');

/** Recursively collect .js files */
function walk(dir, acc) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full, acc);
        else if (entry.isFile() && entry.name.endsWith('.js')) acc.push(full);
    }
    return acc;
}

const files = onlyFile ? [onlyFile] : walk(srcDir, []);

let totalFixed = 0;
let found = 0;
for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');

    const bt = (content.match(/\\`/g) || []).length;
    const ds = (content.match(/\\\$\{/g) || []).length;
    const qs = (content.match(/\\"/g) || []).length;

    if (bt || ds || qs) {
        found++;
        console.log(file);
        console.log('   escaped-backticks: ' + bt + ' | escaped-${: ' + ds + ' | escaped-quotes: ' + qs);
        if (doFix) {
            let fixed = content.replace(/\\`/g, '`').replace(/\\\$\{/g, '${').replace(/\\"/g, '"');
            fs.writeFileSync(file, fixed, 'utf8');
            totalFixed += bt + ds + qs;
            console.log('   FIXED');
        } else {
            console.log('   (dry run -- pass --fix to apply)');
        }
    }
}
console.log('\nFiles affected: ' + found + ' | Total escaped sequences: ' + (doFix ? totalFixed : 'see above'));
