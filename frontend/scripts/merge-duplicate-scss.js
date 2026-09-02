import fs from "node:fs";

import postcss from "postcss";
import scss from "postcss-scss";

const file = process.argv[2];

if (!file) {
  console.error("Usage: node scripts/merge-duplicate-scss.js <file>");
  process.exit(1);
}

const source = fs.readFileSync(file, "utf8");

const root = postcss.parse(source, {
  from: file,
  parser: scss,
});

/**
 * Build a context key so we only merge selectors that exist
 * in the same SCSS nesting / at-rule context.
 */
function getContext(node) {
  const context = [];
  let parent = node.parent;

  while (parent && parent.type !== "root") {
    if (parent.type === "atrule") {
      context.unshift(`@${parent.name} ${parent.params}`);
    } else if (parent.type === "rule") {
      context.unshift(`rule:${parent.selector}`);
    }

    parent = parent.parent;
  }

  return context.join(" > ");
}

let merged = 0;

function processContainer(container) {
  const rules = new Map();

  for (const node of [...container.nodes]) {
    // Recursively process nested SCSS / at-rules first.
    if (node.nodes) {
      processContainer(node);
    }

    if (node.type !== "rule") {
      continue;
    }

    const selector = node.selector.trim();

    const context = getContext(node);

    const key = `${context}\0${selector}`;

    const previous = rules.get(key);

    if (!previous) {
      rules.set(key, node);
      continue;
    }

    // Move declarations from the duplicate into the first rule.
    for (const child of [...node.nodes]) {
      previous.append(child);
    }

    node.remove();
    merged++;
  }
}

processContainer(root);

if (merged === 0) {
  console.log(`No duplicate selectors found in ${file}`);
  process.exit(0);
}

fs.writeFileSync(file, root.toString());

console.log(`Merged ${merged} duplicate selector(s) in ${file}`);
