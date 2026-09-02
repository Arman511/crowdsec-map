import fs from "node:fs";
import path from "node:path";

import postcss from "postcss";
import scss from "postcss-scss";

const SRC_DIR = path.resolve("src");

const selectors = new Map();

function getScssFiles(dir) {
  const files = [];

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      files.push(...getScssFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith(".scss")) {
      files.push(fullPath);
    }
  }

  return files;
}

function getMediaContext(rule) {
  const media = [];

  let current = rule.parent;

  while (current) {
    if (current.type === "atrule" && current.name === "media") {
      media.unshift(current.params);
    }

    current = current.parent;
  }

  return media.join(" && ");
}

for (const file of getScssFiles(SRC_DIR)) {
  const source = fs.readFileSync(file, "utf8");

  const root = postcss.parse(source, {
    from: file,
    parser: scss,
  });

  root.walkRules((rule) => {
    const relativePath = path.relative(process.cwd(), file);

    const mediaContext = getMediaContext(rule);

    for (const selector of rule.selectors) {
      const normalizedSelector = selector
        .replace(/\s+/g, " ")
        .replace(/\s*>\s*/g, ">")
        .replace(/\s*\+\s*/g, "+")
        .replace(/\s*~\s*/g, "~")
        .trim();

      const key = `${mediaContext}||| ${normalizedSelector} `;

      if (!selectors.has(key)) {
        selectors.set(key, {
          selector: normalizedSelector,
          media: mediaContext,
          locations: [],
        });
      }

      selectors.get(key).locations.push({
        file: relativePath,
        line: rule.source.start.line,
      });
    }
  });
}

let foundDuplicates = false;

for (const { selector, media, locations } of selectors.values()) {
  const uniqueFiles = new Set(locations.map(({ file }) => file));

  if (uniqueFiles.size <= 1) {
    continue;
  }

  foundDuplicates = true;

  console.log(`\nDuplicate selector: ${selector}${media ? ` @media ${media}` : ""} `);

  for (const { file, line } of locations) {
    console.log(`  ${file}:${line} `);
  }
}

if (foundDuplicates) {
  console.error("\nDuplicate SCSS selectors found.");
  process.exit(1);
}

console.log("No duplicate SCSS selectors found.");
