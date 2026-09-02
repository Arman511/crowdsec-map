import fs from "node:fs";
import path from "node:path";

import postcss from "postcss";
import scss from "postcss-scss";

const SRC_DIR = path.resolve("src");

const STYLES_DIR = path.join(SRC_DIR, "styles");

const INPUT_FILE = path.resolve(process.argv[2] ?? "src/styles.scss");

const BASE_FILE = path.join(STYLES_DIR, "_base.scss");

if (!fs.existsSync(INPUT_FILE)) {
  console.error(`SCSS file not found: ${INPUT_FILE}`);
  process.exit(1);
}

/**
 * Recursively find files.
 */
function walk(dir) {
  const files = [];

  for (const entry of fs.readdirSync(dir, {
    withFileTypes: true,
  })) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      files.push(...walk(fullPath));
    } else {
      files.push(fullPath);
    }
  }

  return files;
}

/**
 * Escape a string for use inside a regular expression.
 */
function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Extract CSS class names from TSX/JSX.
 *
 * This intentionally looks for strings rather than attempting
 * to parse JavaScript expressions.
 *
 * Examples supported:
 *
 * className="foo bar"
 * className={"foo bar"}
 * className={condition ? "foo" : "bar"}
 * className={cn("foo", condition && "bar")}
 */
function extractClassNames(content) {
  const classes = new Set();

  const stringRegex = /["'`]([^"'`]*?)["'`]/g;

  for (const match of content.matchAll(stringRegex)) {
    const value = match[1];

    for (const className of value.split(/\s+/)) {
      if (/^[a-zA-Z_][a-zA-Z0-9_-]*$/.test(className)) {
        classes.add(className);
      }
    }
  }

  return classes;
}

/**
 * Determine which classes from a selector are known to us.
 */
function getClassesInSelector(selector, classNames) {
  const matches = new Set();

  for (const className of classNames) {
    const pattern = new RegExp(`\\.${escapeRegex(className)}(?![a-zA-Z0-9_-])`);

    if (pattern.test(selector)) {
      matches.add(className);
    }
  }

  return matches;
}

/**
 * Return all TSX files and the classes they use.
 */
function getClassOwners() {
  const tsxFiles = walk(SRC_DIR).filter((file) => /\.(tsx|jsx)$/.test(file));

  const classOwners = new Map();

  for (const file of tsxFiles) {
    const content = fs.readFileSync(file, "utf8");

    const classes = extractClassNames(content);

    for (const className of classes) {
      if (!classOwners.has(className)) {
        classOwners.set(className, []);
      }

      classOwners.get(className).push(file);
    }
  }

  return {
    tsxFiles,
    classOwners,
  };
}

/**
 * Get the owner of a single CSS class.
 *
 * Returns:
 *
 * {
 *   type: "unique",
 *   file: "/.../Map.tsx"
 * }
 *
 * or:
 *
 * {
 *   type: "shared"
 * }
 *
 * or:
 *
 * {
 *   type: "unknown"
 * }
 */
function getClassOwner(className, classOwners) {
  const owners = classOwners.get(className);

  if (!owners || owners.length === 0) {
    return {
      type: "unknown",
    };
  }

  if (owners.length === 1) {
    return {
      type: "unique",
      file: owners[0],
    };
  }

  return {
    type: "shared",
  };
}

/**
 * Split a selector list into individual selectors.
 *
 * We cannot simply use selector.split(",") because commas can
 * appear inside:
 *
 * :not(...)
 * :is(...)
 * :has(...)
 * attribute values
 * etc.
 */
function splitSelectorList(selector) {
  const selectors = [];

  let current = "";

  let parentheses = 0;

  let brackets = 0;

  let quote = null;

  let escaped = false;

  for (const char of selector) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }

    if (char === "\\") {
      current += char;
      escaped = true;
      continue;
    }

    if (quote) {
      current += char;

      if (char === quote) {
        quote = null;
      }

      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      current += char;
      continue;
    }

    if (char === "(") {
      parentheses++;
      current += char;
      continue;
    }

    if (char === ")") {
      parentheses--;
      current += char;
      continue;
    }

    if (char === "[") {
      brackets++;
      current += char;
      continue;
    }

    if (char === "]") {
      brackets--;
      current += char;
      continue;
    }

    if (char === "," && parentheses === 0 && brackets === 0) {
      if (current.trim()) {
        selectors.push(current.trim());
      }

      current = "";
      continue;
    }

    current += char;
  }

  if (current.trim()) {
    selectors.push(current.trim());
  }

  return selectors;
}

/**
 * Determine which TSX file owns an individual selector.
 *
 * A selector is component-owned only when:
 *
 * 1. It contains at least one known class.
 * 2. Every known class belongs to the same TSX file.
 * 3. There are no shared classes involved.
 *
 * Selectors without a known class remain in _base.scss.
 */
function getSelectorOwner(selector, classOwners) {
  const knownClasses = getClassesInSelector(selector, classOwners.keys());

  if (knownClasses.size === 0) {
    return {
      type: "base",
    };
  }

  /*
   * Find every class in the selector in the order it
   * appears in the selector.
   */
  const classesInOrder = [];

  for (const className of classOwners.keys()) {
    const pattern = new RegExp(`\\.${escapeRegex(className)}(?![a-zA-Z0-9_-])`, "g");

    for (const match of selector.matchAll(pattern)) {
      classesInOrder.push({
        className,
        index: match.index,
      });
    }
  }

  classesInOrder.sort((a, b) => a.index - b.index);

  /*
   * The final component-specific class determines ownership.
   *
   * Example:
   *
   * .mapStage > .liveMapStack > .activityTrend
   *
   * mapStage       -> App.tsx
   * liveMapStack   -> LiveMap.tsx
   * activityTrend  -> LiveEvents.tsx
   *
   * Therefore the rule belongs to LiveEvents.tsx.
   */
  for (let i = classesInOrder.length - 1; i >= 0; i--) {
    const className = classesInOrder[i].className;

    const owner = getClassOwner(className, classOwners);

    if (owner.type === "unique") {
      return {
        type: "component",
        file: owner.file,
      };
    }

    /*
     * Shared classes don't provide a reliable owner.
     * Continue looking backwards for a unique class.
     */
  }

  return {
    type: "base",
  };
}

/**
 * Create a rule containing a subset of selectors.
 */
function cloneRuleWithSelectors(rule, selectors) {
  if (selectors.length === 0) {
    return null;
  }

  const clone = rule.clone({
    nodes: [],
  });

  clone.selector = selectors.join(",\n");

  for (const child of rule.nodes ?? []) {
    clone.append(child.clone());
  }

  return clone;
}

/**
 * Split a CSS rule between components/base.
 *
 * Example:
 *
 * body,
 * .appShell,
 * .mapStage {
 *     ...
 * }
 *
 * becomes:
 *
 * _base.scss:
 *
 * body {
 *     ...
 * }
 *
 * App.scss:
 *
 * .appShell {
 *     ...
 * }
 *
 * Map.scss:
 *
 * .mapStage {
 *     ...
 * }
 */
function splitRule(rule, classOwners) {
  const selectors = splitSelectorList(rule.selector);

  const groups = new Map();

  for (const selector of selectors) {
    const ownership = getSelectorOwner(selector, classOwners);

    let key;

    if (ownership.type === "component") {
      key = ownership.file;
    } else {
      key = "base";
    }

    if (!groups.has(key)) {
      groups.set(key, []);
    }

    groups.get(key).push(selector);
  }

  const result = [];

  for (const [owner, ownerSelectors] of groups) {
    const cloned = cloneRuleWithSelectors(rule, ownerSelectors);

    if (!cloned) {
      continue;
    }

    result.push({
      owner,
      node: cloned,
    });
  }

  return result;
}

/**
 * Recursively split a node.
 *
 * This is the important part:
 *
 * @media
 * @supports
 * @container
 * theme selectors
 * etc.
 *
 * are treated as containers rather than being moved as
 * one indivisible block.
 */
function splitNode(node, classOwners) {
  /*
   * Normal CSS/SCSS rule.
   */
  if (node.type === "rule") {
    return splitRule(node, classOwners);
  }

  /*
   * At-rules without child nodes:
   *
   * @font-face
   * @import
   * @charset
   * etc.
   *
   * These are global.
   */
  if (!node.nodes) {
    return [
      {
        owner: "base",
        node: node.clone(),
      },
    ];
  }

  /*
   * Recursively split the children.
   */
  const groups = new Map();

  for (const child of node.nodes) {
    const pieces = splitNode(child, classOwners);

    for (const piece of pieces) {
      if (!groups.has(piece.owner)) {
        groups.set(piece.owner, []);
      }

      groups.get(piece.owner).push(piece.node);
    }
  }

  const result = [];

  for (const [owner, children] of groups) {
    if (children.length === 0) {
      continue;
    }

    /*
     * Preserve the original at-rule wrapper.
     *
     * Example:
     *
     * @media (...) {
     *     .toolbarStatus { ... }
     * }
     *
     * remains:
     *
     * @media (...) {
     *     .toolbarStatus { ... }
     * }
     */
    const clone = node.clone({
      nodes: [],
    });

    for (const child of children) {
      clone.append(child);
    }

    result.push({
      owner,
      node: clone,
    });
  }

  return result;
}

/**
 * Remove exact duplicate rules while preserving nesting.
 */
function deduplicate(root) {
  const seen = new Set();

  root.walk((node) => {
    if (node.type !== "rule") {
      return;
    }

    const key = node.toString();

    if (seen.has(key)) {
      node.remove();
    } else {
      seen.add(key);
    }
  });
}

/**
 * Add an SCSS import to a TSX file.
 *
 * Does nothing if the import already exists.
 */
function addImport(tsxFile, scssFile) {
  let source = fs.readFileSync(tsxFile, "utf8");

  const importPath = path.relative(path.dirname(tsxFile), scssFile).replaceAll("\\", "/");

  const normalizedPath = importPath.startsWith(".") ? importPath : `./${importPath}`;

  const escapedPath = escapeRegex(normalizedPath);

  const importRegex = new RegExp(`import\\s+["']${escapedPath}["'];?`);

  if (importRegex.test(source)) {
    return false;
  }

  const importStatement = `import "${normalizedPath}";`;

  const lines = source.split("\n");

  let lastImportIndex = -1;

  for (let i = 0; i < lines.length; i++) {
    /*
     * Ignore imports inside comments.
     *
     * This is intentionally simple because normal TSX
     * imports appear at the beginning of a line.
     */
    if (/^\s*import\s+/.test(lines[i])) {
      lastImportIndex = i;
    }
  }

  if (lastImportIndex >= 0) {
    lines.splice(lastImportIndex + 1, 0, importStatement);
  } else {
    lines.unshift(importStatement, "");
  }

  fs.writeFileSync(tsxFile, lines.join("\n"), "utf8");

  return true;
}

/**
 * Main.
 */
const { tsxFiles, classOwners } = getClassOwners();

console.log(`Found ${tsxFiles.length} TSX/JSX files.`);

console.log(`Found ${classOwners.size} CSS classes.`);

const source = fs.readFileSync(INPUT_FILE, "utf8");

const root = postcss.parse(source, {
  from: INPUT_FILE,
  parser: scss,
});

const outputRoots = new Map();

const baseRoot = postcss.root();

for (const node of root.nodes) {
  const pieces = splitNode(node, classOwners);

  for (const piece of pieces) {
    if (piece.owner === "base") {
      baseRoot.append(piece.node);
      continue;
    }

    if (!outputRoots.has(piece.owner)) {
      outputRoots.set(piece.owner, postcss.root());
    }

    outputRoots.get(piece.owner).append(piece.node);
  }
}

/*
 * Make sure the styles directory exists.
 */
fs.mkdirSync(STYLES_DIR, {
  recursive: true,
});

/*
 * Write _base.scss.
 */
if (baseRoot.nodes.length > 0) {
  deduplicate(baseRoot);

  fs.writeFileSync(BASE_FILE, `${baseRoot.toString().trim()}\n`, "utf8");

  console.log(`✓ ${path.relative(process.cwd(), BASE_FILE)}`);
}

/*
 * Write component styles.
 */
let filesWritten = 0;

let importsAdded = 0;

for (const [tsxFile, outputRoot] of outputRoots) {
  deduplicate(outputRoot);

  if (!outputRoot.nodes.length) {
    continue;
  }

  const relativeTsx = path.relative(SRC_DIR, tsxFile);

  const parsed = path.parse(relativeTsx);

  const outputFile = path.join(STYLES_DIR, parsed.dir, `${parsed.name}.scss`);

  fs.mkdirSync(path.dirname(outputFile), {
    recursive: true,
  });

  fs.writeFileSync(outputFile, `${outputRoot.toString().trim()}\n`, "utf8");

  console.log(`✓ ${path.relative(process.cwd(), tsxFile)}`);

  console.log(`  → ${path.relative(process.cwd(), outputFile)}`);

  filesWritten++;

  if (addImport(tsxFile, outputFile)) {
    console.log("  + Added SCSS import");

    importsAdded++;
  } else {
    console.log("  = SCSS import already exists");
  }
}

/*
 * App.tsx always receives _base.scss.
 */
const appFile = tsxFiles.find((file) => path.basename(file) === "App.tsx");

if (appFile && fs.existsSync(BASE_FILE)) {
  if (addImport(appFile, BASE_FILE)) {
    console.log(`✓ Added _base.scss to App.tsx`);
  } else {
    console.log("✓ App.tsx already imports _base.scss");
  }
}

console.log();
console.log(`Component SCSS files: ${filesWritten}`);
console.log(`Component imports added: ${importsAdded}`);
console.log();
console.log("Original styles.scss was NOT modified.");
