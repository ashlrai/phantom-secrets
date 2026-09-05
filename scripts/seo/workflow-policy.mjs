const READ_ONLY_PERMISSIONS = Object.freeze({ contents: "read" });

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function stripYamlComment(source) {
  let quote = null;
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (quote === "'") {
      if (character === "'" && source[index + 1] === "'") index += 1;
      else if (character === "'") quote = null;
      continue;
    }
    if (quote === '"') {
      if (character === "\\") index += 1;
      else if (character === '"') quote = null;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      continue;
    }
    if (character === "#" && (index === 0 || /\s/.test(source[index - 1]))) {
      return source.slice(0, index).trimEnd();
    }
  }
  return source.trimEnd();
}

function lineRecord(source, index) {
  invariant(!/^\s*\t/.test(source), `workflow line ${index + 1} uses tab indentation`);
  const indent = source.match(/^ */)[0].length;
  return {
    index,
    indent,
    content: stripYamlComment(source.slice(indent)).trim(),
  };
}

function parseEntry(record, label) {
  const match = record.content.match(/^([A-Za-z0-9_-]+):(?:\s*(.*))?$/);
  invariant(match, `${label} on line ${record.index + 1} must be a literal YAML mapping entry`);
  return { key: match[1], value: match[2] ?? "" };
}

function parseLiteralPermissions(records, header, limit, label) {
  const declaration = parseEntry(header, label);
  invariant(declaration.key === "permissions", `${label} has an invalid header`);
  invariant(
    declaration.value === "",
    `${label} must be an explicit mapping, not ${declaration.value || "an empty scalar"}`,
  );

  const permissions = {};
  for (let index = header.index + 1; index < limit; index += 1) {
    const record = records[index];
    if (!record.content) continue;
    if (record.indent <= header.indent) break;
    invariant(
      record.indent === header.indent + 2,
      `${label} line ${record.index + 1} has unsupported nesting`,
    );
    const entry = parseEntry(record, label);
    invariant(entry.value !== "", `${label}.${entry.key} must be a scalar`);
    invariant(!Object.hasOwn(permissions, entry.key), `${label}.${entry.key} is duplicated`);
    permissions[entry.key] = entry.value.replace(/^(['"])(.*)\1$/, "$2");
  }
  invariant(Object.keys(permissions).length > 0, `${label} must not be empty`);
  return permissions;
}

function assertExactReadOnlyPermissions(permissions, label) {
  const entries = Object.entries(permissions);
  invariant(
    entries.length === 1 &&
      entries[0][0] === "contents" &&
      entries[0][1] === READ_ONLY_PERMISSIONS.contents,
    `${label} must be exactly contents: read`,
  );
}

function findUniqueHeader(records, key, indent, start, limit, label) {
  const matches = [];
  for (let index = start; index < limit; index += 1) {
    const record = records[index];
    if (!record.content || record.indent !== indent) continue;
    const entry = parseEntry(record, label);
    if (entry.key === key) matches.push(record);
  }
  invariant(matches.length === 1, `${label} must declare ${key} exactly once`);
  return matches[0];
}

function sectionEnd(records, header, limit, childIndent) {
  for (let index = header.index + 1; index < limit; index += 1) {
    const record = records[index];
    if (record.content && record.indent < childIndent) return index;
  }
  return limit;
}

export function containsWorkflowSecretReference(source) {
  const expressionPattern = /\$\{\{([\s\S]*?)\}\}/g;
  for (const match of source.matchAll(expressionPattern)) {
    if (/\bsecrets\b/i.test(match[1])) return true;
  }
  return /^[ \t]*secrets[ \t]*:/im.test(source);
}

export function parseWorkflowPolicy(source) {
  invariant(typeof source === "string" && source.trim(), "workflow source must be non-empty text");
  invariant(!containsWorkflowSecretReference(source), "workflow must not reference or inherit secrets");
  const records = source.split(/\r?\n/).map(lineRecord);
  const workflowPermissionsHeader = findUniqueHeader(
    records,
    "permissions",
    0,
    0,
    records.length,
    "workflow",
  );
  const workflowPermissions = parseLiteralPermissions(
    records,
    workflowPermissionsHeader,
    records.length,
    "workflow.permissions",
  );
  assertExactReadOnlyPermissions(workflowPermissions, "workflow.permissions");

  const jobsHeader = findUniqueHeader(records, "jobs", 0, 0, records.length, "workflow");
  invariant(parseEntry(jobsHeader, "workflow.jobs").value === "", "workflow.jobs must be a mapping");
  const jobsEnd = sectionEnd(records, jobsHeader, records.length, 1);
  const jobHeaders = [];
  for (let index = jobsHeader.index + 1; index < jobsEnd; index += 1) {
    const record = records[index];
    if (!record.content || record.indent !== 2) continue;
    const entry = parseEntry(record, "workflow.jobs");
    invariant(entry.value === "", `workflow.jobs.${entry.key} must be a mapping`);
    jobHeaders.push(record);
  }
  invariant(jobHeaders.length > 0, "workflow.jobs must contain at least one job");

  const jobs = {};
  for (let index = 0; index < jobHeaders.length; index += 1) {
    const jobHeader = jobHeaders[index];
    const jobId = parseEntry(jobHeader, "workflow.jobs").key;
    invariant(!Object.hasOwn(jobs, jobId), `workflow.jobs.${jobId} is duplicated`);
    const jobEnd = jobHeaders[index + 1]?.index ?? jobsEnd;
    const permissionsHeader = findUniqueHeader(
      records,
      "permissions",
      4,
      jobHeader.index + 1,
      jobEnd,
      `workflow.jobs.${jobId}`,
    );
    const permissions = parseLiteralPermissions(
      records,
      permissionsHeader,
      jobEnd,
      `workflow.jobs.${jobId}.permissions`,
    );
    assertExactReadOnlyPermissions(permissions, `workflow.jobs.${jobId}.permissions`);
    jobs[jobId] = { permissions };
  }

  return { workflowPermissions, jobs };
}

export function assertReadOnlyWorkflowPolicy(source) {
  return parseWorkflowPolicy(source);
}
