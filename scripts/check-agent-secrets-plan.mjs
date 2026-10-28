import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const planPath = 'docs/design/model-blind-agent-secrets.md';

const BLOCK_RE = /```json phantom-jobspec\s*\n([\s\S]*?)```/g;
const ID_RE = /^RQ-[A-Z0-9][A-Z0-9-]*$/;
const JOB_STATUSES = new Set(['proposed', 'dispatched', 'landed']);
const JOB_ROLES = new Set(['core', 'enabler']);
const CLAIM_EXPECTS = new Set(['present', 'absent']);

export function extractSpec(text, file = planPath) {
  const blocks = [...text.matchAll(BLOCK_RE)];
  if (blocks.length === 0) return { errors: [`${file}: no \`\`\`json phantom-jobspec block found`] };
  if (blocks.length > 1) return { errors: [`${file}: ${blocks.length} phantom-jobspec blocks; exactly one is allowed`] };
  try {
    return { spec: JSON.parse(blocks[0][1]), errors: [] };
  } catch (error) {
    return { errors: [`${file}: jobspec is not valid JSON: ${error.message}`] };
  }
}

function checkClaims(job, base) {
  const errors = [];
  for (const [index, claim] of (job.claims ?? []).entries()) {
    const where = `${job.id} claim ${index} (${claim.path ?? '?'})`;
    if (!CLAIM_EXPECTS.has(claim.expect)) {
      errors.push(`${where}: expect must be present|absent`);
      continue;
    }
    if (typeof claim.path !== 'string' || !claim.path) {
      errors.push(`${where}: missing path`);
      continue;
    }
    const file = resolve(base, claim.path);
    if (claim.expect === 'present') {
      if (!existsSync(file)) {
        errors.push(`${where}: expected file to exist on main`);
        continue;
      }
      if (claim.contains !== undefined) {
        if (typeof claim.contains !== 'string' || !claim.contains) {
          errors.push(`${where}: contains must be a non-empty string`);
        } else if (!readFileSync(file, 'utf8').includes(claim.contains)) {
          errors.push(`${where}: file does not contain ${JSON.stringify(claim.contains)}`);
        }
      }
    } else if (existsSync(file)) {
      errors.push(`${where}: expected absent but file exists — landing job must flip this claim`);
    }
  }
  return errors;
}

function checkAcyclic(jobs) {
  const byId = new Map(jobs.map((job) => [job.id, job]));
  const visiting = new Set();
  const done = new Set();
  const errors = [];
  const visit = (job, trail) => {
    if (done.has(job.id)) return;
    if (visiting.has(job.id)) {
      errors.push(`dependency cycle: ${[...trail, job.id].join(' -> ')}`);
      return;
    }
    visiting.add(job.id);
    for (const dep of job.depends_on) {
      const target = byId.get(dep);
      if (target) visit(target, [...trail, job.id]);
    }
    visiting.delete(job.id);
    done.add(job.id);
  };
  for (const job of jobs) visit(job, []);
  return errors;
}

export function checkSpec(spec, base = root) {
  const errors = [];
  if (spec === null || typeof spec !== 'object' || Array.isArray(spec)) {
    return ['jobspec: must be a JSON object'];
  }
  if (spec.schemaVersion !== 1) errors.push('jobspec: schemaVersion must be 1');
  const required = spec.requiredCoverage;
  const vocabulary = new Set(spec.coverVocabulary ?? []);
  if (!Array.isArray(required) || required.length === 0) {
    errors.push('jobspec: requiredCoverage must be a non-empty array');
  }
  if (!Array.isArray(spec.jobs) || spec.jobs.length === 0) {
    return [...errors, 'jobspec: jobs must be a non-empty array'];
  }

  const ids = new Set();
  const covered = new Set();
  for (const [index, job] of spec.jobs.entries()) {
    const where = job?.id ?? `jobs[${index}]`;
    if (typeof job?.id !== 'string' || !ID_RE.test(job.id)) {
      errors.push(`${where}: id must match ${ID_RE}`);
    } else if (ids.has(job.id)) {
      errors.push(`${job.id}: duplicate job id`);
    }
    ids.add(job?.id);
    for (const field of ['title', 'scope']) {
      if (typeof job?.[field] !== 'string' || !job[field]) {
        errors.push(`${where}: missing ${field}`);
      }
    }
    if (!JOB_ROLES.has(job?.role)) errors.push(`${where}: role must be core|enabler`);
    if (!JOB_STATUSES.has(job?.status)) errors.push(`${where}: status must be proposed|dispatched|landed`);
    if (job?.status === 'dispatched' && typeof job.branch !== 'string') {
      errors.push(`${where}: dispatched job must name its branch`);
    }
    if (!Array.isArray(job?.covers) || job.covers.length === 0) {
      errors.push(`${where}: covers must be a non-empty array`);
    } else {
      for (const tag of job.covers) {
        if (!vocabulary.has(tag)) errors.push(`${where}: unknown covers tag ${JSON.stringify(tag)}`);
        covered.add(tag);
      }
    }
    if (!Array.isArray(job?.depends_on)) {
      errors.push(`${where}: depends_on must be an array`);
    }
    for (const field of ['acceptance', 'tests']) {
      if (!Array.isArray(job?.[field]) || job[field].length === 0) {
        errors.push(`${where}: ${field} must be a non-empty array`);
      }
    }
    for (const path of job?.surfaces?.modified ?? []) {
      if (!existsSync(resolve(base, path))) {
        errors.push(`${where}: surfaces.modified path does not exist: ${path}`);
      }
    }
    errors.push(...checkClaims(job ?? {}, base));
  }

  for (const job of spec.jobs) {
    for (const dep of job?.depends_on ?? []) {
      if (!ids.has(dep)) errors.push(`${job.id}: depends_on references unknown job ${dep}`);
    }
  }
  for (const tag of required ?? []) {
    if (!covered.has(tag)) errors.push(`jobspec: required coverage ${JSON.stringify(tag)} not claimed by any job`);
  }
  errors.push(...checkAcyclic(spec.jobs));
  return errors;
}

export function checkPlan(base = root) {
  const file = resolve(base, planPath);
  if (!existsSync(file)) return [`${planPath}: file missing`];
  const { spec, errors } = extractSpec(readFileSync(file, 'utf8'));
  if (errors.length > 0) return errors;
  return checkSpec(spec, base);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const errors = checkPlan();
  for (const error of errors) console.error(error);
  if (errors.length) process.exitCode = 1;
  else console.log(`PASS: ${planPath} jobspec is well-formed and claims hold`);
}
