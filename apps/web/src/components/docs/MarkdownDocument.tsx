import type { ReactNode } from "react";
import { Fragment } from "react";
import path from "node:path";
import { publicDocHrefForMarkdownFile } from "@/lib/public-docs";

interface MarkdownDocumentProps {
  markdown: string;
  sourceFile: string;
}

const REPOSITORY_SOURCE =
  "https://github.com/ashlrai/phantom-secrets/blob/main/";
const INLINE_TOKEN = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^)]+\)|<https?:\/\/[^>]+>)/g;

function splitTableRow(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim());
}

function isTableSeparator(line: string): boolean {
  const cells = splitTableRow(line);
  return cells.length > 0 && cells.every((cell) => /^:?-{3,}:?$/.test(cell));
}

function isBlockStart(lines: string[], index: number): boolean {
  const line = lines[index] ?? "";
  const next = lines[index + 1] ?? "";

  return (
    /^#{1,6}\s+/.test(line) ||
    /^```/.test(line) ||
    /^>\s?/.test(line) ||
    /^\s*[-*+]\s+/.test(line) ||
    /^\s*\d+\.\s+/.test(line) ||
    /^(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line) ||
    (line.includes("|") && isTableSeparator(next))
  );
}

function headingId(value: string): string {
  return value
    .toLowerCase()
    .replace(/`([^`]+)`/g, "$1")
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}

function resolveHref(href: string, sourceFile: string): string | undefined {
  if (href.startsWith("#")) return href;
  // A protocol-relative URL starts with two slashes and can leave phm.dev.
  // Treat only a single-leading-slash path as an on-site link.
  if (href.startsWith("/") && !href.startsWith("//")) return href;
  if (/^(?:https?:|mailto:)/i.test(href)) return href;
  if (/^[a-z][a-z0-9+.-]*:/i.test(href)) return undefined;

  const hashIndex = href.indexOf("#");
  const relativePath = hashIndex >= 0 ? href.slice(0, hashIndex) : href;
  const fragment = hashIndex >= 0 ? href.slice(hashIndex) : "";
  const repositoryPath = path.posix.normalize(
    path.posix.join("docs", path.posix.dirname(sourceFile), relativePath),
  );

  if (repositoryPath.startsWith("../")) return undefined;

  if (repositoryPath.startsWith("docs/") && repositoryPath.endsWith(".md")) {
    const localHref = publicDocHrefForMarkdownFile(
      path.posix.basename(repositoryPath),
    );
    if (localHref) return `${localHref}${fragment}`;
  }

  return `${REPOSITORY_SOURCE}${repositoryPath}${fragment}`;
}

function renderInline(
  value: string,
  sourceFile: string,
  keyPrefix: string,
): ReactNode[] {
  const output: ReactNode[] = [];
  let cursor = 0;

  for (const match of value.matchAll(INLINE_TOKEN)) {
    const token = match[0];
    const index = match.index ?? 0;

    if (index > cursor) output.push(value.slice(cursor, index));

    if (token.startsWith("`")) {
      output.push(<code key={`${keyPrefix}-${index}`}>{token.slice(1, -1)}</code>);
    } else if (token.startsWith("**")) {
      output.push(
        <strong key={`${keyPrefix}-${index}`}>
          {renderInline(token.slice(2, -2), sourceFile, `${keyPrefix}-${index}`)}
        </strong>,
      );
    } else if (token.startsWith("*")) {
      output.push(
        <em key={`${keyPrefix}-${index}`}>
          {renderInline(token.slice(1, -1), sourceFile, `${keyPrefix}-${index}`)}
        </em>,
      );
    } else if (token.startsWith("<")) {
      const href = token.slice(1, -1);
      output.push(
        <a key={`${keyPrefix}-${index}`} href={href}>
          {href}
        </a>,
      );
    } else {
      const link = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(token);
      const href = link ? resolveHref(link[2], sourceFile) : undefined;
      output.push(
        href ? (
          <a key={`${keyPrefix}-${index}`} href={href}>
            {link?.[1]}
          </a>
        ) : (
          link?.[1] ?? token
        ),
      );
    }

    cursor = index + token.length;
  }

  if (cursor < value.length) output.push(value.slice(cursor));
  return output;
}

export function MarkdownDocument({
  markdown,
  sourceFile,
}: MarkdownDocumentProps) {
  // React escapes every text node produced below. Keep the Markdown source intact
  // instead of treating HTML comments as a sanitization boundary.
  const lines = markdown.split(/\r?\n/);
  const blocks: ReactNode[] = [];
  const headingCounts = new Map<string, number>();
  let index = 0;

  while (index < lines.length) {
    const line = lines[index];

    if (!line.trim()) {
      index += 1;
      continue;
    }

    const heading = /^(#{1,6})\s+(.+)$/.exec(line);
    if (heading) {
      const level = heading[1].length;
      const value = heading[2].replace(/\s+#+\s*$/, "");
      const baseId = headingId(value) || `section-${index}`;
      const count = headingCounts.get(baseId) ?? 0;
      headingCounts.set(baseId, count + 1);
      const id = count === 0 ? baseId : `${baseId}-${count + 1}`;
      const Heading = `h${level}` as keyof React.JSX.IntrinsicElements;

      blocks.push(
        <Heading id={id} key={`heading-${index}`}>
          <a className="docs-article__heading-link" href={`#${id}`} aria-label={`Link to ${value}`}>
            {renderInline(value, sourceFile, `heading-${index}`)}
          </a>
        </Heading>,
      );
      index += 1;
      continue;
    }

    const fence = /^```([^\s]*)\s*$/.exec(line);
    if (fence) {
      const language = fence[1];
      const code: string[] = [];
      index += 1;
      while (index < lines.length && !/^```\s*$/.test(lines[index])) {
        code.push(lines[index]);
        index += 1;
      }
      if (index < lines.length) index += 1;
      blocks.push(
        <pre key={`code-${index}`}>
          <code className={language ? `language-${language}` : undefined}>
            {code.join("\n")}
          </code>
        </pre>,
      );
      continue;
    }

    if (line.includes("|") && isTableSeparator(lines[index + 1] ?? "")) {
      const header = splitTableRow(line);
      const rows: string[][] = [];
      index += 2;
      while (index < lines.length && lines[index].includes("|") && lines[index].trim()) {
        rows.push(splitTableRow(lines[index]));
        index += 1;
      }
      blocks.push(
        <div className="docs-article__table-wrap" key={`table-${index}`}>
          <table>
            <thead>
              <tr>
                {header.map((cell, cellIndex) => (
                  <th scope="col" key={`head-${cellIndex}`}>
                    {renderInline(cell, sourceFile, `table-head-${index}-${cellIndex}`)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, rowIndex) => (
                <tr key={`row-${rowIndex}`}>
                  {header.map((_, cellIndex) => (
                    <td key={`cell-${cellIndex}`}>
                      {renderInline(
                        row[cellIndex] ?? "",
                        sourceFile,
                        `table-${index}-${rowIndex}-${cellIndex}`,
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>,
      );
      continue;
    }

    const listMatch = /^\s*([-*+]|\d+\.)\s+(.+)$/.exec(line);
    if (listMatch) {
      const ordered = /\d+\./.test(listMatch[1]);
      const items: string[] = [];

      while (index < lines.length) {
        const itemMatch = /^\s*([-*+]|\d+\.)\s+(.+)$/.exec(lines[index]);
        if (!itemMatch || /\d+\./.test(itemMatch[1]) !== ordered) break;

        let item = itemMatch[2];
        index += 1;
        while (
          index < lines.length &&
          lines[index].trim() &&
          !isBlockStart(lines, index)
        ) {
          item += ` ${lines[index].trim()}`;
          index += 1;
        }
        items.push(item);
        if (!lines[index]?.trim()) break;
      }

      const List = ordered ? "ol" : "ul";
      blocks.push(
        <List key={`list-${index}`}>
          {items.map((item, itemIndex) => (
            <li key={`item-${itemIndex}`}>
              {renderInline(item, sourceFile, `list-${index}-${itemIndex}`)}
            </li>
          ))}
        </List>,
      );
      continue;
    }

    if (/^>\s?/.test(line)) {
      const quote: string[] = [];
      while (index < lines.length && /^>\s?/.test(lines[index])) {
        quote.push(lines[index].replace(/^>\s?/, ""));
        index += 1;
      }
      blocks.push(
        <blockquote key={`quote-${index}`}>
          {renderInline(quote.join(" "), sourceFile, `quote-${index}`)}
        </blockquote>,
      );
      continue;
    }

    if (/^(?:-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      blocks.push(<hr key={`rule-${index}`} />);
      index += 1;
      continue;
    }

    const paragraph: string[] = [];
    while (index < lines.length && lines[index].trim() && !isBlockStart(lines, index)) {
      paragraph.push(lines[index].trim());
      index += 1;
    }
    blocks.push(
      <p key={`paragraph-${index}`}>
        {renderInline(paragraph.join(" "), sourceFile, `paragraph-${index}`)}
      </p>,
    );
  }

  return <Fragment>{blocks}</Fragment>;
}
