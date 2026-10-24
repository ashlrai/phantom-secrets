// Reproduce the workbench card from our exact first-party ghost vector.
// Uses the repository's locked Sharp 0.35.5 dependency; no network inputs.
import fs from "node:fs";
import path from "node:path";
import sharp from "sharp";

const publicDirectory = path.resolve(import.meta.dirname, "../public");
const ghost = fs.readFileSync(path.join(publicDirectory, "phantom-world/phantom-mark.svg"));
const ghostUrl = `data:image/svg+xml;base64,${ghost.toString("base64")}`;
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <radialGradient id="ambient"><stop stop-color="#153d73"/><stop offset="1" stop-color="#050508"/></radialGradient>
    <linearGradient id="line"><stop stop-color="#60a5fa"/><stop offset="1" stop-color="#a78bfa"/></linearGradient>
  </defs>
  <rect width="1200" height="630" fill="#050508"/>
  <ellipse cx="1020" cy="70" rx="660" ry="540" fill="url(#ambient)" opacity=".7"/>
  <rect x="28" y="28" width="1144" height="574" rx="32" fill="none" stroke="#253349"/>
  <g fill="none" stroke="#3b82f6" opacity=".12"><path d="M680 105H1080M740 200H1120M835 285H1100M900 95V410M1010 65V460"/></g>
  <image href="${ghostUrl}" x="61" y="63" width="63" height="63"/>
  <g font-family="Arial,Helvetica,sans-serif">
    <text x="137" y="94" fill="#f5f5f7" font-size="32" font-weight="700">Phantom</text>
    <text x="139" y="120" fill="#a1a1b5" font-size="17">by AshlrAI</text>
    <text x="72" y="227" fill="#f5f5f7" font-size="63" font-weight="700" letter-spacing="-2">One place for your</text>
    <text x="72" y="302" fill="#f5f5f7" font-size="63" font-weight="700" letter-spacing="-2">engineering agents.</text>
    <text x="75" y="353" fill="#a1a1b5" font-size="23">Your models. Your tools. Your workflow.</text>
    <rect x="72" y="397" width="355" height="105" rx="20" fill="#0b1525" stroke="#406da0"/>
    <circle cx="103" cy="430" r="5" fill="#60a5fa"/>
    <text x="122" y="438" fill="#f5f5f7" font-size="25" font-weight="700">Work with me</text>
    <text x="102" y="474" fill="#a1a1b5" font-size="18">Converse · guide · review</text>
    <rect x="452" y="397" width="355" height="105" rx="20" fill="#171225" stroke="#7864a5"/>
    <circle cx="483" cy="430" r="5" fill="#a78bfa"/>
    <text x="502" y="438" fill="#f5f5f7" font-size="25" font-weight="700">Work for me</text>
    <text x="482" y="474" fill="#a1a1b5" font-size="18">Dispatch · trace · improve</text>
    <text x="75" y="557" fill="#808096" font-size="17">CLI subscriptions · API credits · local models · MCP &amp; CLI tools</text>
    <text x="1060" y="557" text-anchor="end" fill="#bfdbfe" font-size="23" font-weight="700">phm.dev</text>
  </g>
  <image href="${ghostUrl}" x="870" y="369" width="192" height="192" opacity=".88"/>
</svg>`;
async function main() {
  fs.writeFileSync(path.join(publicDirectory, "workbench-og.svg"), `${svg}\n`);
  await sharp(Buffer.from(svg)).png({ compressionLevel: 9 }).toFile(path.join(publicDirectory, "workbench-og.png"));
  const metadata = await sharp(path.join(publicDirectory, "workbench-og.png")).metadata();
  if (metadata.width !== 1200 || metadata.height !== 630) throw new Error("Unexpected card dimensions");
  console.log("Generated 1200×630 workbench card from the first-party Phantom ghost.");
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
