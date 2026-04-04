import puppeteer from 'puppeteer';
import { mkdir } from 'fs/promises';

await mkdir('/Users/masonwyatt/Desktop/secrets project/video/public/screenshots', { recursive: true });

const browser = await puppeteer.launch({ headless: true, args: ['--window-size=1920,1080'] });
const page = await browser.newPage();
await page.setViewport({ width: 1920, height: 1080 });

// Capture multiple scroll positions of phm.dev
const positions = [
  { name: 'hero', scroll: 0, wait: 4000 },
  { name: 'how-it-works', scroll: 900, wait: 2000 },
  { name: 'before-after', scroll: 1800, wait: 2000 },
  { name: 'terminal', scroll: 2700, wait: 2000 },
  { name: 'features', scroll: 3600, wait: 2000 },
  { name: 'pricing', scroll: 4500, wait: 2000 },
];

await page.goto('https://phm.dev', { waitUntil: 'networkidle2', timeout: 15000 }).catch(() => {});
await new Promise(r => setTimeout(r, 4000));

for (const pos of positions) {
  await page.evaluate((y) => window.scrollTo(0, y), pos.scroll);
  await new Promise(r => setTimeout(r, pos.wait));
  await page.screenshot({ 
    path: `/Users/masonwyatt/Desktop/secrets project/video/public/screenshots/${pos.name}.jpeg`, 
    type: 'jpeg', quality: 90 
  });
  console.log(`Captured: ${pos.name}`);
}

await browser.close();
console.log('Done!');
