/**
 * 测试数据生成 CLI：
 *   npm run gen:testdata -- --out tests/testdata
 * 产出 synthetic.pcap / synthetic.pcapng / ground-truth.json
 */
import { writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { generateScenario } from './scenario';

async function main() {
  const args = process.argv.slice(2);
  const outIdx = args.indexOf('--out');
  const outDir = resolve(outIdx >= 0 ? args[outIdx + 1] : 'tests/testdata');

  const gt = await generateScenario({ outDir });
  await writeFile(join(outDir, 'ground-truth.json'), JSON.stringify(gt, null, 2), 'utf-8');
  console.log(`已生成测试包到 ${outDir}`);
  for (const g of gt) {
    console.log(`  - ${g.file}，注入事件 ${g.events.length} 个`);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
