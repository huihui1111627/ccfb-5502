/**
 * 分块数据源抽象。浏览器用 File.slice()，Node 测试用 fd 预读；
 * 读取器只依赖这个接口，因此同一份解析代码两端可跑。
 */
export interface ChunkSource {
  size: number;
  /** 读取 [offset, offset+len)，返回的 ArrayBuffer 长度可能小于 len（EOF） */
  read(offset: number, len: number): Promise<ArrayBuffer>;
}

export const DEFAULT_CHUNK = 4 * 1024 * 1024; // 4 MiB

/** 浏览器 File / Blob 数据源：不把整个文件读进内存 */
export class BlobChunkSource implements ChunkSource {
  constructor(public readonly blob: Blob) {}
  get size(): number {
    return this.blob.size;
  }
  async read(offset: number, len: number): Promise<ArrayBuffer> {
    return this.blob.slice(offset, Math.min(offset + len, this.blob.size)).arrayBuffer();
  }
}

/**
 * 顺序分块拉取器：维护一块滑动窗口，上层按字节消费，不足时异步拉取下一块。
 * 注意：返回的 Uint8Array 视图在下次 pull/consume 后可能失效，需要留存必须 copy。
 *
 * 偏移模型（关键）：
 *  - readCursor：已从源拉取到的文件绝对位置
 *  - windowStart：当前窗口首字节对应的文件绝对偏移
 *  - pos：窗口内已消费位置
 * 三者独立维护，合并窗口时同步平移 windowStart，保证 fileOffset 永远准确。
 */
export class ChunkPuller {
  private buf = new Uint8Array(0);
  private pos = 0;
  private windowStart = 0;
  private readCursor = 0;
  private eof = false;

  constructor(
    private src: ChunkSource,
    private chunkSize = DEFAULT_CHUNK,
  ) {}

  /** 已从文件读取的总字节数（进度条用） */
  get fetched(): number {
    return this.readCursor;
  }

  /** 当前窗口内尚未消费的字节 */
  get available(): number {
    return this.buf.length - this.pos;
  }

  get isEof(): boolean {
    return this.eof && this.available === 0;
  }

  /** 保证至少 n 字节可读（EOF 时返回实际可读长度） */
  async ensure(n: number): Promise<number> {
    if (this.available >= n) return this.available;
    if (this.eof) return this.available;
    // 保留窗口内未消费部分，追加下一块
    const rest = this.buf.subarray(this.pos);
    const next = new Uint8Array(await this.src.read(this.readCursor, this.chunkSize));
    this.readCursor += next.byteLength;
    if (next.byteLength < this.chunkSize) this.eof = true;
    const merged = new Uint8Array(rest.length + next.length);
    merged.set(rest, 0);
    merged.set(next, rest.length);
    // 窗口首字节 = 原窗口首字节 + 已消费量
    this.windowStart += this.pos;
    this.buf = merged;
    this.pos = 0;
    return this.buf.length;
  }

  /** 取 n 字节视图（不复制）；不足且 EOF 返回 null */
  async peek(n: number): Promise<Uint8Array | null> {
    const got = await this.ensure(n);
    if (got < n) return null;
    return this.buf.subarray(this.pos, this.pos + n);
  }

  consume(n: number): void {
    this.pos += n;
  }

  /** 读取并消费 n 字节，返回副本（用于需要长期持有的小结构） */
  async take(n: number): Promise<Uint8Array | null> {
    const v = await this.peek(n);
    if (!v) return null;
    const copy = v.slice();
    this.consume(n);
    return copy;
  }

  /** 当前文件绝对偏移 */
  get fileOffset(): number {
    return this.windowStart + this.pos;
  }
}
