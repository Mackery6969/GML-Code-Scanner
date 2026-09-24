export interface Position {
  /** 1-based */
  line: number;
  /** 1-based, UTF-16 code units */
  column: number;
}

/** Source text with lazy offset → line/column conversion. */
export class SourceText {
  readonly text: string;
  private lineStarts: number[] | undefined;

  constructor(text: string) {
    this.text = text;
  }

  private starts(): number[] {
    if (!this.lineStarts) {
      const starts = [0];
      for (let i = 0; i < this.text.length; i++) if (this.text.charCodeAt(i) === 10) starts.push(i + 1);
      this.lineStarts = starts;
    }
    return this.lineStarts;
  }

  position(offset: number): Position {
    const starts = this.starts();
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= offset) lo = mid;
      else hi = mid - 1;
    }
    return { line: lo + 1, column: offset - starts[lo] + 1 };
  }

  /** Text of a 1-based line without its line terminator. */
  lineText(line: number): string {
    const starts = this.starts();
    const s = starts[line - 1];
    if (s === undefined) return "";
    const e = line < starts.length ? starts[line] - 1 : this.text.length;
    return this.text.slice(s, e).replace(/\r$/, "");
  }

  get lineCount(): number {
    return this.starts().length;
  }
}
