/**
 * FORTBOT - Task Queue
 *
 * Serial execution queue to prevent parallel plan execution.
 * If you send 5 messages fast, they queue up and process one at a time.
 */

type Task<T> = () => Promise<T>;

export class TaskQueue {
  private queue: Array<{
    task: Task<unknown>;
    resolve: (value: unknown) => void;
    reject: (reason: unknown) => void;
  }> = [];
  private running = false;
  private maxQueueSize: number;

  constructor(maxQueueSize = 10) {
    this.maxQueueSize = maxQueueSize;
  }

  /**
   * Add a task to the queue. Returns a promise that resolves when the task completes.
   * Rejects immediately if queue is full.
   */
  async enqueue<T>(task: Task<T>): Promise<T> {
    if (this.queue.length >= this.maxQueueSize) {
      throw new Error(`Queue full (${this.maxQueueSize} pending). Try again later.`);
    }

    return new Promise<T>((resolve, reject) => {
      this.queue.push({
        task: task as Task<unknown>,
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      this.process();
    });
  }

  get pending(): number {
    return this.queue.length;
  }

  get isProcessing(): boolean {
    return this.running;
  }

  private async process(): Promise<void> {
    if (this.running) return;
    this.running = true;

    while (this.queue.length > 0) {
      const item = this.queue.shift()!;
      try {
        const result = await item.task();
        item.resolve(result);
      } catch (error) {
        item.reject(error);
      }
    }

    this.running = false;
  }
}
