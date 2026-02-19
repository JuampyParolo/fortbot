// Playwright is an optional dependency.
// This declaration allows TypeScript to compile without it installed.
declare module 'playwright' {
  export const chromium: {
    launch(options?: Record<string, unknown>): Promise<any>;
  };
}
