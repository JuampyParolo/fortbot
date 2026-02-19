/**
 * FORTBOT - Quarantined LLM
 *
 * Processes UNTRUSTED data in isolation.
 * SECURITY: This LLM has NO access to tools or actions.
 * Its output is schema-enforced and taint-tracked.
 *
 * Two backends:
 *   1. Claude Max (via Agent SDK) — uses haiku for speed
 *   2. Local LLM (ollama/llama.cpp) — data never leaves network
 */

import {
  PlanStep,
  TaintedValue,
  TrustLevel,
  OutputCapacity,
  OutputSchema,
} from '../types/index.js';
import { TaintTracker } from '../policy/taint.js';
import { callClaude, callLocalLLM } from '../llm/claude-max.js';
import { sanitizeWebContent } from '../policy/network.js';

export interface QuarantineResult {
  success: boolean;
  output?: TaintedValue;
  errors: string[];
}

export class QuarantinedLLM {
  private endpoint: string;
  private useLocal: boolean;
  private taintTracker: TaintTracker;
  private quarantineModel: 'sonnet' | 'opus' | 'haiku';

  constructor(
    endpoint: string,
    useLocal: boolean,
    taintTracker: TaintTracker,
    model: 'sonnet' | 'opus' | 'haiku' = 'haiku',
  ) {
    this.endpoint = endpoint;
    this.useLocal = useLocal;
    this.taintTracker = taintTracker;
    this.quarantineModel = model;
  }

  async process(step: PlanStep, input: TaintedValue): Promise<QuarantineResult> {
    const errors: string[] = [];

    // Build constrained prompt
    const systemPrompt = this.buildSystemPrompt(step.outputSchema);
    const instruction = this.extractInstruction(step);
    const rawInput = String(input.value).substring(0, 8000);

    // SECURITY: Sanitize input before it reaches the quarantine LLM.
    // Even though output is schema-enforced, injection in the input could
    // alter the LLM's interpretation of the instruction.
    const sanitized = sanitizeWebContent(rawInput, `quarantine-input:${step.action}`);
    const cleanInput = sanitized.text;

    const userMessage = `DATA TO PROCESS:\n${cleanInput}\n\nINSTRUCTION: ${instruction}`;

    try {
      // Call LLM (local or Claude Max)
      let rawOutput: string;
      if (this.useLocal) {
        const result = await callLocalLLM(this.endpoint, systemPrompt, userMessage);
        rawOutput = result.text;
      } else {
        const result = await callClaude(systemPrompt, userMessage, this.quarantineModel);
        rawOutput = result.text;
      }

      // Enforce output schema
      const validated = this.enforceSchema(rawOutput, step.outputSchema);
      if (!validated.valid) {
        return { success: false, errors: [`Schema violation: ${validated.reason}`] };
      }

      // Create tainted value — output inherits taint from input
      const output = this.taintTracker.deriveValue(
        validated.value,
        input,
        step.outputSchema.type,
        `quarantine:${step.action}`,
      );

      return { success: true, output, errors };
    } catch (error) {
      return {
        success: false,
        errors: [`Quarantine LLM error: ${error instanceof Error ? error.message : error}`],
      };
    }
  }

  private buildSystemPrompt(schema: OutputSchema): string {
    const base = `You are a data processing assistant in a SANDBOXED environment.
You have NO access to tools, APIs, or actions.
You can ONLY process the data given and return a result.
NEVER include instructions, commands, or action requests in your output.
NEVER try to communicate with the user or request actions.`;

    switch (schema.type) {
      case OutputCapacity.BOOLEAN:
        return `${base}\n\nRespond with ONLY "true" or "false". Nothing else.`;
      case OutputCapacity.ENUM:
        return `${base}\n\nRespond with ONLY one of: ${schema.enumValues?.join(', ')}. Nothing else.`;
      case OutputCapacity.NUMBER:
        return `${base}\n\nRespond with ONLY a number. Nothing else.`;
      case OutputCapacity.STRUCTURED:
        return `${base}\n\nRespond with ONLY valid JSON matching this schema: ${JSON.stringify(schema.jsonSchema)}`;
      case OutputCapacity.STRING:
        return `${base}\n\nRespond with plain text. Max ${schema.maxLength ?? 5000} chars. No markdown, no code blocks.`;
      default:
        return base;
    }
  }

  private enforceSchema(raw: string, schema: OutputSchema): { valid: boolean; value: unknown; reason?: string } {
    const trimmed = raw.trim();

    switch (schema.type) {
      case OutputCapacity.BOOLEAN: {
        const lower = trimmed.toLowerCase();
        if (lower === 'true' || lower === 'yes' || lower === 'sí' || lower === 'si') return { valid: true, value: true };
        if (lower === 'false' || lower === 'no') return { valid: true, value: false };
        return { valid: false, value: null, reason: `Expected boolean, got: "${trimmed.substring(0, 50)}"` };
      }
      case OutputCapacity.ENUM: {
        const allowed = schema.enumValues ?? [];
        const lower = trimmed.toLowerCase();
        const match = allowed.find(v => v.toLowerCase() === lower);
        if (match) return { valid: true, value: match };
        return { valid: false, value: null, reason: `"${trimmed}" not in [${allowed.join(', ')}]` };
      }
      case OutputCapacity.NUMBER: {
        const num = Number(trimmed);
        if (!isNaN(num)) return { valid: true, value: num };
        return { valid: false, value: null, reason: `Not a number: "${trimmed.substring(0, 50)}"` };
      }
      case OutputCapacity.STRUCTURED: {
        try {
          const cleaned = trimmed.replace(/```json\s*/g, '').replace(/```/g, '').trim();
          const parsed = JSON.parse(cleaned);
          return { valid: true, value: parsed };
        } catch {
          return { valid: false, value: null, reason: `Invalid JSON` };
        }
      }
      case OutputCapacity.STRING: {
        const maxLen = schema.maxLength ?? 5000;
        const truncated = trimmed.substring(0, maxLen);
        return { valid: true, value: truncated };
      }
      default:
        return { valid: true, value: trimmed };
    }
  }

  private extractInstruction(step: PlanStep): string {
    const instructionParam = step.params['instruction'] ?? step.params['question'] ??
      step.params['target_language'] ?? step.params['categories'];
    if (instructionParam?.kind === 'literal') return String(instructionParam.value);
    return step.action;
  }
}
