/**
 * FORTBOT - Policy Engine
 * 
 * DETERMINISTIC. No LLM. Pure code.
 * Validates plans against security policies before execution.
 * Tracks data flow to prevent exfiltration.
 * Enforces capability-based access control.
 * 
 * This is the component that makes prompt injection irrelevant:
 * even if the LLM is compromised, the policy engine blocks unauthorized actions.
 */

import {
  Plan,
  PlanStep,
  PolicyRule,
  PolicyCondition,
  PolicyViolation,
  SecurityPolicy,
  ActionType,
  TrustLevel,
  TaintedValue,
  OutputCapacity,
  Permission,
  FortBotConfig,
  AuditEntry,
} from '../types/index.js';
import { TaintTracker } from './taint.js';

export class PolicyEngine {
  private policies: SecurityPolicy[];
  private taintTracker: TaintTracker;
  private auditLog: AuditEntry[] = [];
  private config: FortBotConfig;

  /** Actions that can cause real-world side effects */
  private static SENSITIVE_ACTIONS = new Set<ActionType>([
    ActionType.SEND_MESSAGE,
    ActionType.WRITE_FILE,
    ActionType.SHELL_EXEC,
    ActionType.WEB_FETCH,
  ]);

  /** Actions that MUST run in quarantine sandbox */
  private static QUARANTINE_REQUIRED = new Set<ActionType>([
    ActionType.EXTRACT_DATA,
    ActionType.SUMMARIZE,
    ActionType.TRANSLATE,
    ActionType.CLASSIFY,
    ActionType.ANSWER_QUESTION,
  ]);

  /** Map of actions to required permissions */
  private static ACTION_PERMISSIONS: Record<ActionType, Permission> = {
    [ActionType.SEND_MESSAGE]: Permission.SEND_TO_OWNER,
    [ActionType.READ_MESSAGES]: Permission.READ,
    [ActionType.SEARCH_CONTACTS]: Permission.READ,
    [ActionType.SEARCH_MESSAGES]: Permission.READ,
    [ActionType.EXTRACT_DATA]: Permission.READ,
    [ActionType.SUMMARIZE]: Permission.READ,
    [ActionType.TRANSLATE]: Permission.READ,
    [ActionType.CLASSIFY]: Permission.READ,
    [ActionType.ANSWER_QUESTION]: Permission.READ,
    [ActionType.READ_FILE]: Permission.READ,
    [ActionType.WRITE_FILE]: Permission.WRITE_FILE,
    [ActionType.SHELL_EXEC]: Permission.EXECUTE,
    [ActionType.WEB_FETCH]: Permission.PASS_TO_API,
    [ActionType.SCHEDULE_TASK]: Permission.EXECUTE,
    [ActionType.BROWSE]: Permission.PASS_TO_API,
    [ActionType.SCREENSHOT]: Permission.PASS_TO_API,
    [ActionType.ASK_USER_CONFIRMATION]: Permission.READ,
    [ActionType.LOG_EVENT]: Permission.READ,
  };

  constructor(config: FortBotConfig) {
    this.config = config;
    this.policies = config.policies;
    this.taintTracker = new TaintTracker();
  }

  getTaintTracker(): TaintTracker {
    return this.taintTracker;
  }

  /**
   * Validate an entire plan before any execution begins.
   * Returns the plan with approval status and any violations.
   */
  validatePlan(plan: Plan): Plan {
    const violations: PolicyViolation[] = [];

    // 1. Check plan size limits
    if (plan.steps.length > this.config.maxPlanSteps) {
      violations.push({
        stepId: '*',
        rule: { action: '*', conditions: [], effect: 'deny', priority: 9999 },
        reason: `Plan exceeds maximum steps (${plan.steps.length} > ${this.config.maxPlanSteps})`,
        severity: 'critical',
      });
    }

    // 2. Validate each step
    for (const step of plan.steps) {
      const stepViolations = this.validateStep(step, plan);
      violations.push(...stepViolations);
    }

    // 3. Validate data flow across steps (taint propagation)
    const flowViolations = this.validateDataFlow(plan);
    violations.push(...flowViolations);

    // 4. Check for circular dependencies
    if (this.hasCircularDeps(plan)) {
      violations.push({
        stepId: '*',
        rule: { action: '*', conditions: [], effect: 'deny', priority: 9999 },
        reason: 'Plan contains circular dependencies',
        severity: 'critical',
      });
    }

    const hasCritical = violations.some(v => v.severity === 'critical');
    return {
      ...plan,
      approved: !hasCritical,
      violations,
    };
  }

  /**
   * Validate a single step against all policies.
   */
  private validateStep(step: PlanStep, plan: Plan): PolicyViolation[] {
    const violations: PolicyViolation[] = [];

    // Check if action is allowed by any policy
    const applicableRules = this.getApplicableRules(step.action);

    for (const rule of applicableRules) {
      const conditionsMet = this.evaluateConditions(rule.conditions, step, plan);

      if (conditionsMet && rule.effect === 'deny') {
        violations.push({
          stepId: step.id,
          rule,
          reason: `Action ${step.action} denied by policy rule`,
          severity: 'critical',
        });
      }
    }

    // Enforce quarantine requirement
    if (
      step.requiresQuarantine &&
      !PolicyEngine.QUARANTINE_REQUIRED.has(step.action)
    ) {
      // Step claims it needs quarantine but action doesn't require it
      // This is suspicious - the plan might be trying to run privileged
      // actions in quarantine to avoid policy checks
      violations.push({
        stepId: step.id,
        rule: { action: step.action, conditions: [], effect: 'deny', priority: 999 },
        reason: `Action ${step.action} does not belong in quarantine. Suspicious plan.`,
        severity: 'warning',
      });
    }

    if (
      PolicyEngine.QUARANTINE_REQUIRED.has(step.action) &&
      !step.requiresQuarantine
    ) {
      violations.push({
        stepId: step.id,
        rule: { action: step.action, conditions: [], effect: 'deny', priority: 999 },
        reason: `Action ${step.action} MUST run in quarantine but plan says otherwise.`,
        severity: 'critical',
      });
    }

    // Enforce output schema for quarantined steps
    if (step.requiresQuarantine) {
      if (step.outputSchema.type === OutputCapacity.STRING) {
        // Strings from quarantine are HIGH RISK
        // Must have maxLength to limit exfiltration bandwidth
        if (!step.outputSchema.maxLength || step.outputSchema.maxLength > 500) {
          violations.push({
            stepId: step.id,
            rule: { action: step.action, conditions: [], effect: 'deny', priority: 900 },
            reason: `Quarantined step outputs unconstrained string (max ${step.outputSchema.maxLength ?? 'unlimited'} chars). Use typed outputs to reduce injection risk.`,
            severity: 'warning',
          });
        }
      }
    }

    // Check if action requires user confirmation
    if (this.config.alwaysConfirmActions.includes(step.action)) {
      // Not a violation, but inject a confirmation step
      violations.push({
        stepId: step.id,
        rule: { action: step.action, conditions: [], effect: 'ask_user', priority: 0 },
        reason: `Action ${step.action} requires user confirmation`,
        severity: 'info',
      });
    }

    return violations;
  }

  /**
   * Validate data flow across the entire plan.
   * Ensures tainted data from quarantined steps doesn't flow to sensitive actions
   * without proper capability checks.
   */
  private validateDataFlow(plan: Plan): PolicyViolation[] {
    const violations: PolicyViolation[] = [];

    // Build a dependency graph with taint propagation
    const stepOutputTrust = new Map<string, TrustLevel>();
    const stepOutputCapacity = new Map<string, OutputCapacity>();
    const stepIsTainted = new Map<string, boolean>();

    // Actions that inherently produce untrusted output (external data sources)
    const UNTRUSTED_PRODUCERS = new Set([
      ActionType.READ_MESSAGES,
      ActionType.SEARCH_MESSAGES,
      ActionType.WEB_FETCH,
      ActionType.READ_FILE,
    ]);

    for (const step of plan.steps) {
      // Steps that process external data produce tainted output
      if (step.requiresQuarantine || UNTRUSTED_PRODUCERS.has(step.action)) {
        stepOutputTrust.set(step.id, TrustLevel.UNTRUSTED);
        stepOutputCapacity.set(step.id, step.outputSchema.type);
        stepIsTainted.set(step.id, true);
      } else {
        stepOutputTrust.set(step.id, TrustLevel.SYSTEM);
        stepOutputCapacity.set(step.id, step.outputSchema.type);
        stepIsTainted.set(step.id, false);
      }
    }

    // Propagate taint through references
    let changed = true;
    while (changed) {
      changed = false;
      for (const step of plan.steps) {
        for (const param of Object.values(step.params)) {
          if (param.kind === 'reference') {
            const sourceTainted = stepIsTainted.get(param.stepId);
            if (sourceTainted && !stepIsTainted.get(step.id)) {
              stepIsTainted.set(step.id, true);
              // Trust degrades through taint propagation
              stepOutputTrust.set(step.id, TrustLevel.UNTRUSTED);
              changed = true;
            }
          }
        }
      }
    }

    // Check: sensitive actions consuming tainted data
    for (const step of plan.steps) {
      if (!PolicyEngine.SENSITIVE_ACTIONS.has(step.action)) continue;

      for (const [paramName, param] of Object.entries(step.params)) {
        if (param.kind !== 'reference') continue;

        const sourceIsTainted = stepIsTainted.get(param.stepId);
        const sourceCapacity = stepOutputCapacity.get(param.stepId);

        if (sourceIsTainted) {
          // Tainted data flowing to sensitive action!
          // Check if the capacity type makes it safe
          if (
            sourceCapacity === OutputCapacity.BOOLEAN ||
            sourceCapacity === OutputCapacity.ENUM ||
            sourceCapacity === OutputCapacity.NUMBER
          ) {
            // Low capacity: safe even if tainted
            continue;
          }

          // STRING or STRUCTURED from tainted source → BLOCK or WARN
          if (sourceCapacity === OutputCapacity.STRING) {
            violations.push({
              stepId: step.id,
              rule: { action: step.action, conditions: [], effect: 'deny', priority: 1000 },
              reason: `CRITICAL: Tainted STRING from step ${param.stepId} flows to sensitive action ${step.action} (param: ${paramName}). This is a potential prompt injection / exfiltration vector.`,
              severity: 'critical',
            });
          } else if (sourceCapacity === OutputCapacity.STRUCTURED) {
            violations.push({
              stepId: step.id,
              rule: { action: step.action, conditions: [], effect: 'ask_user', priority: 800 },
              reason: `Tainted STRUCTURED data from step ${param.stepId} flows to sensitive action ${step.action}. Requires user review.`,
              severity: 'warning',
            });
          }
        }
      }
    }

    return violations;
  }

  /**
   * Runtime check: validate a specific action execution with actual data.
   */
  validateExecution(
    step: PlanStep,
    inputValues: TaintedValue[],
    outputValue?: TaintedValue,
  ): { allowed: boolean; reason: string; requiresConfirmation: boolean } {
    const requiredPerm = PolicyEngine.ACTION_PERMISSIONS[step.action];

    // Check each input value's taint
    for (const input of inputValues) {
      if (!input.label.tainted) continue;

      const flowCheck = this.taintTracker.canFlowTo(
        input,
        TrustLevel.SYSTEM, // Actions run at system trust
        requiredPerm,
      );

      if (!flowCheck.allowed) {
        this.logAudit(step, inputValues, 'deny', false, [flowCheck.reason]);
        return {
          allowed: false,
          reason: flowCheck.reason,
          requiresConfirmation: false,
        };
      }
    }

    // Check if this action requires user confirmation
    const needsConfirm = this.config.alwaysConfirmActions.includes(step.action);

    this.logAudit(
      step,
      inputValues,
      needsConfirm ? 'ask_user' : 'allow',
      !needsConfirm,
      [],
    );

    return {
      allowed: true,
      reason: 'Policy check passed',
      requiresConfirmation: needsConfirm,
    };
  }

  // --- Helpers ---

  private getApplicableRules(action: ActionType): PolicyRule[] {
    return this.policies
      .flatMap(p => p.rules)
      .filter(r => r.action === action || r.action === '*')
      .sort((a, b) => b.priority - a.priority);
  }

  private evaluateConditions(
    conditions: PolicyCondition[],
    step: PlanStep,
    _plan: Plan,
  ): boolean {
    // All conditions must be true (AND logic)
    return conditions.every(cond => {
      switch (cond.operator) {
        case 'equals':
          return this.getStepField(step, cond.field) === cond.value;
        case 'not_equals':
          return this.getStepField(step, cond.field) !== cond.value;
        case 'in':
          return (cond.value as unknown[]).includes(this.getStepField(step, cond.field));
        case 'not_in':
          return !(cond.value as unknown[]).includes(this.getStepField(step, cond.field));
        case 'is_tainted':
          return step.requiresQuarantine === cond.value;
        default:
          return false;
      }
    });
  }

  private getStepField(step: PlanStep, field: string): unknown {
    if (field === 'action') return step.action;
    if (field === 'requiresQuarantine') return step.requiresQuarantine;
    if (field === 'outputType') return step.outputSchema.type;
    if (field.startsWith('params.')) {
      const paramName = field.slice(7);
      const param = step.params[paramName];
      return param?.kind === 'literal' ? param.value : undefined;
    }
    return undefined;
  }

  private hasCircularDeps(plan: Plan): boolean {
    const visited = new Set<string>();
    const inStack = new Set<string>();
    const stepMap = new Map(plan.steps.map(s => [s.id, s]));

    const dfs = (stepId: string): boolean => {
      if (inStack.has(stepId)) return true; // Cycle!
      if (visited.has(stepId)) return false;
      visited.add(stepId);
      inStack.add(stepId);
      const step = stepMap.get(stepId);
      if (step) {
        for (const dep of step.dependsOn) {
          if (dfs(dep)) return true;
        }
      }
      inStack.delete(stepId);
      return false;
    };

    return plan.steps.some(s => dfs(s.id));
  }

  private logAudit(
    step: PlanStep,
    inputs: TaintedValue[],
    decision: 'allow' | 'deny' | 'ask_user',
    executed: boolean,
    warnings: string[],
  ): void {
    this.auditLog.push({
      timestamp: Date.now(),
      planId: '',
      stepId: step.id,
      action: step.action,
      inputLabels: inputs.map(i => i.label),
      outputLabel: undefined,
      policyDecision: decision,
      executed,
      warnings,
    });
  }

  getAuditLog(): AuditEntry[] {
    return [...this.auditLog];
  }
}
