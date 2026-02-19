/**
 * FORTBOT - Default Security Configuration
 * 
 * These are sensible defaults. Customize per your needs.
 */

import {
  SecurityPolicy,
  ActionType,
  FortBotConfig,
} from '../types/index.js';

export const DEFAULT_POLICIES: SecurityPolicy[] = [
  {
    name: 'block_unauthorized_sends',
    description: 'Prevent sending messages to unknown recipients using tainted data',
    rules: [
      {
        action: ActionType.SEND_MESSAGE,
        conditions: [
          { field: 'requiresQuarantine', operator: 'is_tainted', value: true },
        ],
        effect: 'ask_user',
        priority: 100,
      },
    ],
  },
  {
    name: 'quarantine_enforcement',
    description: 'All data processing actions MUST run in quarantine',
    rules: [
      {
        action: ActionType.EXTRACT_DATA,
        conditions: [
          { field: 'requiresQuarantine', operator: 'equals', value: false },
        ],
        effect: 'deny',
        priority: 999,
      },
      {
        action: ActionType.SUMMARIZE,
        conditions: [
          { field: 'requiresQuarantine', operator: 'equals', value: false },
        ],
        effect: 'deny',
        priority: 999,
      },
      {
        action: ActionType.CLASSIFY,
        conditions: [
          { field: 'requiresQuarantine', operator: 'equals', value: false },
        ],
        effect: 'deny',
        priority: 999,
      },
    ],
  },
  {
    name: 'shell_requires_confirmation',
    description: 'Shell commands always need user approval',
    rules: [
      {
        action: ActionType.SHELL_EXEC,
        conditions: [],
        effect: 'ask_user',
        priority: 500,
      },
    ],
  },
  {
    name: 'web_fetch_confirmation',
    description: 'Web fetching needs user approval',
    rules: [
      {
        action: ActionType.WEB_FETCH,
        conditions: [],
        effect: 'ask_user',
        priority: 500,
      },
    ],
  },
];

export function createDefaultConfig(overrides: Partial<FortBotConfig>): FortBotConfig {
  return {
    ownerNumber: overrides.ownerNumber ?? '',
    knownContacts: overrides.knownContacts ?? [],
    plannerModel: overrides.plannerModel ?? 'sonnet',
    quarantineModel: overrides.quarantineModel ?? 'haiku',
    useLocalQuarantine: overrides.useLocalQuarantine ?? false,
    quarantineLlmEndpoint: overrides.quarantineLlmEndpoint ?? 'http://localhost:11434',
    useDockerSandbox: overrides.useDockerSandbox ?? true,
    policies: overrides.policies ?? DEFAULT_POLICIES,
    alwaysConfirmActions: overrides.alwaysConfirmActions ?? [
      ActionType.SEND_MESSAGE,
      ActionType.SHELL_EXEC,
      ActionType.WRITE_FILE,
      ActionType.WEB_FETCH,
    ],
    maxPlanSteps: overrides.maxPlanSteps ?? 10,
    auditLogPath: overrides.auditLogPath ?? './audit.log',
    killSwitchPhrase: overrides.killSwitchPhrase ?? '/fortbot-stop',
    dbPath: overrides.dbPath ?? './fortbot.db',
    humanConfig: overrides.humanConfig ?? {},
  };
}
