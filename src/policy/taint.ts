/**
 * FORTBOT - Taint Tracking System
 * 
 * Implements taint propagation following FIDES principles.
 * Every piece of data carries its origin and trust level.
 * Taint propagates conservatively: if ANY input is tainted, output is tainted.
 * Trust level of output = MIN(trust levels of all inputs).
 */

import { randomUUID } from 'crypto';
import {
  TaintLabel,
  TaintedValue,
  TrustLevel,
  DataOrigin,
  OutputCapacity,
  Capability,
  Permission,
} from '../types/index.js';

/** Trust level ordering for lattice operations */
const TRUST_ORDER: Record<TrustLevel, number> = {
  [TrustLevel.OWNER]: 4,
  [TrustLevel.SYSTEM]: 3,
  [TrustLevel.KNOWN_CONTACT]: 2,
  [TrustLevel.UNKNOWN]: 1,
  [TrustLevel.UNTRUSTED]: 0,
};

export class TaintTracker {
  private values: Map<string, TaintedValue> = new Map();
  private capabilities: Map<string, Capability> = new Map();

  /**
   * Wrap a raw value with taint metadata.
   * This is the ONLY way data enters the system.
   */
  createValue<T>(
    value: T,
    origin: DataOrigin,
    trust: TrustLevel,
    capacity: OutputCapacity,
    createdBy: string,
  ): TaintedValue<T> {
    const valueId = randomUUID();
    const label: TaintLabel = {
      origin,
      trust,
      createdBy,
      createdAt: Date.now(),
      tainted: trust === TrustLevel.UNTRUSTED || trust === TrustLevel.UNKNOWN,
      provenance: [`created:${createdBy}`],
    };

    const taintedValue: TaintedValue<T> = {
      value,
      label,
      capabilities: [],
      capacity,
    };

    this.values.set(valueId, taintedValue as TaintedValue);
    return taintedValue;
  }

  /**
   * Propagate taint when combining multiple values.
   * Conservative: trust = min(all inputs), tainted = any(all inputs)
   */
  propagate<T>(
    result: T,
    inputs: TaintedValue[],
    transformName: string,
    outputCapacity: OutputCapacity,
  ): TaintedValue<T> {
    // Trust = minimum of all inputs
    const minTrust = inputs.reduce(
      (min, input) => this.minTrust(min, input.label.trust),
      TrustLevel.OWNER,
    );

    // Tainted if ANY input is tainted
    const isTainted = inputs.some(i => i.label.tainted);

    // Merge provenance chains
    const mergedProvenance = inputs.flatMap(i => i.label.provenance);
    mergedProvenance.push(`transform:${transformName}`);

    // Origin = first input's origin (primary source)
    const primaryOrigin = inputs[0]?.label.origin ?? {
      source: 'system' as const,
      identifier: 'propagation',
    };

    const label: TaintLabel = {
      origin: primaryOrigin,
      trust: minTrust,
      createdBy: transformName,
      createdAt: Date.now(),
      tainted: isTainted,
      provenance: mergedProvenance,
    };

    // Capabilities: intersection of all input capabilities
    const sharedCapabilities = this.intersectCapabilities(
      inputs.flatMap(i => i.capabilities),
    );

    return {
      value: result,
      label,
      capabilities: sharedCapabilities,
      capacity: outputCapacity,
    };
  }

  /**
   * Derive a new value from a single input, inheriting its taint.
   * Convenience wrapper around propagate for quarantine output.
   */
  deriveValue<T>(
    result: T,
    input: TaintedValue,
    outputCapacity: OutputCapacity,
    transformName: string,
  ): TaintedValue<T> {
    return this.propagate(result, [input], transformName, outputCapacity);
  }

  /**
   * Grant a capability on a value.
   * Only the policy engine or owner can grant capabilities.
   */
  grantCapability(
    valueId: string,
    permissions: Permission[],
    grantedBy: 'owner' | 'policy_engine' | 'system',
    expiresInMs?: number,
  ): Capability {
    const cap: Capability = {
      id: randomUUID(),
      valueId,
      permissions,
      grantedBy,
      expiresAt: expiresInMs ? Date.now() + expiresInMs : undefined,
      revoked: false,
    };
    this.capabilities.set(cap.id, cap);
    return cap;
  }

  /**
   * Check if a capability authorizes a specific permission.
   */
  checkCapability(cap: Capability, requiredPermission: Permission): boolean {
    if (cap.revoked) return false;
    if (cap.expiresAt && Date.now() > cap.expiresAt) return false;
    return cap.permissions.includes(requiredPermission);
  }

  /**
   * Revoke a capability (permanent).
   */
  revokeCapability(capId: string): void {
    const cap = this.capabilities.get(capId);
    if (cap) cap.revoked = true;
  }

  /**
   * Check if a tainted value can flow to a destination.
   * FIDES principle: low-capacity outputs are safe even if tainted.
   */
  canFlowTo(
    value: TaintedValue,
    destinationTrust: TrustLevel,
    requiredPermission: Permission,
  ): { allowed: boolean; reason: string } {
    // Owner data can go anywhere the owner permits
    if (value.label.trust === TrustLevel.OWNER) {
      return { allowed: true, reason: 'Owner data, unrestricted' };
    }

    // Non-tainted data from known sources: check capability
    if (!value.label.tainted) {
      const hasCap = value.capabilities.some(c =>
        this.checkCapability(c, requiredPermission),
      );
      return hasCap
        ? { allowed: true, reason: 'Capability granted' }
        : { allowed: false, reason: 'No capability for this operation' };
    }

    // TAINTED DATA: apply FIDES capacity rules
    // Boolean/Enum: so little info that injection is impossible
    if (
      value.capacity === OutputCapacity.BOOLEAN ||
      value.capacity === OutputCapacity.ENUM
    ) {
      return {
        allowed: true,
        reason: `Low-capacity type (${value.capacity}), injection impossible`,
      };
    }

    // Number: bounded precision, very low risk
    if (value.capacity === OutputCapacity.NUMBER) {
      return {
        allowed: true,
        reason: 'Numeric type, injection risk negligible',
      };
    }

    // Structured: medium risk, needs capability
    if (value.capacity === OutputCapacity.STRUCTURED) {
      const hasCap = value.capabilities.some(c =>
        this.checkCapability(c, requiredPermission),
      );
      return hasCap
        ? { allowed: true, reason: 'Structured data with capability' }
        : {
            allowed: false,
            reason: 'Structured tainted data requires capability',
          };
    }

    // STRING from tainted source: HIGHEST RISK
    // Only allowed if explicitly granted capability AND destination trust is sufficient
    if (value.capacity === OutputCapacity.STRING) {
      const hasCap = value.capabilities.some(c =>
        this.checkCapability(c, requiredPermission),
      );
      if (!hasCap) {
        return {
          allowed: false,
          reason: 'BLOCKED: Tainted string without capability. Potential injection vector.',
        };
      }
      // Even with capability, tainted strings can't flow to higher trust destinations
      if (TRUST_ORDER[destinationTrust] > TRUST_ORDER[value.label.trust]) {
        return {
          allowed: false,
          reason: 'BLOCKED: Tainted string cannot flow to higher-trust destination.',
        };
      }
      return { allowed: true, reason: 'Tainted string with explicit capability' };
    }

    return { allowed: false, reason: 'Unknown capacity type' };
  }

  // --- Private helpers ---

  private minTrust(a: TrustLevel, b: TrustLevel): TrustLevel {
    return TRUST_ORDER[a] <= TRUST_ORDER[b] ? a : b;
  }

  private intersectCapabilities(caps: Capability[]): Capability[] {
    // Deduplicate by id, keep only valid ones
    const seen = new Set<string>();
    return caps.filter(c => {
      if (seen.has(c.id)) return false;
      if (c.revoked) return false;
      if (c.expiresAt && Date.now() > c.expiresAt) return false;
      seen.add(c.id);
      return true;
    });
  }
}
