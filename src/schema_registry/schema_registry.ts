/**
 * Aegis Enterprise — Schema Registry
 *
 * Validates incoming raw telemetry schemas to prevent downstream pipeline crashes.
 */

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
}

export class SchemaRegistry {
  private static instance: SchemaRegistry;
  private schemas: Map<string, Record<string, string>> = new Map();

  private constructor() {
    // Register standard telemetry schema v1
    this.registerSchema("v1", {
      event_type: "string",
      source: "string",
      timestamp: "number",
    });
  }

  public static getInstance(): SchemaRegistry {
    if (!SchemaRegistry.instance) {
      SchemaRegistry.instance = new SchemaRegistry();
    }
    return SchemaRegistry.instance;
  }

  registerSchema(version: string, fields: Record<string, string>): void {
    this.schemas.set(version, fields);
  }

  /** Validate incoming payload fields against registered version */
  validate(payload: any, version = "v1"): ValidationResult {
    const schema = this.schemas.get(version);
    if (!schema) {
      return {
        isValid: false,
        errors: [`Schema version "${version}" not registered.`],
      };
    }

    const errors: string[] = [];
    for (const [field, expectedType] of Object.entries(schema)) {
      if (!(field in payload)) {
        errors.push(`Missing required field: "${field}"`);
      } else if (typeof payload[field] !== expectedType) {
        errors.push(
          `Invalid type for field "${field}": expected ${expectedType}, got ${typeof payload[field]}`,
        );
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }
}

export const schemaRegistry = SchemaRegistry.getInstance();
