import { promptRegistry } from '../../src/copilot/prompt_registry.js';

describe('Prompt Registry Service', () => {
  it('should retrieve active prompts by name', async () => {
    const prompt = await promptRegistry.getActivePrompt(1, 'analyst_system');
    expect(prompt).not.toBeNull();
    expect(prompt?.name).toBe('analyst_system');
    expect(prompt?.is_active).toBe(true);
  });

  it('should support creating new prompts and incrementing version', async () => {
    const initialPrompt = await promptRegistry.getActivePrompt(1, 'analyst_system');
    const oldVersion = initialPrompt?.version || 1;

    const newPrompt = await promptRegistry.createPrompt({
      tenant_id: 1,
      name: 'analyst_system',
      version: oldVersion,
      category: 'analyst',
      prompt_template: 'New template version here {{var}}',
      system_hint: 'New hint',
      variables: {},
      is_active: true,
      governance_reviewed: true,
      reviewed_by: null,
      created_by: null
    });

    expect(newPrompt.version).toBe(oldVersion + 1);
    expect(newPrompt.is_active).toBe(true);

    const activePrompt = await promptRegistry.getActivePrompt(1, 'analyst_system');
    expect(activePrompt?.version).toBe(oldVersion + 1);
    expect(activePrompt?.prompt_template).toContain('New template version');
  });
});
